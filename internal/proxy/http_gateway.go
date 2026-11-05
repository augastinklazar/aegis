package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/augastinklazar/aegis/internal/audit"
	"github.com/augastinklazar/aegis/internal/broker"
	"github.com/augastinklazar/aegis/internal/hitl"
	"github.com/augastinklazar/aegis/internal/hitl/notifiers"
	"github.com/augastinklazar/aegis/internal/sandbox"
	"github.com/augastinklazar/aegis/internal/vault"
)

type Gateway struct {
	vault          *vault.Vault
	phantomManager *broker.PhantomManager
	sandbox        *sandbox.CELEngine
	counter        *sandbox.StateCounter
	parkManager    *hitl.ParkManager
	dispatcher     *notifiers.Dispatcher
	auditLogger    *audit.Logger
	baseURL        string
	upstreamRoutes map[string]string // serviceID -> baseURL e.g. stripe_prod -> https://api.stripe.com
}

func NewGateway(
	v *vault.Vault,
	pm *broker.PhantomManager,
	sb *sandbox.CELEngine,
	sc *sandbox.StateCounter,
	park *hitl.ParkManager,
	disp *notifiers.Dispatcher,
	al *audit.Logger,
	baseURL string,
) *Gateway {
	gw := &Gateway{
		vault:          v,
		phantomManager: pm,
		sandbox:        sb,
		counter:        sc,
		parkManager:    park,
		dispatcher:     disp,
		auditLogger:    al,
		baseURL:        baseURL,
		upstreamRoutes: map[string]string{
			"stripe_prod": "https://api.stripe.com",
			"stripe_test": "https://api.stripe.com",
			"github_api":  "https://api.github.com",
			"openai_api":  "https://api.openai.com",
			"anthropic":   "https://api.anthropic.com",
			"slack_api":   "https://slack.com/api",
		},
	}
	return gw
}

func (gw *Gateway) SetUpstreamRoute(serviceID, targetURL string) {
	gw.upstreamRoutes[serviceID] = targetURL
}

func (gw *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path format: /proxy/{service_id}/path...
	path := strings.TrimPrefix(r.URL.Path, "/proxy/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, `{"error":"invalid_proxy_path","usage":"/proxy/{service_id}/{path}"}`, http.StatusBadRequest)
		return
	}

	serviceID := parts[0]
	targetSubPath := "/"
	if len(parts) > 1 {
		targetSubPath += parts[1]
	}

	// 1. Extract Bearer phantom token
	authHeader := r.Header.Get("Authorization")
	phantomToken := strings.TrimPrefix(authHeader, "Bearer ")
	if phantomToken == "" || phantomToken == authHeader {
		// Check X-Aegis-Token
		phantomToken = r.Header.Get("X-Aegis-Token")
	}

	if phantomToken == "" {
		http.Error(w, `{"error":"unauthorized","message":"missing Bearer phantom token"}`, http.StatusUnauthorized)
		return
	}

	// 2. Validate Phantom Token
	pt, err := gw.phantomManager.ValidateAndConsume(phantomToken, serviceID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "invalid_phantom_token",
			"message": err.Error(),
		})
		return
	}

	// 3. Read & Redact Body
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
	}

	// Redact PII in outgoing payload
	redactedBodyStr := sandbox.RedactPII(string(bodyBytes))
	bodyBytes = []byte(redactedBodyStr)

	var bodyMap map[string]interface{}
	if len(bodyBytes) > 0 && (strings.Contains(r.Header.Get("Content-Type"), "json") || bodyBytes[0] == '{') {
		json.Unmarshal(bodyBytes, &bodyMap)
	}

	// Extract natural language reason (AAuth draft-rosenberg)
	agentReason := r.Header.Get("X-Aegis-Reason")
	if agentReason == "" {
		agentReason = r.Header.Get("Aegis-Reason")
	}
	if agentReason == "" && bodyMap != nil {
		if rStr, ok := bodyMap["reason"].(string); ok {
			agentReason = rStr
		}
	}
	if agentReason == "" {
		agentReason = fmt.Sprintf("Agent executed %s on %s", r.Method, targetSubPath)
	}

	// 4. Policy Sandbox Evaluation
	evalCtx := &sandbox.EvalContext{
		Method:  r.Method,
		Path:    targetSubPath,
		Body:    bodyMap,
		AgentID: pt.AgentID,
		TaskID:  pt.TaskID,
		Service: serviceID,
	}

	evalResult, err := gw.sandbox.Evaluate(evalCtx)
	if err != nil {
		http.Error(w, `{"error":"policy_evaluation_error","details":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// 5. Handle Policy Decisions
	switch evalResult.Decision {
	case sandbox.DecisionDeny:
		gw.auditLogger.Log(pt.AgentID, pt.TaskID, serviceID, r.Method+" "+targetSubPath, bodyBytes, "DENIED", "", "")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "policy_denied",
			"rule":    evalResult.MatchedRule,
			"message": evalResult.Reason,
		})
		return

	case sandbox.DecisionEscalate:
		// Park connection for Human In The Loop approval
		requestID := hitl.GenerateRequestID()
		approvalURL := fmt.Sprintf("%s/approve/%s", gw.baseURL, requestID)

		// Dispatch notifications
		gw.dispatcher.Dispatch(&notifiers.NotificationPayload{
			RequestID:      requestID,
			AgentID:        pt.AgentID,
			TaskID:         pt.TaskID,
			Service:        serviceID,
			Action:         r.Method + " " + targetSubPath,
			Reason:         agentReason,
			PayloadSummary: string(bodyBytes),
			ApprovalURL:    approvalURL,
			Approvers:      evalResult.Approvers,
		})

		// Check if client requested async polling (AAuth RFC 8628-like)
		preferAsync := r.Header.Get("Prefer") == "respond-async" || strings.Contains(r.Header.Get("Accept"), "application/vnd.aauth+json")
		if preferAsync {
			// Save pending request to park manager asynchronously without freezing thread
			go func() {
				gw.parkManager.Park(&hitl.ParkedRequest{
					ID:             requestID,
					AgentID:        pt.AgentID,
					TaskID:         pt.TaskID,
					Service:        serviceID,
					Action:         r.Method + " " + targetSubPath,
					Payload:        bodyBytes,
					Reason:         agentReason,
					TimeoutSeconds: evalResult.TimeoutSeconds,
					Approvers:      evalResult.Approvers,
				})
			}()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":           "pending_approval",
				"request_id":       requestID,
				"verification_uri": approvalURL,
				"poll_endpoint":    fmt.Sprintf("%s/v1/hitl/requests/%s", gw.baseURL, requestID),
				"interval":         2,
				"expires_in":       evalResult.TimeoutSeconds,
			})
			return
		}

		// Synchronous freeze: hold HTTP request open
		parkedReq := &hitl.ParkedRequest{
			ID:             requestID,
			AgentID:        pt.AgentID,
			TaskID:         pt.TaskID,
			Service:        serviceID,
			Action:         r.Method + " " + targetSubPath,
			Payload:        bodyBytes,
			Reason:         agentReason,
			TimeoutSeconds: evalResult.TimeoutSeconds,
			Approvers:      evalResult.Approvers,
		}

		decision, err := gw.parkManager.Park(parkedReq)
		if err != nil || decision == nil || !decision.Approved {
			denialReason := "Human reviewer rejected action"
			if decision != nil && decision.DenialReason != "" {
				denialReason = decision.DenialReason
			}
			gw.auditLogger.Log(pt.AgentID, pt.TaskID, serviceID, r.Method+" "+targetSubPath, bodyBytes, "ESCALATED_DENIED", decision.Approver, decision.ApproverSig)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "escalation_rejected",
				"message": denialReason,
			})
			return
		}

		// Approved! Log with passkey signature
		gw.auditLogger.Log(pt.AgentID, pt.TaskID, serviceID, r.Method+" "+targetSubPath, bodyBytes, "ESCALATED_APPROVED", decision.Approver, decision.ApproverSig)
	default:
		// ALLOWED
		gw.auditLogger.Log(pt.AgentID, pt.TaskID, serviceID, r.Method+" "+targetSubPath, bodyBytes, "ALLOWED", "", "")
	}

	// 6. Credential Injection & Egress Forwarding
	realSecret, err := gw.vault.GetSecret(serviceID)
	if err != nil {
		// Try OAuth token
		if tok, errOAuth := gw.vault.GetOAuthToken(serviceID); errOAuth == nil && tok.AccessToken != "" {
			realSecret = tok.AccessToken
		} else {
			http.Error(w, `{"error":"upstream_credential_missing","service":"`+serviceID+`"}`, http.StatusBadGateway)
			return
		}
	}

	targetBaseURL, ok := gw.upstreamRoutes[serviceID]
	if !ok {
		// Fallback: check if service is an explicit URL
		if strings.HasPrefix(serviceID, "http") {
			targetBaseURL = serviceID
		} else {
			targetBaseURL = "http://" + serviceID
		}
	}

	targetURL, err := url.Parse(targetBaseURL + targetSubPath)
	if err != nil {
		http.Error(w, `{"error":"invalid_upstream_url"}`, http.StatusInternalServerError)
		return
	}
	targetURL.RawQuery = r.URL.RawQuery

	outReq, err := http.NewRequest(r.Method, targetURL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, `{"error":"failed_creating_upstream_request"}`, http.StatusInternalServerError)
		return
	}

	// Copy original headers
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	// Strip phantom tokens
	outReq.Header.Del("X-Aegis-Token")
	outReq.Header.Del("X-Aegis-Reason")
	outReq.Header.Del("Aegis-Reason")

	// Inject real decrypted credential over the wire
	if strings.HasPrefix(realSecret, "sk_") || strings.HasPrefix(realSecret, "Bearer ") || strings.HasPrefix(realSecret, "ghp_") {
		if strings.HasPrefix(realSecret, "Bearer ") {
			outReq.Header.Set("Authorization", realSecret)
		} else {
			outReq.Header.Set("Authorization", "Bearer "+realSecret)
		}
	} else {
		outReq.Header.Set("Authorization", "Bearer "+realSecret)
		outReq.Header.Set("x-api-key", realSecret)
	}

	// Execute upstream call
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, `{"error":"upstream_call_failed","details":"`+err.Error()+`"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Update spend state if successful and amount is recorded
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && bodyMap != nil {
		if amtVal, ok := bodyMap["amount"]; ok {
			var amt float64
			switch v := amtVal.(type) {
			case float64:
				amt = v
			case int:
				amt = float64(v)
			case string:
				amt, _ = strconv.ParseFloat(v, 64)
			}
			if amt > 0 {
				gw.counter.Record(pt.AgentID, "refunds", amt)
			}
		}
	}

	// Copy response headers and body back to agent
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
