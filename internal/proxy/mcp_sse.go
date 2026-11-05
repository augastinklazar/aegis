package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/augastinklazar/aegis/internal/audit"
	"github.com/augastinklazar/aegis/internal/hitl"
	"github.com/augastinklazar/aegis/internal/hitl/notifiers"
	"github.com/augastinklazar/aegis/internal/sandbox"
)

type MCPSSEProxy struct {
	sandbox     *sandbox.CELEngine
	counter     *sandbox.StateCounter
	parkManager *hitl.ParkManager
	dispatcher  *notifiers.Dispatcher
	auditLogger *audit.Logger
	baseURL     string
}

func NewMCPSSEProxy(
	sb *sandbox.CELEngine,
	sc *sandbox.StateCounter,
	pm *hitl.ParkManager,
	disp *notifiers.Dispatcher,
	al *audit.Logger,
	baseURL string,
) *MCPSSEProxy {
	return &MCPSSEProxy{
		sandbox:     sb,
		counter:     sc,
		parkManager: pm,
		dispatcher:  disp,
		auditLogger: al,
		baseURL:     baseURL,
	}
}

func (s *MCPSSEProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path: /mcp/{service}/message or /mcp/{service}/sse
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/sse") {
		// SSE endpoint handshake
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		fmt.Fprintf(w, "event: endpoint\ndata: %s/message\n\n", strings.TrimSuffix(r.URL.Path, "/sse"))
		return
	}

	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(r.Body)
		var rpcReq JSONRPCRequest
		if err := json.Unmarshal(body, &rpcReq); err == nil && rpcReq.Method == "tools/call" {
			var tc ToolCallParams
			if err := json.Unmarshal(rpcReq.Params, &tc); err == nil {
				evalCtx := &sandbox.EvalContext{
					Tool:    tc.Name,
					Args:    tc.Arguments,
					AgentID: "sse-agent",
					TaskID:  "sse-session",
					Service: "mcp:" + tc.Name,
				}

				res, _ := s.sandbox.Evaluate(evalCtx)
				if res.Decision == sandbox.DecisionDeny {
					s.auditLogger.Log("sse-agent", "sse-session", "mcp:"+tc.Name, "tools/call", body, "DENIED", "", "")
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0",
						"id":      rpcReq.ID,
						"error":   map[string]interface{}{"code": -32003, "message": "Blocked by policy: " + res.Reason},
					})
					return
				}

				if res.Decision == sandbox.DecisionEscalate {
					reqID := hitl.GenerateRequestID()
					approvalURL := fmt.Sprintf("%s/approve/%s", s.baseURL, reqID)
					s.dispatcher.Dispatch(&notifiers.NotificationPayload{
						RequestID:      reqID,
						AgentID:        "sse-agent",
						TaskID:         "sse-session",
						Service:        "mcp:" + tc.Name,
						Action:         "tools/call:" + tc.Name,
						Reason:         "Remote SSE agent invoking " + tc.Name,
						PayloadSummary: string(body),
						ApprovalURL:    approvalURL,
						Approvers:      res.Approvers,
					})

					parked := &hitl.ParkedRequest{
						ID:             reqID,
						AgentID:        "sse-agent",
						TaskID:         "sse-session",
						Service:        "mcp:" + tc.Name,
						Action:         "tools/call:" + tc.Name,
						Payload:        body,
						Reason:         "Remote SSE agent invoking " + tc.Name,
						TimeoutSeconds: res.TimeoutSeconds,
						Approvers:      res.Approvers,
					}
					dec, err := s.parkManager.Park(parked)
					if err != nil || dec == nil || !dec.Approved {
						s.auditLogger.Log("sse-agent", "sse-session", "mcp:"+tc.Name, "tools/call", body, "ESCALATED_DENIED", "", "")
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(map[string]interface{}{
							"jsonrpc": "2.0",
							"id":      rpcReq.ID,
							"error":   map[string]interface{}{"code": -32003, "message": "Escalation rejected by human"},
						})
						return
					}
					s.auditLogger.Log("sse-agent", "sse-session", "mcp:"+tc.Name, "tools/call", body, "ESCALATED_APPROVED", dec.Approver, dec.ApproverSig)
				} else {
					s.auditLogger.Log("sse-agent", "sse-session", "mcp:"+tc.Name, "tools/call", body, "ALLOWED", "", "")
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","result":{"status":"accepted"}}`))
		return
	}

	http.NotFound(w, r)
}
