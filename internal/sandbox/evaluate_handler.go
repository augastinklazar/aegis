package sandbox

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type EvaluateRequest struct {
	Tool         string                 `json:"tool,omitempty"`
	SQL          string                 `json:"sql,omitempty"`
	Command      string                 `json:"command,omitempty"`
	Method       string                 `json:"method,omitempty"`
	Path         string                 `json:"path,omitempty"`
	Body         map[string]interface{} `json:"body,omitempty"`
	Args         map[string]interface{} `json:"args,omitempty"`
	PolicyPreset string                 `json:"policy_preset,omitempty"`
	AgentID      string                 `json:"agent_id,omitempty"`
	RedactPII    bool                   `json:"redact_pii,omitempty"`
}

type EvaluateResponse struct {
	Decision        string   `json:"decision"` // ALLOW, ESCALATE, DENY
	Reason          string   `json:"reason"`
	AgentHint       string   `json:"agent_hint,omitempty"`
	MatchedRule     string   `json:"matched_rule,omitempty"`
	Approvers       []string `json:"approvers,omitempty"`
	RedactedPayload string   `json:"redacted_payload,omitempty"`
	LatencyMs       int64    `json:"latency_ms"`
}

type EvaluateHandler struct {
	engine *CELEngine
}

func NewEvaluateHandler(engine *CELEngine) *EvaluateHandler {
	return &EvaluateHandler{engine: engine}
}

func (h *EvaluateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_json_payload", "details": err.Error()})
		return
	}

	resp := &EvaluateResponse{
		Decision: "ALLOW",
		Reason:   "Action passed all deterministic sandbox checks",
	}

	// 1. Direct SQL Evaluation
	sqlQuery := req.SQL
	if sqlQuery == "" && req.Args != nil {
		if q, ok := req.Args["query"].(string); ok {
			sqlQuery = q
		}
	}
	if sqlQuery != "" {
		verdict := AnalyzeSQL(sqlQuery)
		if verdict.IsDestructive {
			resp.Decision = "DENY"
			resp.Reason = verdict.Reason
			resp.AgentHint = "Refactor query to include explicit WHERE clause or target a specific identifier without dropping database schemas."
			resp.LatencyMs = time.Since(start).Milliseconds()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	// 2. Direct Bash / Command Evaluation
	bashCmd := req.Command
	if bashCmd == "" && req.Args != nil {
		if c, ok := req.Args["command"].(string); ok {
			bashCmd = c
		}
	}
	if bashCmd != "" {
		verdict := AnalyzeBash(bashCmd)
		if verdict.IsDangerous {
			resp.Decision = "DENY"
			resp.Reason = verdict.Reason
			resp.AgentHint = "Command violates system integrity constraints (e.g. destructive recursion, network exfiltration, or reverse shells)."
			resp.LatencyMs = time.Since(start).Milliseconds()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	// 3. PII Redaction
	if req.RedactPII {
		rawBody, _ := json.Marshal(req.Body)
		if len(rawBody) > 0 {
			resp.RedactedPayload = RedactPII(string(rawBody))
		}
	}

	// 4. CEL Semantic Policy Evaluation
	if h.engine != nil {
		evalCtx := &EvalContext{
			Method:  req.Method,
			Path:    req.Path,
			Body:    req.Body,
			Tool:    req.Tool,
			Args:    req.Args,
			AgentID: req.AgentID,
			Service: req.PolicyPreset,
		}
		if evalCtx.Method == "" {
			evalCtx.Method = "POST"
		}

		evalRes, err := h.engine.Evaluate(evalCtx)
		if err == nil && evalRes != nil {
			resp.Decision = string(evalRes.Decision)
			resp.Reason = evalRes.Reason
			resp.MatchedRule = evalRes.MatchedRule
			resp.Approvers = evalRes.Approvers

			if resp.Decision == "DENY" {
				resp.AgentHint = fmt.Sprintf("Violated policy rule '%s'. Plan an alternative approach.", evalRes.MatchedRule)
			} else if resp.Decision == "ESCALATE" {
				resp.AgentHint = "Action exceeds automatic threshold; submit to human reviewer queue."
			}
		}
	}

	resp.LatencyMs = time.Since(start).Milliseconds()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
