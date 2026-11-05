package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"

	"github.com/augastinklazar/aegis/internal/audit"
	"github.com/augastinklazar/aegis/internal/hitl"
	"github.com/augastinklazar/aegis/internal/hitl/notifiers"
	"github.com/augastinklazar/aegis/internal/sandbox"
)

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
	Reason    string                 `json:"_reason,omitempty"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      interface{}   `json:"id"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

type MCPStdioWrapper struct {
	command     string
	args        []string
	sandbox     *sandbox.CELEngine
	counter     *sandbox.StateCounter
	parkManager *hitl.ParkManager
	dispatcher  *notifiers.Dispatcher
	auditLogger *audit.Logger
	agentID     string
	taskID      string
	baseURL     string
	mu          sync.Mutex
}

func NewMCPStdioWrapper(
	command string,
	args []string,
	sb *sandbox.CELEngine,
	sc *sandbox.StateCounter,
	pm *hitl.ParkManager,
	disp *notifiers.Dispatcher,
	al *audit.Logger,
	agentID string,
	taskID string,
	baseURL string,
) *MCPStdioWrapper {
	if agentID == "" {
		agentID = "mcp-agent"
	}
	if taskID == "" {
		taskID = "mcp-session"
	}
	return &MCPStdioWrapper{
		command:     command,
		args:        args,
		sandbox:     sb,
		counter:     sc,
		parkManager: pm,
		dispatcher:  disp,
		auditLogger: al,
		agentID:     agentID,
		taskID:      taskID,
		baseURL:     baseURL,
	}
}

func (w *MCPStdioWrapper) Run() error {
	cmd := exec.Command(w.command, w.args...)
	cmd.Stderr = os.Stderr

	childStdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("child stdin pipe: %w", err)
	}
	childStdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("child stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start child command '%s': %w", w.command, err)
	}

	// Forward child stdout to parent stdout in background
	go func() {
		defer childStdout.Close()
		io.Copy(os.Stdout, childStdout)
	}()

	// Read line-delimited JSON-RPC from parent stdin
	scanner := bufio.NewScanner(os.Stdin)
	// Buffer up to 10MB for large payloads
	const maxCapacity = 10 * 1024 * 1024
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var rpcReq JSONRPCRequest
		if err := json.Unmarshal(line, &rpcReq); err != nil {
			// Not valid JSON-RPC or partial; pass through
			childStdin.Write(line)
			childStdin.Write([]byte("\n"))
			continue
		}

		// Intercept tools/call
		if rpcReq.Method == "tools/call" {
			var tcParams ToolCallParams
			if err := json.Unmarshal(rpcReq.Params, &tcParams); err == nil {
				passed, errResp := w.interceptToolCall(&rpcReq, &tcParams)
				if !passed {
					// Deterministically blocked or rejected: write JSON-RPC error response to stdout directly
					errBytes, _ := json.Marshal(errResp)
					w.mu.Lock()
					os.Stdout.Write(errBytes)
					os.Stdout.Write([]byte("\n"))
					w.mu.Unlock()
					continue
				}

				// If passed, re-serialize params with PII redaction
				redactedArgsJSON, _ := json.Marshal(tcParams.Arguments)
				redactedArgsStr := sandbox.RedactPII(string(redactedArgsJSON))
				var cleanArgs map[string]interface{}
				json.Unmarshal([]byte(redactedArgsStr), &cleanArgs)
				tcParams.Arguments = cleanArgs

				newParamsBytes, _ := json.Marshal(tcParams)
				rpcReq.Params = newParamsBytes
				line, _ = json.Marshal(rpcReq)
			}
		}

		// Forward to child MCP server
		childStdin.Write(line)
		childStdin.Write([]byte("\n"))
	}

	childStdin.Close()
	return cmd.Wait()
}

func (w *MCPStdioWrapper) interceptToolCall(rpcReq *JSONRPCRequest, tc *ToolCallParams) (bool, *JSONRPCResponse) {
	evalCtx := &sandbox.EvalContext{
		Tool:    tc.Name,
		Args:    tc.Arguments,
		AgentID: w.agentID,
		TaskID:  w.taskID,
		Service: "mcp:" + tc.Name,
	}

	evalResult, err := w.sandbox.Evaluate(evalCtx)
	if err != nil {
		log.Printf("[mcp] policy eval error: %v", err)
	}

	payloadBytes, _ := json.Marshal(tc.Arguments)
	reason := tc.Reason
	if reason == "" {
		reason = fmt.Sprintf("MCP agent executing tool '%s'", tc.Name)
	}

	switch evalResult.Decision {
	case sandbox.DecisionDeny:
		w.auditLogger.Log(w.agentID, w.taskID, "mcp:"+tc.Name, "tools/call", payloadBytes, "DENIED", "", "")
		return false, &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      rpcReq.ID,
			Error: &JSONRPCError{
				Code:    -32003,
				Message: fmt.Sprintf("Blocked by Aegis Policy: %s", evalResult.Reason),
			},
		}

	case sandbox.DecisionEscalate:
		reqID := hitl.GenerateRequestID()
		approvalURL := fmt.Sprintf("%s/approve/%s", w.baseURL, reqID)

		w.dispatcher.Dispatch(&notifiers.NotificationPayload{
			RequestID:      reqID,
			AgentID:        w.agentID,
			TaskID:         w.taskID,
			Service:        "mcp:" + tc.Name,
			Action:         "tools/call:" + tc.Name,
			Reason:         reason,
			PayloadSummary: string(payloadBytes),
			ApprovalURL:    approvalURL,
			Approvers:      evalResult.Approvers,
		})

		// Freeze tool execution waiting for human approval
		parkedReq := &hitl.ParkedRequest{
			ID:             reqID,
			AgentID:        w.agentID,
			TaskID:         w.taskID,
			Service:        "mcp:" + tc.Name,
			Action:         "tools/call:" + tc.Name,
			Payload:        payloadBytes,
			Reason:         reason,
			TimeoutSeconds: evalResult.TimeoutSeconds,
			Approvers:      evalResult.Approvers,
		}

		decision, err := w.parkManager.Park(parkedReq)
		if err != nil || decision == nil || !decision.Approved {
			denialReason := "Human reviewer denied MCP tool execution"
			if decision != nil && decision.DenialReason != "" {
				denialReason = decision.DenialReason
			}
			w.auditLogger.Log(w.agentID, w.taskID, "mcp:"+tc.Name, "tools/call", payloadBytes, "ESCALATED_DENIED", decision.Approver, decision.ApproverSig)

			return false, &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      rpcReq.ID,
				Error: &JSONRPCError{
					Code:    -32003,
					Message: fmt.Sprintf("Escalation Denied: %s", denialReason),
				},
			}
		}

		w.auditLogger.Log(w.agentID, w.taskID, "mcp:"+tc.Name, "tools/call", payloadBytes, "ESCALATED_APPROVED", decision.Approver, decision.ApproverSig)
		return true, nil

	default:
		// ALLOWED
		w.auditLogger.Log(w.agentID, w.taskID, "mcp:"+tc.Name, "tools/call", payloadBytes, "ALLOWED", "", "")
		return true, nil
	}
}
