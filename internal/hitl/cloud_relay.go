package hitl

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/augastinklazar/aegis/internal/hitl/notifiers"
)

type CloudEscalateRequest struct {
	AgentID        string   `json:"agent_id"`
	TaskID         string   `json:"task_id"`
	Service        string   `json:"service"`
	Action         string   `json:"action"`
	Reason         string   `json:"reason"`
	PayloadSummary string   `json:"payload_summary"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	Approvers      []string `json:"approvers"`
}

type CloudRelayHandler struct {
	parkManager *ParkManager
	dispatcher  *notifiers.Dispatcher
	baseURL     string
}

func NewCloudRelayHandler(park *ParkManager, disp *notifiers.Dispatcher, baseURL string) *CloudRelayHandler {
	return &CloudRelayHandler{
		parkManager: park,
		dispatcher:  disp,
		baseURL:     baseURL,
	}
}

func (h *CloudRelayHandler) HandleEscalate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req CloudEscalateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_json_payload"})
		return
	}

	if req.TimeoutSeconds <= 0 {
		req.TimeoutSeconds = 300
	}

	reqID := GenerateRequestID()
	approvalURL := fmt.Sprintf("%s/approve.html?id=%s", h.baseURL, reqID)

	// Save request to ParkManager
	parked := &ParkedRequest{
		ID:             reqID,
		AgentID:        req.AgentID,
		TaskID:         req.TaskID,
		Service:        req.Service,
		Action:         req.Action,
		Payload:        []byte(req.PayloadSummary),
		Reason:         req.Reason,
		TimeoutSeconds: req.TimeoutSeconds,
		Approvers:      req.Approvers,
	}

	// Launch async parking channel
	go func() {
		h.parkManager.Park(parked)
	}()

	// Dispatch notification cards to configured channels
	h.dispatcher.Dispatch(&notifiers.NotificationPayload{
		RequestID:      reqID,
		AgentID:        req.AgentID,
		TaskID:         req.TaskID,
		Service:        req.Service,
		Action:         req.Action,
		Reason:         req.Reason,
		PayloadSummary: req.PayloadSummary,
		ApprovalURL:    approvalURL,
		Approvers:      req.Approvers,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"request_id":       reqID,
		"status":           "pending_approval",
		"approval_url":     approvalURL,
		"poll_endpoint":    fmt.Sprintf("%s/v1/escalate/%s", h.baseURL, reqID),
		"timeout_seconds":  req.TimeoutSeconds,
	})
}

func (h *CloudRelayHandler) HandlePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/v1/escalate/")
	reqID := strings.Trim(path, "/")
	if reqID == "" {
		http.Error(w, `{"error":"missing_request_id"}`, http.StatusBadRequest)
		return
	}

	req, err := h.parkManager.GetRequest(reqID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "request_not_found_or_expired"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"request_id": req.ID,
		"status":     req.Status,
		"decision":   req.Decision,
		"created_at": req.CreatedAt,
		"expires_at": req.ExpiresAt,
	})
}
