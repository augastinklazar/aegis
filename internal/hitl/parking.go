package hitl

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrRequestNotFound = errors.New("hitl request not found")
	ErrAlreadyResolved = errors.New("hitl request already resolved")
	ErrTimeout         = errors.New("hitl request timed out waiting for human approval")
)

type DecisionResult struct {
	Approved     bool      `json:"approved"`
	Approver     string    `json:"approver"`
	ApproverSig  string    `json:"approver_sig,omitempty"`
	DenialReason string    `json:"denial_reason,omitempty"`
	ResolvedAt   time.Time `json:"resolved_at"`
}

type ParkedRequest struct {
	ID             string          `json:"id"`
	AgentID        string          `json:"agent_id"`
	TaskID         string          `json:"task_id"`
	Service        string          `json:"service"`
	Action         string          `json:"action"`
	Payload        []byte          `json:"payload"`
	PayloadSummary string          `json:"payload_summary"`
	Reason         string          `json:"reason"`
	Approvers      []string        `json:"approvers"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	CreatedAt      time.Time       `json:"created_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	Status         string          `json:"status"` // PENDING, APPROVED, DENIED, TIMED_OUT
	Decision       *DecisionResult `json:"decision,omitempty"`

	decisionChan chan *DecisionResult
}

type ParkManager struct {
	db       *sql.DB
	requests map[string]*ParkedRequest
	mu       sync.RWMutex
}

func NewParkManager(db *sql.DB) (*ParkManager, error) {
	pm := &ParkManager{
		db:       db,
		requests: make(map[string]*ParkedRequest),
	}
	if err := pm.initSchema(); err != nil {
		return nil, fmt.Errorf("park manager schema init: %w", err)
	}
	return pm, nil
}

func (pm *ParkManager) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS hitl_requests (
		id TEXT PRIMARY KEY,
		agent_id TEXT NOT NULL,
		task_id TEXT NOT NULL,
		service TEXT NOT NULL,
		action TEXT NOT NULL,
		payload TEXT NOT NULL,
		reason TEXT,
		status TEXT NOT NULL,
		approver TEXT,
		approver_sig TEXT,
		denial_reason TEXT,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		resolved_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_hitl_status ON hitl_requests(status);
	`
	_, err := pm.db.Exec(schema)
	return err
}

func GenerateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "hitl_" + hex.EncodeToString(b)
}

func (pm *ParkManager) Park(req *ParkedRequest) (*DecisionResult, error) {
	if req.ID == "" {
		req.ID = GenerateRequestID()
	}
	if req.TimeoutSeconds <= 0 {
		req.TimeoutSeconds = 300 // 5 minutes
	}

	req.CreatedAt = time.Now().UTC()
	req.ExpiresAt = req.CreatedAt.Add(time.Duration(req.TimeoutSeconds) * time.Second)
	req.Status = "PENDING"
	req.decisionChan = make(chan *DecisionResult, 1)

	// Save to DB
	query := `
	INSERT INTO hitl_requests (id, agent_id, task_id, service, action, payload, reason, status, created_at, expires_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := pm.db.Exec(query, req.ID, req.AgentID, req.TaskID, req.Service, req.Action, string(req.Payload), req.Reason, req.Status, req.CreatedAt, req.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("store hitl request: %w", err)
	}

	pm.mu.Lock()
	pm.requests[req.ID] = req
	pm.mu.Unlock()

	// Wait on channel or timeout
	select {
	case res := <-req.decisionChan:
		return res, nil
	case <-time.After(time.Duration(req.TimeoutSeconds) * time.Second):
		pm.mu.Lock()
		req.Status = "TIMED_OUT"
		delete(pm.requests, req.ID)
		pm.mu.Unlock()

		pm.db.Exec(`UPDATE hitl_requests SET status = 'TIMED_OUT', resolved_at = ? WHERE id = ?`, time.Now().UTC(), req.ID)
		return &DecisionResult{
			Approved:     false,
			Approver:     "system",
			DenialReason: "Human-in-the-loop approval timed out after " + fmt.Sprintf("%d", req.TimeoutSeconds) + " seconds",
			ResolvedAt:   time.Now().UTC(),
		}, ErrTimeout
	}
}

func (pm *ParkManager) Resolve(requestID string, approved bool, approver, sig, denialReason string) error {
	pm.mu.Lock()
	req, ok := pm.requests[requestID]
	if ok {
		delete(pm.requests, requestID)
	}
	pm.mu.Unlock()

	status := "APPROVED"
	if !approved {
		status = "DENIED"
	}
	now := time.Now().UTC()

	res, err := pm.db.Exec(`
		UPDATE hitl_requests
		SET status = ?, approver = ?, approver_sig = ?, denial_reason = ?, resolved_at = ?
		WHERE id = ? AND status = 'PENDING'
	`, status, approver, sig, denialReason, now, requestID)
	if err != nil {
		return err
	}

	rows, _ := res.RowsAffected()
	if rows == 0 && req == nil {
		return ErrRequestNotFound
	}

	decision := &DecisionResult{
		Approved:     approved,
		Approver:     approver,
		ApproverSig:  sig,
		DenialReason: denialReason,
		ResolvedAt:   now,
	}

	if req != nil {
		req.Status = status
		req.Decision = decision
		select {
		case req.decisionChan <- decision:
		default:
		}
	}

	return nil
}

func (pm *ParkManager) GetPending() []*ParkedRequest {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	list := make([]*ParkedRequest, 0, len(pm.requests))
	for _, r := range pm.requests {
		list = append(list, r)
	}
	return list
}

func (pm *ParkManager) GetRequest(id string) (*ParkedRequest, error) {
	pm.mu.RLock()
	if req, ok := pm.requests[id]; ok {
		pm.mu.RUnlock()
		return req, nil
	}
	pm.mu.RUnlock()

	var (
		agentID, taskID, service, action, payload, reason, status string
		approver, approverSig, denialReason                       sql.NullString
		createdAt, expiresAt                                      time.Time
		resolvedAt                                                sql.NullTime
	)

	query := `
	SELECT id, agent_id, task_id, service, action, payload, reason, status, approver, approver_sig, denial_reason, created_at, expires_at, resolved_at
	FROM hitl_requests WHERE id = ?
	`
	err := pm.db.QueryRow(query, id).Scan(
		&id, &agentID, &taskID, &service, &action, &payload, &reason, &status,
		&approver, &approverSig, &denialReason, &createdAt, &expiresAt, &resolvedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRequestNotFound
	}
	if err != nil {
		return nil, err
	}

	req := &ParkedRequest{
		ID:             id,
		AgentID:        agentID,
		TaskID:         taskID,
		Service:        service,
		Action:         action,
		Payload:        []byte(payload),
		Reason:         reason,
		Status:         status,
		CreatedAt:      createdAt,
		ExpiresAt:      expiresAt,
	}

	if status != "PENDING" {
		req.Decision = &DecisionResult{
			Approved:     status == "APPROVED",
			Approver:     approver.String,
			ApproverSig:  approverSig.String,
			DenialReason: denialReason.String,
			ResolvedAt:   resolvedAt.Time,
		}
	}

	return req, nil
}
