package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

type AuditEntry struct {
	ID          int64     `json:"id"`
	Seq         int64     `json:"seq"`
	Timestamp   time.Time `json:"timestamp"`
	PrevHash    string    `json:"prev_hash"`
	RecordHash  string    `json:"record_hash"`
	AgentID     string    `json:"agent_id"`
	TaskID      string    `json:"task_id"`
	Service     string    `json:"service"`
	Action      string    `json:"action"`
	PayloadHash string    `json:"payload_hash"`
	RawPayload  string    `json:"raw_payload"`
	Decision    string    `json:"decision"` // ALLOWED, DENIED, ESCALATED_APPROVED, ESCALATED_DENIED
	Approver    string    `json:"approver,omitempty"`
	ApproverSig string    `json:"approver_sig,omitempty"`
}

type Logger struct {
	db *sql.DB
	mu sync.Mutex
}

func NewLogger(db *sql.DB) (*Logger, error) {
	l := &Logger{db: db}
	if err := l.initSchema(); err != nil {
		return nil, fmt.Errorf("audit schema init: %w", err)
	}
	return l, nil
}

func (l *Logger) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		seq INTEGER NOT NULL UNIQUE,
		timestamp DATETIME NOT NULL,
		prev_hash TEXT NOT NULL,
		record_hash TEXT NOT NULL,
		agent_id TEXT NOT NULL,
		task_id TEXT NOT NULL,
		service TEXT NOT NULL,
		action TEXT NOT NULL,
		payload_hash TEXT NOT NULL,
		raw_payload TEXT,
		decision TEXT NOT NULL,
		approver TEXT,
		approver_sig TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
	CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_log(seq);
	CREATE INDEX IF NOT EXISTS idx_audit_service ON audit_log(service);
	`
	_, err := l.db.Exec(schema)
	return err
}

func ComputePayloadHash(payload []byte) string {
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}

func computeRecordHash(seq int64, prevHash string, ts time.Time, agentID, taskID, service, action, payloadHash, decision, approverSig string) string {
	raw := fmt.Sprintf("%d|%s|%d|%s|%s|%s|%s|%s|%s|%s",
		seq, prevHash, ts.UnixNano(), agentID, taskID, service, action, payloadHash, decision, approverSig)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func (l *Logger) Log(agentID, taskID, service, action string, payload []byte, decision, approver, approverSig string) (*AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	tx, err := l.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var lastSeq sql.NullInt64
	var lastHash sql.NullString
	err = tx.QueryRow(`SELECT seq, record_hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &lastHash)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("read last audit record: %w", err)
	}

	seq := int64(1)
	prevHash := GenesisHash
	if lastSeq.Valid {
		seq = lastSeq.Int64 + 1
		prevHash = lastHash.String
	}

	now := time.Now().UTC()
	payloadHash := ComputePayloadHash(payload)
	recordHash := computeRecordHash(seq, prevHash, now, agentID, taskID, service, action, payloadHash, decision, approverSig)

	rawStr := string(payload)
	if len(rawStr) > 4096 {
		rawStr = rawStr[:4096] + "...[truncated]"
	}

	query := `
	INSERT INTO audit_log (
		seq, timestamp, prev_hash, record_hash, agent_id, task_id,
		service, action, payload_hash, raw_payload, decision, approver, approver_sig
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	res, err := tx.Exec(query, seq, now, prevHash, recordHash, agentID, taskID, service, action, payloadHash, rawStr, decision, approver, approverSig)
	if err != nil {
		return nil, fmt.Errorf("insert audit log: %w", err)
	}

	id, _ := res.LastInsertId()
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &AuditEntry{
		ID:          id,
		Seq:         seq,
		Timestamp:   now,
		PrevHash:    prevHash,
		RecordHash:  recordHash,
		AgentID:     agentID,
		TaskID:      taskID,
		Service:     service,
		Action:      action,
		PayloadHash: payloadHash,
		RawPayload:  rawStr,
		Decision:    decision,
		Approver:    approver,
		ApproverSig: approverSig,
	}, nil
}

type VerificationReport struct {
	Valid       bool   `json:"valid"`
	TotalBlocks int64  `json:"total_blocks"`
	TipHash     string `json:"tip_hash"`
	BrokenSeq   int64  `json:"broken_seq,omitempty"`
	Error       string `json:"error,omitempty"`
}

func (l *Logger) VerifyChain() (*VerificationReport, error) {
	rows, err := l.db.Query(`SELECT seq, timestamp, prev_hash, record_hash, agent_id, task_id, service, action, payload_hash, raw_payload, decision, approver_sig FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	var count int64 = 0
	var lastRecordHash string

	for rows.Next() {
		var (
			seq                                                                int64
			ts                                                                 time.Time
			prevHash, recordHash, agentID, taskID, service, action, payloadHash string
			rawPayload                                                         sql.NullString
			decision, approverSig                                              sql.NullString
		)

		if err := rows.Scan(&seq, &ts, &prevHash, &recordHash, &agentID, &taskID, &service, &action, &payloadHash, &rawPayload, &decision, &approverSig); err != nil {
			return nil, err
		}

		// Verify payload integrity if raw_payload is stored without truncation
		if rawPayload.Valid && len(rawPayload.String) > 0 {
			calcPayloadHash := ComputePayloadHash([]byte(rawPayload.String))
			if calcPayloadHash != payloadHash {
				return &VerificationReport{
					Valid:     false,
					BrokenSeq: seq,
					Error:     fmt.Sprintf("raw payload hash tamper detected at seq %d", seq),
				}, nil
			}
		}

		if prevHash != expectedPrev {
			return &VerificationReport{
				Valid:     false,
				BrokenSeq: seq,
				Error:     fmt.Sprintf("prev_hash mismatch at seq %d: expected %s, got %s", seq, expectedPrev, prevHash),
			}, nil
		}

		expectedHash := computeRecordHash(seq, prevHash, ts, agentID, taskID, service, action, payloadHash, decision.String, approverSig.String)
		if recordHash != expectedHash {
			return &VerificationReport{
				Valid:     false,
				BrokenSeq: seq,
				Error:     fmt.Sprintf("cryptographic hash integrity violation at seq %d", seq),
			}, nil
		}

		expectedPrev = recordHash
		lastRecordHash = recordHash
		count++
	}

	return &VerificationReport{
		Valid:       true,
		TotalBlocks: count,
		TipHash:     lastRecordHash,
	}, nil
}

func (l *Logger) GetRecent(limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	query := `
	SELECT id, seq, timestamp, prev_hash, record_hash, agent_id, task_id, service, action, payload_hash, raw_payload, decision, approver, approver_sig
	FROM audit_log ORDER BY seq DESC LIMIT ?
	`
	rows, err := l.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var app, sig, raw sql.NullString
		err := rows.Scan(
			&e.ID, &e.Seq, &e.Timestamp, &e.PrevHash, &e.RecordHash,
			&e.AgentID, &e.TaskID, &e.Service, &e.Action,
			&e.PayloadHash, &raw, &e.Decision, &app, &sig,
		)
		if err != nil {
			return nil, err
		}
		e.RawPayload = raw.String
		e.Approver = app.String
		e.ApproverSig = sig.String
		entries = append(entries, e)
	}
	return entries, nil
}
