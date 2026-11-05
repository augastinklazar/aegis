package broker

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
	ErrTokenNotFound   = errors.New("phantom token not found")
	ErrTokenExpired    = errors.New("phantom token expired")
	ErrQuotaExceeded   = errors.New("token call quota exceeded")
	ErrServiceMismatch = errors.New("token not authorized for requested service")
)

type AuthorizationDetail struct {
	Type           string   `json:"type"`
	Actions        []string `json:"actions,omitempty"`
	MaxAmountCents int64    `json:"max_amount_cents,omitempty"`
	Currency       string   `json:"currency,omitempty"`
	MaxCalls       int      `json:"max_calls,omitempty"`
	PathPrefix     string   `json:"path_prefix,omitempty"`
}

type PhantomToken struct {
	Token          string                `json:"token"`
	AgentID        string                `json:"agent_id"`
	TaskID         string                `json:"task_id"`
	Subject        string                `json:"subject"` // Human identity
	Service        string                `json:"service"` // Upstream service id (e.g. stripe_prod)
	Scopes         []string              `json:"scopes"`
	AuthDetails    []AuthorizationDetail `json:"authorization_details,omitempty"`
	ExpiresAt      time.Time             `json:"expires_at"`
	MaxCalls       int                   `json:"max_calls"` // 0 = unlimited
	RemainingCalls int                   `json:"remaining_calls"`
	CreatedAt      time.Time             `json:"created_at"`
}

type PhantomManager struct {
	db    *sql.DB
	cache sync.Map
}

func NewPhantomManager(db *sql.DB) (*PhantomManager, error) {
	pm := &PhantomManager{db: db}
	if err := pm.initSchema(); err != nil {
		return nil, fmt.Errorf("phantom schema init: %w", err)
	}
	return pm, nil
}

func (pm *PhantomManager) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS phantom_tokens (
		token TEXT PRIMARY KEY,
		agent_id TEXT NOT NULL,
		task_id TEXT NOT NULL,
		subject TEXT NOT NULL,
		service TEXT NOT NULL,
		scopes TEXT NOT NULL,
		auth_details TEXT,
		expires_at DATETIME NOT NULL,
		max_calls INTEGER NOT NULL,
		remaining_calls INTEGER NOT NULL,
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_phantom_agent ON phantom_tokens(agent_id);
	CREATE INDEX IF NOT EXISTS idx_phantom_expires ON phantom_tokens(expires_at);
	`
	_, err := pm.db.Exec(schema)
	return err
}

func GeneratePhantomToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return "ag_tok_" + hex.EncodeToString(b)
}

func (pm *PhantomManager) IssueToken(agentID, taskID, subject, service string, scopes []string, authDetails []AuthorizationDetail, ttl time.Duration, maxCalls int) (*PhantomToken, error) {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if maxCalls < 0 {
		maxCalls = 0
	}

	tok := GeneratePhantomToken()
	now := time.Now().UTC()
	exp := now.Add(ttl)

	pt := &PhantomToken{
		Token:          tok,
		AgentID:        agentID,
		TaskID:         taskID,
		Subject:        subject,
		Service:        service,
		Scopes:         scopes,
		AuthDetails:    authDetails,
		ExpiresAt:      exp,
		MaxCalls:       maxCalls,
		RemainingCalls: maxCalls,
		CreatedAt:      now,
	}

	query := `
	INSERT INTO phantom_tokens (
		token, agent_id, task_id, subject, service, scopes, auth_details, expires_at, max_calls, remaining_calls, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := pm.db.Exec(query, tok, agentID, taskID, subject, service, "", "", exp, maxCalls, maxCalls, now)
	if err != nil {
		return nil, fmt.Errorf("store phantom token: %w", err)
	}

	pm.cache.Store(tok, pt)
	return pt, nil
}

func (pm *PhantomManager) ValidateAndConsume(tok, service string) (*PhantomToken, error) {
	var pt *PhantomToken

	if val, ok := pm.cache.Load(tok); ok {
		pt = val.(*PhantomToken)
	} else {
		// Load from DB
		var (
			agentID, taskID, subject, srv string
			expiresAt, createdAt          time.Time
			maxCalls, remainingCalls      int
		)
		query := `SELECT agent_id, task_id, subject, service, expires_at, max_calls, remaining_calls, created_at FROM phantom_tokens WHERE token = ?`
		err := pm.db.QueryRow(query, tok).Scan(&agentID, &taskID, &subject, &srv, &expiresAt, &maxCalls, &remainingCalls, &createdAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		if err != nil {
			return nil, err
		}

		pt = &PhantomToken{
			Token:          tok,
			AgentID:        agentID,
			TaskID:         taskID,
			Subject:        subject,
			Service:        srv,
			ExpiresAt:      expiresAt,
			MaxCalls:       maxCalls,
			RemainingCalls: remainingCalls,
			CreatedAt:      createdAt,
		}
		pm.cache.Store(tok, pt)
	}

	now := time.Now().UTC()
	if now.After(pt.ExpiresAt) {
		pm.cache.Delete(tok)
		return nil, ErrTokenExpired
	}

	if pt.Service != "*" && pt.Service != service {
		return nil, fmt.Errorf("%w: token bound to '%s', attempted '%s'", ErrServiceMismatch, pt.Service, service)
	}

	if pt.MaxCalls > 0 {
		if pt.RemainingCalls <= 0 {
			return nil, ErrQuotaExceeded
		}
		pt.RemainingCalls--
		// Update DB
		pm.db.Exec(`UPDATE phantom_tokens SET remaining_calls = ? WHERE token = ?`, pt.RemainingCalls, tok)
	}

	return pt, nil
}
