package broker

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

func TestPhantomManager_Quotas(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aegis_broker_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "broker.db")
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	pm, err := NewPhantomManager(db)
	if err != nil {
		t.Fatal(err)
	}

	// Issue token with max 2 calls
	pt, err := pm.IssueToken("agent_test", "task_01", "user_alice", "stripe_prod", []string{"refunds"}, nil, 5*time.Minute, 2)
	if err != nil {
		t.Fatal(err)
	}

	// Call 1: valid
	tok1, err := pm.ValidateAndConsume(pt.Token, "stripe_prod")
	if err != nil || tok1.RemainingCalls != 1 {
		t.Fatalf("call 1 failed: %v, remaining: %d", err, tok1.RemainingCalls)
	}

	// Call 2: valid
	tok2, err := pm.ValidateAndConsume(pt.Token, "stripe_prod")
	if err != nil || tok2.RemainingCalls != 0 {
		t.Fatalf("call 2 failed: %v, remaining: %d", err, tok2.RemainingCalls)
	}

	// Call 3: Quota exceeded
	_, err = pm.ValidateAndConsume(pt.Token, "stripe_prod")
	if err != ErrQuotaExceeded {
		t.Fatalf("expected ErrQuotaExceeded, got: %v", err)
	}

	// Service Mismatch test
	pt2, err := pm.IssueToken("agent_test", "task_02", "user_alice", "github_api", nil, nil, 5*time.Minute, 5)
	if err != nil {
		t.Fatalf("issue token 2 failed: %v", err)
	}
	_, err = pm.ValidateAndConsume(pt2.Token, "stripe_prod")
	if err == nil {
		t.Fatal("expected error on service mismatch, got nil")
	}
}

func TestRFC8693_TokenExchange(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aegis_rfc_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "broker_rfc.db")
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	pm, _ := NewPhantomManager(db)
	ar, _ := NewAgentRegistry(db)
	jwtSecret := []byte("secret_key_12345678901234567890")

	// Register agent manifest
	ar.Register(&AgentManifest{
		AgentID:       "fin_bot",
		Name:          "Finance Reconciler",
		Purpose:       "Process billing refunds",
		ModelProvider: "anthropic/claude-3-5-sonnet",
	})

	brk := NewBroker(pm, ar, jwtSecret)

	// Execute RFC 8693 Token Exchange
	req := &TokenExchangeRequest{
		GrantType:            GrantTypeTokenExchange,
		SubjectToken:         "usr_human_alice_99",
		SubjectTokenType:     TokenTypeJWT,
		ActorToken:           "fin_bot",
		Audience:             "stripe_prod",
		Scope:                "refunds.write",
		TaskID:               "tx_9988",
		Reason:               "Refunding duplicate invoice #4421",
		AuthorizationDetails: `{"type":"refund","max_amount_cents":2000}`,
		TTLSeconds:           300,
		MaxCalls:             5,
	}

	resp, err := brk.HandleTokenExchange(req)
	if err != nil {
		t.Fatalf("token exchange failed: %v", err)
	}

	if resp.AccessToken == "" || resp.TokenType != "Bearer" || resp.ExpiresIn != 300 {
		t.Fatalf("invalid token response: %+v", resp)
	}

	// Parse & verify JWT claims (OBO act claim)
	token, err := jwt.Parse(resp.JWT, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		t.Fatalf("invalid jwt: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("invalid claims")
	}

	if claims["sub"] != "usr_human_alice_99" {
		t.Fatalf("expected sub usr_human_alice_99, got %v", claims["sub"])
	}

	actClaim, ok := claims["act"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing or invalid act claim: %+v", claims["act"])
	}
	if actClaim["sub"] != "fin_bot" || actClaim["task_id"] != "tx_9988" || actClaim["model"] != "anthropic/claude-3-5-sonnet" {
		t.Fatalf("unexpected act claim payload: %+v", actClaim)
	}
}
