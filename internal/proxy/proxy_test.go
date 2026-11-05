package proxy

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/augastinklazar/aegis/internal/audit"
	"github.com/augastinklazar/aegis/internal/broker"
	"github.com/augastinklazar/aegis/internal/hitl"
	"github.com/augastinklazar/aegis/internal/hitl/notifiers"
	"github.com/augastinklazar/aegis/internal/sandbox"
	"github.com/augastinklazar/aegis/internal/vault"
	_ "modernc.org/sqlite"
)

func TestGateway_CredentialInjection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aegis_proxy_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "proxy.db")
	db, _ := sql.Open("sqlite", dbPath)
	defer db.Close()

	masterKey := []byte("01234567890123456789012345678901")
	v, _ := vault.NewVault(dbPath, masterKey)
	defer v.Close()

	// 1. Store real upstream secret in vault
	realSecret := "sk_test_mock_stripe_secret_key"
	v.SetSecret("stripe_prod", realSecret)

	// 2. Mock upstream server (e.g. simulated Stripe)
	var capturedAuthHeader string
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"ref_123","status":"succeeded"}`))
	}))
	defer mockUpstream.Close()

	// 3. Setup Aegis Gateway
	pm, _ := broker.NewPhantomManager(db)
	sc, _ := sandbox.NewStateCounter(db)
	sb, _ := sandbox.NewCELEngine(sc)
	park, _ := hitl.NewParkManager(db)
	disp := notifiers.NewDispatcher("", "", "", "")
	al, _ := audit.NewLogger(db)

	gw := NewGateway(v, pm, sb, sc, park, disp, al, "http://localhost:8080")
	gw.SetUpstreamRoute("stripe_prod", mockUpstream.URL)

	// 4. Issue task-scoped phantom token
	pt, err := pm.IssueToken("agent_bot", "task_01", "human_user", "stripe_prod", nil, nil, 10*time.Minute, 5)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Agent sends request to Gateway with ephemeral phantom token
	reqBody := `{"amount": 1000, "currency": "usd"}`
	req := httptest.NewRequest(http.MethodPost, "/proxy/stripe_prod/v1/refunds", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+pt.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aegis-Reason", "Agent issuing customer requested refund")

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 OK, got %d: %s", resp.StatusCode, string(body))
	}

	// 6. Verify Upstream received the REAL decrypted secret, NOT the phantom token!
	expectedAuth := "Bearer " + realSecret
	if capturedAuthHeader != expectedAuth {
		t.Fatalf("credential injection failed: expected %s, got %s", expectedAuth, capturedAuthHeader)
	}

	// 7. Verify Merkle audit chain recorded the action
	entries, err := al.GetRecent(5)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	if entries[0].Decision != "ALLOWED" || entries[0].Service != "stripe_prod" {
		t.Fatalf("unexpected audit entry: %+v", entries[0])
	}
}
