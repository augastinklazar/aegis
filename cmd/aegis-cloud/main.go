package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/augastinklazar/aegis/internal/audit"
	"github.com/augastinklazar/aegis/internal/billing"
	"github.com/augastinklazar/aegis/internal/hitl"
	"github.com/augastinklazar/aegis/internal/hitl/notifiers"
	"github.com/augastinklazar/aegis/internal/sandbox"
	"github.com/augastinklazar/aegis/internal/vault"
	"github.com/augastinklazar/aegis/web"
	_ "modernc.org/sqlite"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = os.Getenv("AEGIS_PORT")
	}
	if port == "" {
		port = "8080"
	}

	dbPath := os.Getenv("AEGIS_DATABASE_URL")
	if dbPath == "" {
		dbPath = os.Getenv("AEGIS_DB_PATH")
	}
	if dbPath == "" {
		dbPath = "aegis-cloud.db"
	}

	baseURL := os.Getenv("AEGIS_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:" + port
	}

	rapidAPISecret := os.Getenv("AEGIS_RAPIDAPI_SECRET")
	upgradeURL := os.Getenv("AEGIS_UPGRADE_URL")
	if upgradeURL == "" {
		upgradeURL = "https://polar.sh/augastinklazar"
	}

	vaultKey := []byte(os.Getenv("AEGIS_VAULT_KEY"))
	if len(vaultKey) != 32 {
		vaultKey = []byte("aegis-cloud-master-vault-key32b")
	}

	// 1. Initialize SQLite / Turso WAL database
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatalf("cloud database open error: %v", err)
	}
	defer db.Close()

	// 2. Billing Manager & Multi-tenant Quota
	bm, err := billing.NewBillingManager(db)
	if err != nil {
		log.Fatalf("billing manager init: %v", err)
	}

	// Ensure free default demo tenant exists for direct testing
	_, _ = bm.CreateTenant("community_demo", "free", 500)

	// 3. Sandbox CEL Engine
	sc, err := sandbox.NewStateCounter(db)
	if err != nil {
		log.Fatalf("state counter init: %v", err)
	}

	sb, err := sandbox.NewCELEngine(sc)
	if err != nil {
		log.Fatalf("cel engine init: %v", err)
	}
	policiesDir := os.Getenv("AEGIS_POLICIES_DIR")
	if policiesDir == "" {
		policiesDir = "policies"
	}
	sb.LoadPoliciesFromDir(policiesDir)
	sb.LoadPoliciesFromDir(filepath.Join(policiesDir, "presets"))

	// 4. Audit Logger
	al, err := audit.NewLogger(db)
	if err != nil {
		log.Fatalf("audit logger init: %v", err)
	}

	// 5. Cloud Escalation Relay & Notifiers
	park, err := hitl.NewParkManager(db)
	if err != nil {
		log.Fatalf("park manager init: %v", err)
	}

	disp := notifiers.NewDispatcher(
		os.Getenv("AEGIS_TELEGRAM_BOT_TOKEN"),
		os.Getenv("AEGIS_TELEGRAM_CHAT_ID"),
		os.Getenv("AEGIS_DISCORD_WEBHOOK_URL"),
		os.Getenv("AEGIS_SLACK_WEBHOOK_URL"),
	)
	relay := hitl.NewCloudRelayHandler(park, disp, baseURL)
	evaluateHandler := sandbox.NewEvaluateHandler(sb)

	passkeyMgr, _ := hitl.NewPasskeyManager(db, baseURL, vaultKey)

	// 6. Router & Middleware
	mux := http.NewServeMux()
	billingAuth := billing.BillingAuthMiddleware(bm, rapidAPISecret, upgradeURL)

	// Public Healthcheck
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy","service":"aegis-cloud","version":"0.2.0"}`))
	})

	// Web UI & Embedded Mobile Passkey Approval Screen
	mux.Handle("/", web.AssetHandler())

	// Polar.sh Webhook (Automated payments & API key provision)
	mux.HandleFunc("POST /v1/webhooks/polar", bm.HandlePolarWebhook)

	// Public Escalation Resolution (from user mobile browser)
	mux.HandleFunc("GET /v1/escalate/{id}", relay.HandlePoll)

	mux.HandleFunc("POST /v1/hitl/requests/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var body struct {
			Approver  string `json:"approver"`
			Signature string `json:"signature"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Approver == "" {
			body.Approver = "cloud_approver"
		}
		if body.Signature == "" && passkeyMgr != nil {
			body.Signature = passkeyMgr.GenerateHMACSignature(id, "APPROVED", body.Approver)
		}

		if err := park.Resolve(id, true, body.Approver, body.Signature, ""); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "approved", "request_id": id})
	})

	mux.HandleFunc("POST /v1/hitl/requests/{id}/deny", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var body struct {
			Approver string `json:"approver"`
			Reason   string `json:"reason"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Reason == "" {
			body.Reason = "Denied by mobile reviewer"
		}
		if err := park.Resolve(id, false, body.Approver, "", body.Reason); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "denied", "request_id": id})
	})

	// Paid Protected Endpoints:
	// 1. Stateless Evaluation API
	mux.Handle("POST /v1/evaluate", billingAuth(evaluateHandler))

	// 2. Hosted Escalation Relay API
	mux.Handle("POST /v1/escalate", billingAuth(http.HandlerFunc(relay.HandleEscalate)))

	// 3. Multi-Tenant Cloud Audit Trail
	mux.Handle("GET /v1/audit/cloud", billingAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Context().Value("tenant_id")
		entries, err := al.GetRecent(50)
		if err != nil {
			http.Error(w, `{"error":"failed_reading_audit"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tenant_id": tenantID,
			"records":   entries,
		})
	})))

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go func() {
		log.Printf("🚀 Aegis Cloud Multi-Tenant API running on %s", baseURL)
		log.Printf("   ├─ Stateless Guardrail: POST %s/v1/evaluate", baseURL)
		log.Printf("   ├─ Cloud Escalation Relay: POST %s/v1/escalate", baseURL)
		log.Printf("   ├─ Mobile Approval UI: %s/approve.html?id=...", baseURL)
		log.Printf("   └─ Polar Webhooks: POST %s/v1/webhooks/polar", baseURL)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("cloud server error: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

func init() {
	_ = vault.ErrSecretNotFound
}
