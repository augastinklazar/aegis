package billing

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestBilling_MultiTenant_Quotas(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aegis_billing_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "billing.db")
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bm, err := NewBillingManager(db)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Create a Builder tier tenant with 2 monthly calls
	tenant, err := bm.CreateTenant("cust_alice_123", "builder", 2)
	if err != nil {
		t.Fatalf("create tenant error: %v", err)
	}

	// 2. Consume Call 1
	id1, rem1, err := bm.VerifyAndConsume(tenant.APIKey)
	if err != nil || id1 != "cust_alice_123" || rem1 != 1 {
		t.Fatalf("consume 1 failed: id=%s, rem=%d, err=%v", id1, rem1, err)
	}

	// 3. Consume Call 2
	id2, rem2, err := bm.VerifyAndConsume(tenant.APIKey)
	if err != nil || id2 != "cust_alice_123" || rem2 != 0 {
		t.Fatalf("consume 2 failed: id=%s, rem=%d, err=%v", id2, rem2, err)
	}

	// 4. Call 3: Quota Exceeded
	_, _, err = bm.VerifyAndConsume(tenant.APIKey)
	if err != ErrQuotaExceeded {
		t.Fatalf("expected ErrQuotaExceeded, got: %v", err)
	}

	// 5. Test Billing Middleware with HTTP Handler
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Context().Value("tenant_id")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("OK:%s", tenantID)))
	})

	rapidSecret := "rapidapi_secret_token_123"
	upgradeURL := "https://polar.sh/augastinklazar"
	mw := BillingAuthMiddleware(bm, rapidSecret, upgradeURL)(dummyHandler)

	// Test Path A: RapidAPI Header Bypass
	reqRapid := httptest.NewRequest(http.MethodGet, "/v1/evaluate", nil)
	reqRapid.Header.Set("X-RapidAPI-Proxy-Secret", rapidSecret)
	reqRapid.Header.Set("X-RapidAPI-User", "dev_bob")
	recRapid := httptest.NewRecorder()
	mw.ServeHTTP(recRapid, reqRapid)

	if recRapid.Code != http.StatusOK || recRapid.Body.String() != "OK:rapid_dev_bob" {
		t.Fatalf("RapidAPI auth failed: code=%d, body=%s", recRapid.Code, recRapid.Body.String())
	}

	// Test Path B: Exceeded Quota direct key returns 402 Payment Required
	reqDirect := httptest.NewRequest(http.MethodGet, "/v1/evaluate", nil)
	reqDirect.Header.Set("Authorization", "Bearer "+tenant.APIKey)
	recDirect := httptest.NewRecorder()
	mw.ServeHTTP(recDirect, reqDirect)

	if recDirect.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 Payment Required for exhausted quota, got: %d", recDirect.Code)
	}

	// Test Path C: Polar.sh Webhook provisioning new tenant
	webhookPayload := PolarWebhookPayload{
		Type: "subscription.created",
	}
	webhookPayload.Data.Customer.ID = "cust_charlie_789"
	webhookPayload.Data.Customer.Email = "charlie@startup.io"
	webhookPayload.Data.Product.Name = "Aegis Builder Plan"
	webhookPayload.Data.Status = "active"

	webhookBody, _ := json.Marshal(webhookPayload)
	reqHook := httptest.NewRequest(http.MethodPost, "/v1/webhooks/polar", bytes.NewReader(webhookBody))
	recHook := httptest.NewRecorder()
	bm.HandlePolarWebhook(recHook, reqHook)

	if recHook.Code != http.StatusOK {
		t.Fatalf("polar webhook failed: code=%d, body=%s", recHook.Code, recHook.Body.String())
	}

	var hookResp map[string]interface{}
	json.Unmarshal(recHook.Body.Bytes(), &hookResp)
	if hookResp["tenant_id"] != "cust_charlie_789" {
		t.Fatalf("unexpected tenant in webhook response: %+v", hookResp)
	}
}
