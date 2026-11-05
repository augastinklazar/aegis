package billing

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidKey    = errors.New("invalid or inactive api key")
	ErrQuotaExceeded = errors.New("monthly api quota exceeded")
)

type Tenant struct {
	TenantID     string    `json:"tenant_id"`
	APIKey       string    `json:"api_key"`
	Plan         string    `json:"plan"` // free, builder, team
	MonthlyQuota int64     `json:"monthly_quota"`
	UsedQuota    int64     `json:"used_quota"`
	ResetAt      time.Time `json:"reset_at"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
}

type BillingManager struct {
	db *sql.DB
	mu sync.Mutex
}

func NewBillingManager(db *sql.DB) (*BillingManager, error) {
	bm := &BillingManager{db: db}
	if err := bm.initSchema(); err != nil {
		return nil, fmt.Errorf("init billing schema: %w", err)
	}
	return bm, nil
}

func (bm *BillingManager) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS tenants (
		tenant_id TEXT PRIMARY KEY,
		api_key TEXT UNIQUE NOT NULL,
		plan TEXT NOT NULL,
		monthly_quota INTEGER NOT NULL,
		used_quota INTEGER NOT NULL,
		reset_at DATETIME NOT NULL,
		active BOOLEAN NOT NULL,
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_tenants_api_key ON tenants(api_key);
	`
	_, err := bm.db.Exec(schema)
	return err
}

func GenerateAPIKey(prefix string) string {
	b := make([]byte, 20)
	rand.Read(b)
	if prefix == "" {
		prefix = "ag_live_"
	}
	return prefix + hex.EncodeToString(b)
}

func (bm *BillingManager) CreateTenant(tenantID, plan string, quota int64) (*Tenant, error) {
	apiKey := GenerateAPIKey("ag_live_")
	now := time.Now().UTC()
	resetAt := now.AddDate(0, 1, 0) // 1 month

	t := &Tenant{
		TenantID:     tenantID,
		APIKey:       apiKey,
		Plan:         plan,
		MonthlyQuota: quota,
		UsedQuota:    0,
		ResetAt:      resetAt,
		Active:       true,
		CreatedAt:    now,
	}

	query := `
	INSERT INTO tenants (tenant_id, api_key, plan, monthly_quota, used_quota, reset_at, active, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(tenant_id) DO UPDATE SET
		plan=excluded.plan,
		monthly_quota=excluded.monthly_quota,
		active=excluded.active;
	`
	_, err := bm.db.Exec(query, t.TenantID, t.APIKey, t.Plan, t.MonthlyQuota, t.UsedQuota, t.ResetAt, t.Active, t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (bm *BillingManager) VerifyAndConsume(apiKey string) (string, int64, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	var t Tenant
	query := `SELECT tenant_id, plan, monthly_quota, used_quota, reset_at, active FROM tenants WHERE api_key = ?`
	err := bm.db.QueryRow(query, apiKey).Scan(&t.TenantID, &t.Plan, &t.MonthlyQuota, &t.UsedQuota, &t.ResetAt, &t.Active)
	if errors.Is(err, sql.ErrNoRows) || !t.Active {
		return "", 0, ErrInvalidKey
	}
	if err != nil {
		return "", 0, err
	}

	now := time.Now().UTC()
	// Reset quota if month passed
	if now.After(t.ResetAt) {
		t.UsedQuota = 0
		t.ResetAt = now.AddDate(0, 1, 0)
		bm.db.Exec(`UPDATE tenants SET used_quota = 0, reset_at = ? WHERE tenant_id = ?`, t.ResetAt, t.TenantID)
	}

	if t.MonthlyQuota > 0 && t.UsedQuota >= t.MonthlyQuota {
		return t.TenantID, 0, ErrQuotaExceeded
	}

	t.UsedQuota++
	_, err = bm.db.Exec(`UPDATE tenants SET used_quota = ? WHERE tenant_id = ?`, t.UsedQuota, t.TenantID)
	if err != nil {
		return "", 0, err
	}

	remaining := t.MonthlyQuota - t.UsedQuota
	if t.MonthlyQuota == 0 {
		remaining = 999999999 // Unlimited
	}
	return t.TenantID, remaining, nil
}

// BillingAuthMiddleware supports both RapidAPI marketplace and direct Polar.sh API keys
func BillingAuthMiddleware(bm *BillingManager, rapidAPISecret, upgradeURL string) func(http.Handler) http.Handler {
	if upgradeURL == "" {
		upgradeURL = "https://polar.sh/augastinklazar"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Path A: Customer comes via RapidAPI Marketplace
			rapidSecretHeader := r.Header.Get("X-RapidAPI-Proxy-Secret")
			if rapidAPISecret != "" && rapidSecretHeader == rapidAPISecret {
				rapidUser := r.Header.Get("X-RapidAPI-User")
				if rapidUser == "" {
					rapidUser = "anonymous"
				}
				tenantID := "rapid_" + rapidUser
				ctx := context.WithValue(r.Context(), "tenant_id", tenantID)
				ctx = context.WithValue(ctx, "plan", "rapidapi")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Path B: Direct customer using Polar.sh / Lemon Squeezy API key
			authHeader := r.Header.Get("Authorization")
			apiKey := strings.TrimPrefix(authHeader, "Bearer ")
			if apiKey == "" || apiKey == authHeader {
				apiKey = r.Header.Get("X-Aegis-Key")
			}

			if apiKey == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error":       "missing_api_key",
					"message":     "Provide 'Authorization: Bearer ag_live_...' or 'X-Aegis-Key'",
					"upgrade_url": upgradeURL,
				})
				return
			}

			tenantID, remaining, err := bm.VerifyAndConsume(apiKey)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				if errors.Is(err, ErrQuotaExceeded) {
					w.WriteHeader(http.StatusPaymentRequired)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"error":       "quota_exceeded",
						"message":     "Monthly API call allowance exhausted. Upgrade plan for higher limits.",
						"upgrade_url": upgradeURL,
					})
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "invalid_api_key",
					"message": err.Error(),
				})
				return
			}

			w.Header().Set("X-Aegis-Remaining-Quota", fmt.Sprintf("%d", remaining))
			ctx := context.WithValue(r.Context(), "tenant_id", tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// PolarWebhookPayload represents subscription events from Polar.sh
type PolarWebhookPayload struct {
	Type string `json:"type"` // order.created, subscription.created, subscription.updated
	Data struct {
		ID           string `json:"id"`
		Customer     struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"customer"`
		Product struct {
			Name string `json:"name"`
		} `json:"product"`
		Status string `json:"status"`
	} `json:"data"`
}

func (bm *BillingManager) HandlePolarWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload PolarWebhookPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	customerID := payload.Data.Customer.ID
	if customerID == "" {
		customerID = payload.Data.Customer.Email
	}
	if customerID == "" {
		http.Error(w, "missing customer identifier", http.StatusBadRequest)
		return
	}

	plan := strings.ToLower(payload.Data.Product.Name)
	var quota int64 = 50000 // default Builder: 50k
	if strings.Contains(plan, "team") || strings.Contains(plan, "compliance") {
		quota = 500000
	} else if strings.Contains(plan, "free") {
		quota = 500
	}

	tenant, err := bm.CreateTenant(customerID, plan, quota)
	if err != nil {
		http.Error(w, "failed updating tenant: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "processed",
		"tenant_id": tenant.TenantID,
		"api_key":   tenant.APIKey,
		"quota":     tenant.MonthlyQuota,
	})
}
