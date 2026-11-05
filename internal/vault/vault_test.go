package vault

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVault_KMS(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aegis_vault_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test_vault.db")
	masterKey := []byte("01234567890123456789012345678901") // 32 bytes

	v, err := NewVault(dbPath, masterKey)
	if err != nil {
		t.Fatalf("failed creating vault: %v", err)
	}
	defer v.Close()

	// Test Secret storage and retrieval
	service := "stripe_prod"
	secret := "sk_test_mock_stripe_api_key_9988"

	if err := v.SetSecret(service, secret); err != nil {
		t.Fatalf("set secret error: %v", err)
	}

	got, err := v.GetSecret(service)
	if err != nil {
		t.Fatalf("get secret error: %v", err)
	}
	if got != secret {
		t.Fatalf("expected secret %s, got %s", secret, got)
	}

	// Test Listing
	services, err := v.ListServices()
	if err != nil || len(services) != 1 || services[0] != service {
		t.Fatalf("unexpected services list: %v", services)
	}

	// Test OAuth Token storage & update
	rec := &OAuthTokenRecord{
		ServiceID:    "google_oauth",
		AccessToken:  "ya29.initial_access_token",
		RefreshToken: "1//refresh_token_xyz",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		RefreshURL:   "https://oauth2.googleapis.com/token",
		ClientID:     "client_123",
		ClientSecret: "secret_456",
	}

	if err := v.StoreOAuthToken(rec); err != nil {
		t.Fatalf("store oauth token error: %v", err)
	}

	gotRec, err := v.GetOAuthToken("google_oauth")
	if err != nil {
		t.Fatalf("get oauth token error: %v", err)
	}
	if gotRec.AccessToken != rec.AccessToken || gotRec.RefreshToken != rec.RefreshToken {
		t.Fatalf("oauth record mismatch: %+v", gotRec)
	}

	// Test Delete
	if err := v.DeleteSecret(service); err != nil {
		t.Fatalf("delete error: %v", err)
	}
	if _, err := v.GetSecret(service); err != ErrSecretNotFound {
		t.Fatalf("expected ErrSecretNotFound, got %v", err)
	}
}
