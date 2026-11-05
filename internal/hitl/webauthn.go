package hitl

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
)

type WebAuthnUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.ID
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.Name
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

type PasskeyManager struct {
	webAuthn *webauthn.WebAuthn
	db       *sql.DB
	hmacKey  []byte
}

func NewPasskeyManager(db *sql.DB, rawURL string, hmacKey []byte) (*PasskeyManager, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		rawURL = "http://localhost:8080"
		u, _ = url.Parse(rawURL)
	}

	rpID := u.Hostname()
	if rpID == "" {
		rpID = "localhost"
	}

	origin := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	if u.Scheme == "" {
		origin = "http://" + u.Host
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Aegis Auth Gateway",
		RPID:          rpID,
		RPOrigins:     []string{origin, "http://localhost:8080", "http://127.0.0.1:8080"},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn init: %w", err)
	}

	pm := &PasskeyManager{
		webAuthn: wa,
		db:       db,
		hmacKey:  hmacKey,
	}

	if err := pm.initSchema(); err != nil {
		return nil, fmt.Errorf("passkey schema init: %w", err)
	}

	return pm, nil
}

func (pm *PasskeyManager) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS passkey_users (
		username TEXT PRIMARY KEY,
		user_id BLOB NOT NULL,
		credentials_json TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS passkey_sessions (
		token TEXT PRIMARY KEY,
		session_data TEXT NOT NULL,
		expires_at DATETIME NOT NULL
	);
	`
	_, err := pm.db.Exec(schema)
	return err
}

func (pm *PasskeyManager) WebAuthn() *webauthn.WebAuthn {
	return pm.webAuthn
}

func (pm *PasskeyManager) GetUser(username string) (*WebAuthnUser, error) {
	var uid []byte
	var credsJSON string
	err := pm.db.QueryRow(`SELECT user_id, credentials_json FROM passkey_users WHERE username = ?`, username).Scan(&uid, &credsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, err
	}

	var creds []webauthn.Credential
	json.Unmarshal([]byte(credsJSON), &creds)

	return &WebAuthnUser{
		ID:          uid,
		Name:        username,
		DisplayName: strings.Title(username),
		Credentials: creds,
	}, nil
}

func (pm *PasskeyManager) SaveUser(u *WebAuthnUser) error {
	credsJSON, _ := json.Marshal(u.Credentials)
	query := `
	INSERT INTO passkey_users (username, user_id, credentials_json)
	VALUES (?, ?, ?)
	ON CONFLICT(username) DO UPDATE SET
		credentials_json=excluded.credentials_json;
	`
	_, err := pm.db.Exec(query, u.Name, u.ID, string(credsJSON))
	return err
}

// GenerateHMACSignature generates an immutable proof signature for approval sign-offs
func (pm *PasskeyManager) GenerateHMACSignature(requestID, decision, approver string) string {
	mac := hmac.New(sha256.New, pm.hmacKey)
	payload := fmt.Sprintf("%s:%s:%s", requestID, decision, approver)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func (pm *PasskeyManager) VerifyHMACSignature(requestID, decision, approver, sig string) bool {
	expected := pm.GenerateHMACSignature(requestID, decision, approver)
	return hmac.Equal([]byte(expected), []byte(sig))
}
