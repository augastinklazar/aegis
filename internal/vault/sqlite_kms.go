package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrSecretNotFound = errors.New("secret not found in vault")
	ErrInvalidKey     = errors.New("invalid master key: must be 32 bytes for AES-256")
)

type OAuthTokenRecord struct {
	ServiceID    string
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
	RefreshURL   string
	ClientID     string
	ClientSecret string
}

type Vault struct {
	db  *sql.DB
	gcm cipher.AEAD
}

func NewVault(dbPath string, masterKey []byte) (*Vault, error) {
	if len(masterKey) != 32 {
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("cipher init: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init: %w", err)
	}

	// Open SQLite with WAL mode & busy timeout
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	v := &Vault{
		db:  db,
		gcm: gcm,
	}

	if err := v.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return v, nil
}

func (v *Vault) DB() *sql.DB {
	return v.db
}

func (v *Vault) Close() error {
	return v.db.Close()
}

func (v *Vault) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS vault_secrets (
		service_id TEXT PRIMARY KEY,
		ciphertext BLOB NOT NULL,
		nonce BLOB NOT NULL,
		metadata TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS oauth_tokens (
		service_id TEXT PRIMARY KEY,
		access_token BLOB NOT NULL,
		access_nonce BLOB NOT NULL,
		refresh_token BLOB,
		refresh_nonce BLOB,
		token_type TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		refresh_url TEXT,
		client_id TEXT,
		client_secret BLOB,
		client_secret_nonce BLOB,
		updated_at DATETIME NOT NULL
	);
	`
	_, err := v.db.Exec(schema)
	return err
}

func (v *Vault) encrypt(plaintext []byte) (ciphertext, nonce []byte, err error) {
	nonce = make([]byte, v.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = v.gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func (v *Vault) decrypt(ciphertext, nonce []byte) ([]byte, error) {
	return v.gcm.Open(nil, nonce, ciphertext, nil)
}

func (v *Vault) SetSecret(serviceID, secret string) error {
	ciphertext, nonce, err := v.encrypt([]byte(secret))
	if err != nil {
		return fmt.Errorf("encrypt secret: %w", err)
	}

	now := time.Now().UTC()
	query := `
	INSERT INTO vault_secrets (service_id, ciphertext, nonce, metadata, created_at, updated_at)
	VALUES (?, ?, ?, '', ?, ?)
	ON CONFLICT(service_id) DO UPDATE SET
		ciphertext=excluded.ciphertext,
		nonce=excluded.nonce,
		updated_at=excluded.updated_at;
	`
	_, err = v.db.Exec(query, serviceID, ciphertext, nonce, now, now)
	return err
}

func (v *Vault) GetSecret(serviceID string) (string, error) {
	var ciphertext, nonce []byte
	query := `SELECT ciphertext, nonce FROM vault_secrets WHERE service_id = ?`
	err := v.db.QueryRow(query, serviceID).Scan(&ciphertext, &nonce)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrSecretNotFound
	}
	if err != nil {
		return "", err
	}

	decrypted, err := v.decrypt(ciphertext, nonce)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}

	return string(decrypted), nil
}

func (v *Vault) DeleteSecret(serviceID string) error {
	_, err := v.db.Exec(`DELETE FROM vault_secrets WHERE service_id = ?`, serviceID)
	return err
}

func (v *Vault) ListServices() ([]string, error) {
	rows, err := v.db.Query(`SELECT service_id FROM vault_secrets ORDER BY service_id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		services = append(services, s)
	}
	return services, nil
}

func (v *Vault) StoreOAuthToken(rec *OAuthTokenRecord) error {
	accCipher, accNonce, err := v.encrypt([]byte(rec.AccessToken))
	if err != nil {
		return err
	}

	var refCipher, refNonce []byte
	if rec.RefreshToken != "" {
		refCipher, refNonce, err = v.encrypt([]byte(rec.RefreshToken))
		if err != nil {
			return err
		}
	}

	var csCipher, csNonce []byte
	if rec.ClientSecret != "" {
		csCipher, csNonce, err = v.encrypt([]byte(rec.ClientSecret))
		if err != nil {
			return err
		}
	}

	now := time.Now().UTC()
	query := `
	INSERT INTO oauth_tokens (
		service_id, access_token, access_nonce, refresh_token, refresh_nonce,
		token_type, expires_at, refresh_url, client_id, client_secret, client_secret_nonce, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(service_id) DO UPDATE SET
		access_token=excluded.access_token,
		access_nonce=excluded.access_nonce,
		refresh_token=excluded.refresh_token,
		refresh_nonce=excluded.refresh_nonce,
		token_type=excluded.token_type,
		expires_at=excluded.expires_at,
		refresh_url=excluded.refresh_url,
		client_id=excluded.client_id,
		client_secret=excluded.client_secret,
		client_secret_nonce=excluded.client_secret_nonce,
		updated_at=excluded.updated_at;
	`
	_, err = v.db.Exec(query,
		rec.ServiceID, accCipher, accNonce, refCipher, refNonce,
		rec.TokenType, rec.ExpiresAt, rec.RefreshURL, rec.ClientID,
		csCipher, csNonce, now,
	)
	return err
}

func (v *Vault) GetOAuthToken(serviceID string) (*OAuthTokenRecord, error) {
	query := `
	SELECT service_id, access_token, access_nonce, refresh_token, refresh_nonce,
	       token_type, expires_at, refresh_url, client_id, client_secret, client_secret_nonce
	FROM oauth_tokens WHERE service_id = ?
	`
	var (
		rec                                       OAuthTokenRecord
		accCipher, accNonce                       []byte
		refCipher, refNonce                       []byte
		csCipher, csNonce                         []byte
		refreshURL, clientID                      sql.NullString
	)

	err := v.db.QueryRow(query, serviceID).Scan(
		&rec.ServiceID, &accCipher, &accNonce, &refCipher, &refNonce,
		&rec.TokenType, &rec.ExpiresAt, &refreshURL, &clientID,
		&csCipher, &csNonce,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSecretNotFound
	}
	if err != nil {
		return nil, err
	}

	rec.RefreshURL = refreshURL.String
	rec.ClientID = clientID.String

	accBytes, err := v.decrypt(accCipher, accNonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt access token: %w", err)
	}
	rec.AccessToken = string(accBytes)

	if len(refCipher) > 0 && len(refNonce) > 0 {
		refBytes, err := v.decrypt(refCipher, refNonce)
		if err == nil {
			rec.RefreshToken = string(refBytes)
		}
	}

	if len(csCipher) > 0 && len(csNonce) > 0 {
		csBytes, err := v.decrypt(csCipher, csNonce)
		if err == nil {
			rec.ClientSecret = string(csBytes)
		}
	}

	return &rec, nil
}

func (v *Vault) GetExpiringOAuthTokens(threshold time.Duration) ([]*OAuthTokenRecord, error) {
	cutoff := time.Now().UTC().Add(threshold)
	query := `SELECT service_id FROM oauth_tokens WHERE expires_at <= ? AND refresh_token IS NOT NULL`
	rows, err := v.db.Query(query, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*OAuthTokenRecord
	for rows.Next() {
		var sID string
		if err := rows.Scan(&sID); err != nil {
			continue
		}
		rec, err := v.GetOAuthToken(sID)
		if err == nil {
			results = append(results, rec)
		}
	}
	return results, nil
}

func (v *Vault) UpdateOAuthAccessToken(serviceID, accessToken string, expiresAt time.Time) error {
	accCipher, accNonce, err := v.encrypt([]byte(accessToken))
	if err != nil {
		return err
	}
	query := `UPDATE oauth_tokens SET access_token = ?, access_nonce = ?, expires_at = ?, updated_at = ? WHERE service_id = ?`
	_, err = v.db.Exec(query, accCipher, accNonce, expiresAt, time.Now().UTC(), serviceID)
	return err
}
