package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
)

type Config struct {
	Port         string
	DBPath       string
	VaultKey     []byte
	JWTSecret    []byte
	PoliciesDir  string
	BaseURL      string
	TelegramBot  string
	TelegramChat string
	DiscordHook  string
	SlackHook    string
}

func LoadConfig() (*Config, error) {
	port := getEnv("AEGIS_PORT", "8080")
	dbPath := getEnv("AEGIS_DB_PATH", "aegis.db")
	policiesDir := getEnv("AEGIS_POLICIES_DIR", "policies")
	baseURL := getEnv("AEGIS_BASE_URL", "http://localhost:"+port)

	// 32-byte AES-256 vault key
	vaultKeyHex := os.Getenv("AEGIS_VAULT_KEY")
	var vaultKey []byte
	if vaultKeyHex != "" {
		var err error
		vaultKey, err = hex.DecodeString(vaultKeyHex)
		if err != nil || len(vaultKey) != 32 {
			// fallback if raw string provided
			vaultKey = make([]byte, 32)
			copy(vaultKey, []byte(vaultKeyHex))
		}
	} else {
		// Stable default or randomized
		vaultKey = []byte("aegis-master-encryption-key-32b!")
	}

	jwtSecret := []byte(getEnv("AEGIS_JWT_SECRET", "aegis-jwt-secret-signing-token-must-be-long"))

	return &Config{
		Port:         port,
		DBPath:       dbPath,
		VaultKey:     vaultKey,
		JWTSecret:    jwtSecret,
		PoliciesDir:  policiesDir,
		BaseURL:      baseURL,
		TelegramBot:  os.Getenv("AEGIS_TELEGRAM_BOT_TOKEN"),
		TelegramChat: os.Getenv("AEGIS_TELEGRAM_CHAT_ID"),
		DiscordHook:  os.Getenv("AEGIS_DISCORD_WEBHOOK_URL"),
		SlackHook:    os.Getenv("AEGIS_SLACK_WEBHOOK_URL"),
	}, nil
}

func GenerateKeyHex() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}
