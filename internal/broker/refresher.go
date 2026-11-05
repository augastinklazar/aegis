package broker

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/augastinklazar/aegis/internal/vault"
)

type RefresherDaemon struct {
	vault    *vault.Vault
	interval time.Duration
	client   *http.Client
}

func NewRefresherDaemon(v *vault.Vault, interval time.Duration) *RefresherDaemon {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &RefresherDaemon{
		vault:    v,
		interval: interval,
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

func (rd *RefresherDaemon) Start(ctx context.Context) {
	ticker := time.NewTicker(rd.interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := rd.RefreshExpiringTokens(); err != nil {
					log.Printf("[refresher] error checking tokens: %v", err)
				}
			}
		}
	}()
}

func (rd *RefresherDaemon) RefreshExpiringTokens() error {
	expiring, err := rd.vault.GetExpiringOAuthTokens(5 * time.Minute)
	if err != nil {
		return err
	}

	for _, rec := range expiring {
		if rec.RefreshURL == "" || rec.RefreshToken == "" {
			continue
		}

		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {rec.RefreshToken},
		}
		if rec.ClientID != "" {
			form.Set("client_id", rec.ClientID)
		}
		if rec.ClientSecret != "" {
			form.Set("client_secret", rec.ClientSecret)
		}

		req, err := http.NewRequest(http.MethodPost, rec.RefreshURL, strings.NewReader(form.Encode()))
		if err != nil {
			log.Printf("[refresher] create req failed for %s: %v", rec.ServiceID, err)
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := rd.client.Do(req)
		if err != nil {
			log.Printf("[refresher] refresh failed for %s: %v", rec.ServiceID, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			body, _ := io.ReadAll(resp.Body)
			var tokenResp struct {
				AccessToken string `json:"access_token"`
				ExpiresIn   int64  `json:"expires_in"`
			}
			if err := json.Unmarshal(body, &tokenResp); err == nil && tokenResp.AccessToken != "" {
				exp := time.Now().UTC().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
				if tokenResp.ExpiresIn == 0 {
					exp = time.Now().UTC().Add(3600 * time.Second)
				}
				if err := rd.vault.UpdateOAuthAccessToken(rec.ServiceID, tokenResp.AccessToken, exp); err != nil {
					log.Printf("[refresher] update token in vault failed for %s: %v", rec.ServiceID, err)
				} else {
					log.Printf("[refresher] successfully refreshed token for %s", rec.ServiceID)
				}
			}
		} else {
			log.Printf("[refresher] provider returned status %d for %s", resp.StatusCode, rec.ServiceID)
		}
	}
	return nil
}
