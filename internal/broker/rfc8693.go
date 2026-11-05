package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
)

type TokenExchangeRequest struct {
	GrantType            string `json:"grant_type"`
	SubjectToken         string `json:"subject_token"`
	SubjectTokenType     string `json:"subject_token_type"`
	ActorToken           string `json:"actor_token"` // Agent ID or agent token
	ActorTokenType       string `json:"actor_token_type"`
	Audience             string `json:"audience"` // e.g. stripe_prod, github_api
	Scope                string `json:"scope"`
	TaskID               string `json:"task_id"`
	Reason               string `json:"reason,omitempty"`                // AAuth draft-rosenberg natural language reason
	AuthorizationDetails string `json:"authorization_details,omitempty"` // RAR RFC 9396
	TTLSeconds           int    `json:"ttl_seconds,omitempty"`
	MaxCalls             int    `json:"max_calls,omitempty"`
}

type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"` // Phantom token (ag_tok_...)
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"` // Bearer
	ExpiresIn       int    `json:"expires_in"` // seconds
	JWT             string `json:"jwt,omitempty"`
	Scope           string `json:"scope,omitempty"`
}

type Broker struct {
	phantomManager *PhantomManager
	agentRegistry  *AgentRegistry
	jwtSecret      []byte
}

func NewBroker(pm *PhantomManager, ar *AgentRegistry, jwtSecret []byte) *Broker {
	return &Broker{
		phantomManager: pm,
		agentRegistry:  ar,
		jwtSecret:      jwtSecret,
	}
}

func (b *Broker) HandleTokenExchange(req *TokenExchangeRequest) (*TokenExchangeResponse, error) {
	if req.GrantType != GrantTypeTokenExchange {
		return nil, errors.New("unsupported_grant_type: must be " + GrantTypeTokenExchange)
	}
	if req.SubjectToken == "" {
		return nil, errors.New("invalid_request: missing subject_token")
	}
	if req.ActorToken == "" {
		return nil, errors.New("invalid_request: missing actor_token (agent_id)")
	}
	if req.Audience == "" {
		return nil, errors.New("invalid_request: missing audience (target service)")
	}

	taskID := req.TaskID
	if taskID == "" {
		taskID = "task_" + uuid.New().String()[:8]
	}

	ttl := 10 * time.Minute
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	// Parse RAR details if supplied
	var authDetails []AuthorizationDetail
	if req.AuthorizationDetails != "" {
		if strings.HasPrefix(strings.TrimSpace(req.AuthorizationDetails), "[") {
			json.Unmarshal([]byte(req.AuthorizationDetails), &authDetails)
		} else {
			var single AuthorizationDetail
			if err := json.Unmarshal([]byte(req.AuthorizationDetails), &single); err == nil {
				authDetails = append(authDetails, single)
			}
		}
	}

	scopes := strings.Fields(req.Scope)

	// Issue phantom token
	pt, err := b.phantomManager.IssueToken(
		req.ActorToken,
		taskID,
		req.SubjectToken,
		req.Audience,
		scopes,
		authDetails,
		ttl,
		req.MaxCalls,
	)
	if err != nil {
		return nil, fmt.Errorf("issue phantom token: %w", err)
	}

	// Build RFC 8693 compliant JWT with act claim
	modelProvider := "unknown"
	if manifest, err := b.agentRegistry.Get(req.ActorToken); err == nil {
		modelProvider = manifest.ModelProvider
	}

	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": "aegis-auth",
		"sub": req.SubjectToken, // Human user who delegated authority
		"aud": req.Audience,
		"act": map[string]interface{}{
			"sub":     req.ActorToken, // Agent ID
			"task_id": taskID,
			"model":   modelProvider,
		},
		"iat": now.Unix(),
		"exp": pt.ExpiresAt.Unix(),
		"jti": pt.Token,
	}

	if req.Scope != "" {
		claims["scope"] = req.Scope
	}
	if len(authDetails) > 0 {
		claims["authorization_details"] = authDetails
	}
	if req.Reason != "" {
		claims["reason"] = req.Reason
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedJWT, err := token.SignedString(b.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("sign jwt: %w", err)
	}

	return &TokenExchangeResponse{
		AccessToken:     pt.Token,
		IssuedTokenType: TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int(ttl.Seconds()),
		JWT:             signedJWT,
		Scope:           req.Scope,
	}, nil
}

func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req TokenExchangeRequest
	ct := r.Header.Get("Content-Type")

	if strings.Contains(ct, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, `{"error":"invalid_form"}`, http.StatusBadRequest)
			return
		}
		req = TokenExchangeRequest{
			GrantType:            r.FormValue("grant_type"),
			SubjectToken:         r.FormValue("subject_token"),
			SubjectTokenType:     r.FormValue("subject_token_type"),
			ActorToken:           r.FormValue("actor_token"),
			ActorTokenType:       r.FormValue("actor_token_type"),
			Audience:             r.FormValue("audience"),
			Scope:                r.FormValue("scope"),
			TaskID:               r.FormValue("task_id"),
			Reason:               r.FormValue("reason"),
			AuthorizationDetails: r.FormValue("authorization_details"),
		}
	}

	resp, err := b.HandleTokenExchange(&req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
