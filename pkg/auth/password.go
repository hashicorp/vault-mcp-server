package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func PasswordGrant(ctx context.Context, cfg AuthConfig) (*Token, error) {
	if cfg.ActorUsername == "" || cfg.ActorPassword == "" {
		return nil, fmt.Errorf("auth: actor username and password are required")
	}

	form := url.Values{
		"grant_type": {"password"},
		"username":   {cfg.ActorUsername},
		"password":   {cfg.ActorPassword},
	}
	if len(cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	if cfg.ActorClientSecret == "" {
		form.Set("client_id", cfg.ActorClientID)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, cfg.TokenURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("auth: building password request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cfg.ActorClientSecret != "" {
		req.SetBasicAuth(cfg.ActorClientID, cfg.ActorClientSecret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: password login failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("auth: password login returned HTTP %d", resp.StatusCode)
	}

	var token Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("auth: decoding token: %w", err)
	}
	if token.AccessToken == "" {
		return nil, fmt.Errorf("auth: empty access token")
	}

	return &token, nil
}
