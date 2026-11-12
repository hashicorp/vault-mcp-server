package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OAuthTokenError struct {
	Code   string
	Status int
}

func (e *OAuthTokenError) Error() string {
	return fmt.Sprintf("auth: token endpoint returned OAuth error %q (HTTP %d)", e.Code, e.Status)
}

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
	return postTokenForm(ctx, cfg.TokenURL, cfg.ActorClientID, cfg.ActorClientSecret, form)
}

func postTokenForm(ctx context.Context, tokenURL, clientID, clientSecret string, form url.Values) (*Token, error) {
	if tokenURL == "" || clientID == "" {
		return nil, fmt.Errorf("auth: token URL and client ID are required")
	}
	if clientSecret == "" {
		form.Set("client_id", clientID)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("auth: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: token request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Token
		ExpiresIn int64  `json:"expires_in"`
		Error     string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("auth: token endpoint returned HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("auth: decoding token: %w", err)
	}
	if result.Error != "" {
		return nil, &OAuthTokenError{Code: result.Error, Status: resp.StatusCode}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("auth: token endpoint returned HTTP %d", resp.StatusCode)
	}
	if result.AccessToken == "" {
		return nil, fmt.Errorf("auth: empty access token")
	}
	if result.ExpiresIn > 0 {
		result.ExpiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	}
	return &result.Token, nil
}
