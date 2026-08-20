// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ErrAuthTimeout is returned when the PKCE redirect does not arrive before the deadline.
var ErrAuthTimeout = errors.New("auth: PKCE flow timed out waiting for browser redirect")

// PKCEConfig holds the OAuth 2.0 / PKCE parameters needed to run a browser flow.
type PKCEConfig struct {
	// ClientID is the OAuth client identifier registered with the IdP.
	ClientID string
	// AuthURL is the IdP's authorization endpoint.
	AuthURL string
	// TokenURL is the IdP's token endpoint (used for the code exchange).
	TokenURL string
	// RedirectURL is the local callback URL (e.g. http://localhost:49152/callback).
	// The listener binds to the port embedded in this URL.
	RedirectURL string
	// Scopes is the list of OAuth scopes to request.
	Scopes []string
	// Deadline is the per-flow timeout. Defaults to 5 minutes when zero.
	Deadline time.Duration
}

// PKCEResult contains the raw token strings returned from both PKCE flows.
type PKCEResult struct {
	// SubjectToken is the raw access token for the human user (Subject flow).
	SubjectToken string
	// ActorToken is the raw access token for the MCP Server (Actor flow).
	ActorToken string
}

// tokenResponse is the minimal subset of the OAuth token endpoint JSON response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// RunPKCEFlows executes two sequential PKCE Authorization Code flows — first
// Subject (human user), then Actor (MCP Server) — using the provided config.
// Each flow opens a temporary local HTTP listener, launches the browser to the
// IdP authorization URL, waits for the redirect callback, exchanges the
// authorization code for a token, and shuts the listener down before the next
// flow begins. The caller receives a PKCEResult with both raw access tokens.
func RunPKCEFlows(ctx context.Context, cfg PKCEConfig) (*PKCEResult, error) {
	subjectToken, err := runSinglePKCEFlow(ctx, cfg, "Subject")
	if err != nil {
		return nil, fmt.Errorf("auth: Subject PKCE flow failed: %w", err)
	}

	actorToken, err := runSinglePKCEFlow(ctx, cfg, "Actor")
	if err != nil {
		return nil, fmt.Errorf("auth: Actor PKCE flow failed: %w", err)
	}

	return &PKCEResult{
		SubjectToken: subjectToken,
		ActorToken:   actorToken,
	}, nil
}

// runSinglePKCEFlow runs one PKCE Authorization Code flow and returns the raw
// access token string. label is used only for logging / stderr messages.
func runSinglePKCEFlow(ctx context.Context, cfg PKCEConfig, label string) (string, error) {
	deadline := cfg.Deadline
	if deadline == 0 {
		deadline = 5 * time.Minute
	}
	flowCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	// Generate PKCE verifier and S256 challenge.
	verifier, err := generateCodeVerifier()
	if err != nil {
		return "", fmt.Errorf("generating code verifier: %w", err)
	}
	challenge := codeChallenge(verifier)

	// Parse RedirectURL to extract the callback path and listener port.
	redirURL, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return "", fmt.Errorf("parsing redirect URL: %w", err)
	}
	callbackPath := redirURL.Path
	if callbackPath == "" {
		callbackPath = "/callback"
	}
	listenAddr := redirURL.Host // host:port

	// codeCh receives the authorization code (or an error string) from the handler.
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if idpErr := q.Get("error"); idpErr != "" {
			desc := q.Get("error_description")
			errCh <- fmt.Errorf("auth: IdP returned error %q: %s", idpErr, desc)
			http.Error(w, "Authentication failed. You may close this tab.", http.StatusBadRequest)
			return
		}
		code := q.Get("code")
		if code == "" {
			errCh <- fmt.Errorf("auth: redirect missing 'code' parameter")
			http.Error(w, "Missing code. You may close this tab.", http.StatusBadRequest)
			return
		}
		codeCh <- code
		fmt.Fprintf(w, "Authentication successful (%s). You may close this tab.", label)
	})

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", fmt.Errorf("starting local listener on %s: %w", listenAddr, err)
	}

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Shutdown(context.Background()) //nolint:errcheck // best-effort shutdown

	// Build the authorization URL.
	authURL := buildAuthURL(cfg, challenge)
	fmt.Printf("[vault-mcp-server] Opening browser for %s authentication:\n  %s\n", label, authURL)
	openBrowser(authURL)

	// Wait for the redirect code, a timeout, or a cancellation.
	select {
	case code := <-codeCh:
		return exchangeCode(cfg, code, verifier)
	case err := <-errCh:
		return "", err
	case <-flowCtx.Done():
		if errors.Is(flowCtx.Err(), context.DeadlineExceeded) {
			return "", ErrAuthTimeout
		}
		return "", flowCtx.Err()
	}
}

// generateCodeVerifier creates a cryptographically random 32-byte PKCE verifier
// encoded as base64url without padding (RFC 7636).
func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// codeChallenge computes the S256 PKCE challenge from a verifier (RFC 7636 §4.2).
func codeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// buildAuthURL constructs the IdP authorization URL with PKCE parameters.
func buildAuthURL(cfg PKCEConfig, challenge string) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", cfg.ClientID)
	v.Set("redirect_uri", cfg.RedirectURL)
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")
	if len(cfg.Scopes) > 0 {
		v.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	return cfg.AuthURL + "?" + v.Encode()
}

// exchangeCode performs the RFC 6749 token endpoint POST to exchange an
// authorization code for an access token.
func exchangeCode(cfg PKCEConfig, code, verifier string) (string, error) {
	body := url.Values{}
	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	body.Set("redirect_uri", cfg.RedirectURL)
	body.Set("client_id", cfg.ClientID)
	body.Set("code_verifier", verifier)

	resp, err := http.PostForm(cfg.TokenURL, body)
	if err != nil {
		return "", fmt.Errorf("token endpoint POST failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var tok tokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}
	if tok.Error != "" {
		return "", fmt.Errorf("token endpoint error %q: %s", tok.Error, tok.ErrorDesc)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned empty access_token")
	}
	return tok.AccessToken, nil
}

// openBrowser attempts to open url in the user's default browser.
// Failure is non-fatal: the URL is already printed to stdout for manual use.
func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Start() // best-effort
}
