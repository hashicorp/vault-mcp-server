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
	"strings"
	"time"
)

// httpTimeout bounds each IdP and STS request. It is a variable so tests can shorten it.
var httpTimeout = 10 * time.Second

// httpClient is used for every IdP token endpoint and STS request.
func httpClient() *http.Client {
	return &http.Client{Timeout: httpTimeout}
}

// maxErrorBody bounds how much of an upstream error response is kept in an
// error message, and so in the logs.
const maxErrorBody = 256

// truncateBody returns raw as a string, cut to maxErrorBody bytes.
func truncateBody(raw []byte) string {
	if len(raw) <= maxErrorBody {
		return string(raw)
	}
	return string(raw[:maxErrorBody]) + "...(truncated)"
}

// isLoopbackHost reports whether host (without port) is localhost or a
// loopback IP address.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// generateState creates a cryptographically random 16-byte CSRF state token
// encoded as base64url without padding. The IdP echoes it back on the callback,
// where it is checked to reject forged or replayed callbacks.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// stateGenerator is the function used to produce a CSRF state token.
// Tests may replace it with a deterministic function to predict the state value.
var stateGenerator = generateState

// ErrAuthTimeout is returned when the PKCE redirect does not arrive before the deadline.
var ErrAuthTimeout = errors.New("auth: PKCE flow timed out waiting for browser redirect")

// PKCEConfig holds the OAuth 2.0 / PKCE parameters needed to run a browser flow.
type PKCEConfig struct {
	// ClientID is the OAuth client identifier registered with the IdP.
	ClientID string
	// ClientSecret is the OAuth client secret. When non-empty, the token
	// endpoint request uses HTTP Basic authentication (client_secret_basic)
	// as required by IBM Verify.
	ClientSecret string
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
	// ActorToken is the raw access token for the MCP Server (client credentials grant).
	ActorToken string
	// SubjectRefreshToken is set only when the IdP issued a refresh_token; it
	// allows the delegation JWT to be renewed without a new browser login.
	SubjectRefreshToken string
	// The issue and expiry times of each access token. IssuedAt is when the token
	// request was sent, so ExpiresAt is never later than the real expiry. A zero
	// ExpiresAt means unknown, in which case the token is renewed with every JWT.
	SubjectIssuedAt  time.Time
	SubjectExpiresAt time.Time
	ActorIssuedAt    time.Time
	ActorExpiresAt   time.Time
}

// tokenResponse is the minimal subset of the OAuth token endpoint JSON response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	// ExpiresIn is json.Number so that both 3600 and "3600" decode. IBM Verify
	// always returns it.
	ExpiresIn json.Number `json:"expires_in"`
	Error     string      `json:"error"`
	ErrorDesc string      `json:"error_description"`

	// IssuedAt and ExpiresAt are filled in by postTokenForm as soon as the
	// response arrives. ExpiresAt is zero when the response had no expires_in.
	IssuedAt  time.Time `json:"-"`
	ExpiresAt time.Time `json:"-"`
}

// PKCEFlowResult is delivered on the channel returned by StartPKCEFlow.
type PKCEFlowResult struct {
	Token *tokenResponse
	Err   error
}

// StartPKCEFlow starts a single PKCE Authorization Code flow and returns the
// authorization URL immediately. The caller must open (or display) the URL.
// The token endpoint response is delivered asynchronously on the returned
// channel (buffered 1). The callback listener is shut down before a result is
// sent, or when ctx is cancelled.
func StartPKCEFlow(ctx context.Context, cfg PKCEConfig, label string) (authURL string, result <-chan PKCEFlowResult, err error) {
	deadline := cfg.Deadline
	if deadline == 0 {
		deadline = 5 * time.Minute
	}
	flowCtx, cancel := context.WithTimeout(ctx, deadline)

	verifier, err := generateCodeVerifier()
	if err != nil {
		cancel()
		return "", nil, fmt.Errorf("generating code verifier: %w", err)
	}
	challenge := codeChallenge(verifier)

	state, err := stateGenerator()
	if err != nil {
		cancel()
		return "", nil, fmt.Errorf("generating state: %w", err)
	}

	redirURL, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		cancel()
		return "", nil, fmt.Errorf("parsing redirect URL: %w", err)
	}
	// The callback listener binds to this host, and the authorization code
	// arrives on it, so it must never listen beyond this machine.
	if !isLoopbackHost(redirURL.Hostname()) {
		cancel()
		return "", nil, fmt.Errorf("redirect URL must use a loopback host (localhost, 127.0.0.1 or ::1); got %q", redirURL.Hostname())
	}
	callbackPath := redirURL.Path
	if callbackPath == "" {
		callbackPath = "/callback"
	}
	listenAddr := redirURL.Host

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if idpErr := q.Get("error"); idpErr != "" {
			errCh <- fmt.Errorf("auth: IdP returned error %q: %s", idpErr, q.Get("error_description"))
			http.Error(w, "Authentication failed. You may close this tab.", http.StatusBadRequest)
			return
		}
		if got := q.Get("state"); got != state {
			errCh <- fmt.Errorf("auth: state mismatch (CSRF check failed)")
			http.Error(w, "State mismatch. You may close this tab.", http.StatusBadRequest)
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
		cancel()
		return "", nil, fmt.Errorf("starting local listener on %s: %w", listenAddr, err)
	}

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	ch := make(chan PKCEFlowResult, 1)
	go func() {
		defer cancel()
		var res PKCEFlowResult
		select {
		case code := <-codeCh:
			tok, err := exchangeCode(cfg, code, verifier, state)
			res = PKCEFlowResult{Token: tok, Err: err}
		case err := <-errCh:
			res = PKCEFlowResult{Err: err}
		case <-flowCtx.Done():
			if errors.Is(flowCtx.Err(), context.DeadlineExceeded) {
				res = PKCEFlowResult{Err: ErrAuthTimeout}
			} else {
				res = PKCEFlowResult{Err: flowCtx.Err()}
			}
		}
		// Release the callback port before delivering the result so the caller
		// can immediately start another flow on the same port.
		srv.Shutdown(context.Background()) //nolint:errcheck
		ch <- res
	}()

	return buildAuthURL(cfg, challenge, state), ch, nil
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
//
// All parameters including redirect_uri are percent-encoded via url.Values.Encode()
// (e.g. "://" → "%3A%2F%2F"). IBM Verify accepts the encoded form and matches it
// against the registered redirect URI correctly.
//
// response_mode=query and state are required by IBM Verify:
//   - response_mode=query ensures the authorization code is returned as a URL
//     query parameter (not a fragment or form_post).
//   - state is a CSRF token validated on the callback.
func buildAuthURL(cfg PKCEConfig, challenge, state string) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("response_mode", "query")
	v.Set("client_id", cfg.ClientID)
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")
	v.Set("state", state)
	v.Set("redirect_uri", cfg.RedirectURL)
	if len(cfg.Scopes) > 0 {
		v.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	return cfg.AuthURL + "?" + v.Encode()
}

// exchangeCode performs the RFC 6749 token endpoint POST to exchange an
// authorization code for an access token.
//
// When cfg.ClientSecret is set, the request uses HTTP Basic authentication
// (client_secret_basic) as required by IBM Verify — the client_id and
// client_secret are sent in the Authorization header rather than the body.
// When cfg.ClientSecret is empty, client_id is included in the POST body
// (client_secret_post / public client behaviour).
//
// The state parameter is accepted but not forwarded to the token endpoint;
// it was already validated by the callback handler before exchangeCode is called.
func exchangeCode(cfg PKCEConfig, code, verifier, _ string) (*tokenResponse, error) {
	body := url.Values{}
	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	body.Set("redirect_uri", cfg.RedirectURL)
	body.Set("code_verifier", verifier)

	tok, err := postTokenForm(cfg.TokenURL, cfg.ClientID, cfg.ClientSecret, body)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

// oauthTokenError is an OAuth error response (RFC 6749 §5.2) from a token
// endpoint, such as invalid_grant.
type oauthTokenError struct {
	Code   string
	Status int
}

func (e *oauthTokenError) Error() string {
	return fmt.Sprintf("token endpoint error %q (HTTP %d)", e.Code, e.Status)
}

// postTokenForm POSTs form to an OAuth token endpoint and returns the parsed
// response. When clientSecret is set, credentials go in the Authorization header
// (client_secret_basic); otherwise client_id is added to the body (public client).
func postTokenForm(tokenURL, clientID, clientSecret string, form url.Values) (*tokenResponse, error) {
	if clientSecret == "" {
		form.Set("client_id", clientID)
	}

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	// The expiry is measured from when the request was sent, so it can only be
	// earlier than the real one, never later.
	issuedAt := time.Now()
	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint POST failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var tok tokenResponse
		if resp.StatusCode < 500 && json.Unmarshal(raw, &tok) == nil && tok.Error != "" {
			return nil, &oauthTokenError{Code: tok.Error, Status: resp.StatusCode}
		}
		return nil, fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, truncateBody(raw))
	}

	var tok tokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}
	if tok.Error != "" {
		return nil, &oauthTokenError{Code: tok.Error, Status: resp.StatusCode}
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint returned empty access_token")
	}
	tok.IssuedAt = issuedAt
	if secs, err := tok.ExpiresIn.Int64(); err == nil && secs > 0 {
		tok.ExpiresAt = issuedAt.Add(time.Duration(secs) * time.Second)
	}
	return &tok, nil
}
