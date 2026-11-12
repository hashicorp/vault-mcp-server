// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// generateState creates a cryptographically random 16-byte CSRF state token
// encoded as base64url without padding.
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
	token, err := runSinglePKCETokenFlow(ctx, cfg, label)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

func runSinglePKCETokenFlow(ctx context.Context, cfg PKCEConfig, label string) (*Token, error) {
	_, results, err := startPKCETokenFlow(ctx, cfg, label)
	if err != nil {
		return nil, err
	}
	result := <-results
	if result.Err != nil {
		return nil, result.Err
	}
	return &result.Token, nil
}

func startPKCETokenFlow(ctx context.Context, cfg PKCEConfig, label string) (string, <-chan SubjectLoginResult, error) {
	deadline := cfg.Deadline
	if deadline == 0 {
		deadline = 5 * time.Minute
	}
	flowCtx, cancel := context.WithTimeout(ctx, deadline)

	// Generate PKCE verifier and S256 challenge.
	verifier, err := generateCodeVerifier()
	if err != nil {
		cancel()
		return "", nil, fmt.Errorf("generating code verifier: %w", err)
	}
	challenge := codeChallenge(verifier)

	// Generate a CSRF state token.
	state, err := stateGenerator()
	if err != nil {
		cancel()
		return "", nil, fmt.Errorf("generating state: %w", err)
	}

	// Parse RedirectURL to extract the callback path and listener address.
	redirURL, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		cancel()
		return "", nil, fmt.Errorf("parsing redirect URL: %w", err)
	}
	callbackPath := redirURL.Path
	if callbackPath == "" {
		callbackPath = "/callback"
	}
	listenAddr := redirURL.Host // host:port — must match IdP-registered redirect URI

	// codeCh receives the authorization code (or an error string) from the handler.
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if idpErr := q.Get("error"); idpErr != "" {
			desc := q.Get("error_description")
			select {
			case errCh <- fmt.Errorf("auth: IdP returned error %q: %s", idpErr, desc):
			default:
			}
			http.Error(w, "Authentication failed. You may close this tab.", http.StatusBadRequest)
			return
		}
		// Validate CSRF state.
		if got := q.Get("state"); got != state {
			select {
			case errCh <- fmt.Errorf("auth: state mismatch (CSRF check failed)"):
			default:
			}
			http.Error(w, "State mismatch. You may close this tab.", http.StatusBadRequest)
			return
		}
		code := q.Get("code")
		if code == "" {
			select {
			case errCh <- fmt.Errorf("auth: redirect missing 'code' parameter"):
			default:
			}
			http.Error(w, "Missing code. You may close this tab.", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(os.Stderr, "[vault-mcp-server] %s auth code received\n", label)
		select {
		case codeCh <- code:
		default:
			http.Error(w, "Callback already received.", http.StatusConflict)
			return
		}
		fmt.Fprintf(w, "Authentication successful (%s). You may close this tab.", label)
	})

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		cancel()
		return "", nil, fmt.Errorf("starting local listener on %s: %w", listenAddr, err)
	}

	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case errCh <- fmt.Errorf("auth: callback server failed: %w", err):
			default:
			}
		}
	}()

	// Build the authorization URL.
	authURL := buildAuthURL(cfg, challenge, state)
	fmt.Fprintf(os.Stderr, "[vault-mcp-server] Opening browser for %s authentication\n", label)
	if err := openBrowser(authURL); err != nil {
		fmt.Fprintf(os.Stderr, "[vault-mcp-server] Could not open browser: %v; open the sign-in URL returned by the login tool manually\n", err)
	}

	results := make(chan SubjectLoginResult, 1)
	go func() {
		defer cancel()
		defer close(results)
		var result SubjectLoginResult
		select {
		case code := <-codeCh:
			token, err := exchangeCodeToken(flowCtx, cfg, code, verifier)
			result.Err = err
			if token != nil {
				result.Token = *token
			}
		case err := <-errCh:
			result.Err = err
		case <-flowCtx.Done():
			result.Err = flowCtx.Err()
			if errors.Is(result.Err, context.DeadlineExceeded) {
				result.Err = ErrAuthTimeout
			}
		}
		shutdownCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "[vault-mcp-server] Callback shutdown failed: %v\n", err)
			if err := srv.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "[vault-mcp-server] Callback close failed: %v\n", err)
			}
		}
		results <- result
	}()
	return authURL, results, nil
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
func exchangeCode(cfg PKCEConfig, code, verifier, _ string) (string, error) {
	token, err := exchangeCodeToken(context.Background(), cfg, code, verifier)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

func exchangeCodeToken(ctx context.Context, cfg PKCEConfig, code, verifier string) (*Token, error) {
	body := url.Values{}
	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	body.Set("redirect_uri", cfg.RedirectURL)
	body.Set("code_verifier", verifier)

	return postTokenForm(ctx, cfg.TokenURL, cfg.ClientID, cfg.ClientSecret, body)
}

// openBrowser attempts to open u in a private/incognito window.
// It returns an error if no supported browser is available or if the
// browser process cannot be started.
func openBrowser(u string) error {
	type candidate struct {
		bin  string
		flag string
	}

	var candidates []candidate

	switch runtime.GOOS {
	case "darwin":
		candidates = []candidate{
			{"google-chrome", "--incognito"},
			{"chromium", "--incognito"},
			{"firefox", "--private-window"},
			{"brave-browser", "--incognito"},
		}
	case "windows":
		candidates = []candidate{
			{"chrome", "--incognito"},
			{"msedge", "--inprivate"},
			{"firefox", "--private-window"},
			{"brave", "--incognito"},
		}
	default: // Linux / BSD
		candidates = []candidate{
			{"google-chrome", "--incognito"},
			{"google-chrome-stable", "--incognito"},
			{"chromium-browser", "--incognito"},
			{"chromium", "--incognito"},
			{"firefox", "--private-window"},
			{"brave-browser", "--incognito"},
		}
	}

	var foundBrowser bool
	var lastErr error

	for _, c := range candidates {
		path, err := exec.LookPath(c.bin)
		if err != nil {
			continue
		}

		foundBrowser = true

		cmd := exec.Command(path, c.flag, u)
		if err := cmd.Start(); err != nil {
			lastErr = fmt.Errorf("failed to start %s in private mode: %w", c.bin, err)
			continue
		}

		return nil
	}

	if !foundBrowser {
		return fmt.Errorf("no supported browser found for opening private/incognito window")
	}

	return fmt.Errorf("failed to open URL in private/incognito window: %w", lastErr)
}

// openBrowser attempts to open u in an incognito/private window of the first
// browser binary found on PATH, then falls back to the OS default opener.
// Failure is non-fatal: the URL is already printed to stdout for manual use.
/*func openBrowser(u string) {
	// Browsers tried in order; first match wins.
	// Each entry is {binary, incognito-flag}.
	type candidate struct{ bin, flag string }
	var candidates []candidate
	switch runtime.GOOS {
	case "darwin":
		candidates = []candidate{
			{"google-chrome", "--incognito"},
			{"chromium", "--incognito"},
			{"firefox", "--private-window"},
			{"brave-browser", "--incognito"},
		}
	case "windows":
		candidates = []candidate{
			{"chrome", "--incognito"},
			{"msedge", "--inprivate"},
			{"firefox", "--private-window"},
			{"brave", "--incognito"},
		}
	default: // Linux / BSD
		candidates = []candidate{
			{"google-chrome", "--incognito"},
			{"google-chrome-stable", "--incognito"},
			{"chromium-browser", "--incognito"},
			{"chromium", "--incognito"},
			{"firefox", "--private-window"},
			{"brave-browser", "--incognito"},
		}
	}


	for _, c := range candidates {
		if path, err := exec.LookPath(c.bin); err == nil {
			_ = exec.Command(path, c.flag, u).Start()
			return
		}
	}

	// No known browser found — fall back to the OS default opener without
	// incognito (open / start / xdg-open do not support browser-specific flags).
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Start()
}*/
