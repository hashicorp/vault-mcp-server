// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
)

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Vault MCP — Sign In</title>
  {{if .RedirectURL}}<meta http-equiv="refresh" content="1;url={{.RedirectURL}}" />{{end}}
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; background:#f5f5f5; margin:0; }
    .card { max-width:480px; margin:8vh auto; background:#fff; padding:24px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.08); }
    h1 { margin:0 0 8px; font-size:20px; }
    p { margin:0 0 16px; color:#555; font-size:14px; line-height:1.4; }
    label { display:block; font-weight:600; font-size:13px; margin:12px 0 6px; }
    input, select { width:100%; padding:10px 12px; border:1px solid #ddd; border-radius:8px; font-size:14px; box-sizing:border-box; }
    button { width:100%; margin-top:16px; padding:10px 12px; border:0; border-radius:8px; background:#000; color:#fff; font-weight:700; font-size:14px; cursor:pointer; }
    .oidc { background:#ffce00; color:#000; }
    .err { background:#fdecea; border:1px solid #f5c6cb; color:#7a1c1c; padding:10px 12px; border-radius:8px; margin-bottom:12px; font-size:13px; }
    .success { background:#e7f7ed; border:1px solid #b7ebc6; color:#0f5132; padding:10px 12px; border-radius:8px; margin-bottom:12px; font-size:13px; }
    .note { background:#fff8e1; border-left:4px solid #ff8f00; padding:10px 12px; border-radius:8px; margin-top:16px; font-size:13px; color:#555; }
    .hide { display:none; }
    hr { border:0; border-top:1px solid #eee; margin:20px 0; }
    a { color:#0052cc; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Vault MCP Server</h1>

    {{if .RedirectURL}}
      <div class="success">Authentication succeeded. Redirecting…</div>
      <p>If you are not redirected, <a href="{{.RedirectURL}}">continue</a>.</p>
      <div class="note">It is safe to close this tab — your MCP client now holds an encrypted access token. Nothing is stored server-side.</div>
    {{else}}
      <p>Sign in to <strong>{{.VaultAddr}}</strong>. Your Vault token is encrypted into your MCP bearer token.</p>
      {{if .Error}}<div class="err">{{.Error}}</div>{{end}}

      <form method="POST" action="{{.BasePath}}/vault/login">
        <input type="hidden" name="auth_state" value="{{.AuthState}}" />
        <label for="method">Authentication method</label>
        <select id="method" name="method">
          <option value="ldap">LDAP (username / password)</option>
          <option value="userpass">Userpass (username / password)</option>
        </select>

        <div id="userpassFields">
          <label for="username">Username</label>
          <input id="username" name="username" type="text" autocomplete="username" placeholder="e.g. mdesales" />
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password" />
        </div>

        <button type="submit">Sign in</button>
      </form>

      {{if .OIDCEnabled}}
      <hr />
      <form method="POST" action="{{.BasePath}}/vault/oidc/start">
        <input type="hidden" name="auth_state" value="{{.AuthState}}" />
        <button type="submit" class="oidc">Sign in with OIDC (SSO)</button>
      </form>
      {{end}}

      <div class="note">Credentials/tokens are encrypted into your MCP bearer token. Treat them as sensitive.</div>
    {{end}}
  </div>
</body>
</html>`))

type loginPageData struct {
	AuthState   string
	VaultAddr   string
	Error       string
	RedirectURL string
	OIDCEnabled bool
	// BasePath is the public path prefix (e.g. "/mcps/vault-mcp") the server is
	// mounted under, prepended to the login/OIDC form actions so they resolve
	// behind a reverse-proxy prefix instead of the host root. Empty at the root.
	BasePath string
}

// vaultLogin renders the login page (GET) and handles credential submission (POST).
func (r *Router) vaultLogin(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		r.renderLogin(w, req, req.URL.Query().Get("auth_state"), req.URL.Query().Get("error"))
	case http.MethodPost:
		r.handleLoginSubmit(w, req)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (r *Router) renderLogin(w http.ResponseWriter, req *http.Request, authState, errMsg string) {
	if authState == "" {
		http.Error(w, "missing auth_state", http.StatusBadRequest)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTemplate.Execute(w, loginPageData{
		AuthState:   authState,
		VaultAddr:   r.vaultAuthParams().Address,
		Error:       errMsg,
		OIDCEnabled: true,
		BasePath:    r.cfg.BasePath(),
	})
}

func (r *Router) handleLoginSubmit(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	encState := req.FormValue("auth_state")
	method := strings.TrimSpace(req.FormValue("method"))

	var st AuthState
	if _, err := r.tokenSvc.Parse(string(TokenTypeAuthState), encState, &st); err != nil {
		http.Error(w, "invalid or expired auth_state", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(req.Context(), 20*time.Second)
	defer cancel()

	params := r.vaultAuthParams()

	username := strings.TrimSpace(req.FormValue("username"))
	password := req.FormValue("password")
	if username == "" || password == "" {
		r.renderLogin(w, req, encState, "username and password are required")
		return
	}

	var vaultToken string
	var err error
	switch method {
	case "ldap":
		vaultToken, err = client.LoginLDAP(ctx, params, r.cfg.LDAPMount, username, password)
	case "userpass":
		vaultToken, err = client.LoginUserpass(ctx, params, r.cfg.UserpassMount, username, password)
	default:
		r.renderLogin(w, req, encState, "unsupported authentication method")
		return
	}

	if err != nil {
		r.logger.WithError(err).Warn("vault login failed")
		r.renderLogin(w, req, encState, "authentication failed: "+truncateErr(err))
		return
	}

	r.issueAuthCodeAndRedirect(w, req, st, vaultToken)
}

// issueAuthCodeAndRedirect mints an authorization code carrying the Vault token
// and redirects the browser back to the MCP client's redirect_uri.
func (r *Router) issueAuthCodeAndRedirect(w http.ResponseWriter, req *http.Request, st AuthState, vaultToken string) {
	codeData := AuthCodeData{
		VaultToken:           vaultToken,
		VaultAddr:            r.vaultAuthParams().Address,
		VaultNamespace:       r.cfg.VaultNamespace,
		RedirectURI:          st.RedirectURI,
		CodeChallenge:        st.CodeChallenge,
		CodeChallengeMethod:  st.CodeChallengeMethod,
		State:                st.State,
		Scopes:               st.Scopes,
		ClientID:             st.ClientID,
		CreatedAtUnixSeconds: time.Now().UTC().Unix(),
	}
	code, _, err := r.tokenSvc.Mint(string(TokenTypeAuthCode), r.cfg.AuthCodeTTL, codeData)
	if err != nil {
		http.Error(w, "failed to issue auth code", http.StatusInternalServerError)
		return
	}

	cb, err := url.Parse(st.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := cb.Query()
	q.Set("code", code)
	if st.State != "" {
		q.Set("state", st.State)
	}
	cb.RawQuery = q.Encode()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTemplate.Execute(w, loginPageData{RedirectURL: cb.String()})
}

// renderCallbackError renders a standalone error card using the same styles as
// the login page. It is used by the OIDC callback handler when it cannot
// redirect back to the login page (e.g., unknown or expired pending state).
func (r *Router) renderCallbackError(w http.ResponseWriter, msg string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_ = callbackErrorTemplate.Execute(w, msg)
}

var callbackErrorTemplate = template.Must(template.New("callbackError").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Vault MCP — Sign In Error</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; background:#f5f5f5; margin:0; }
    .card { max-width:480px; margin:8vh auto; background:#fff; padding:24px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.08); }
    h1 { margin:0 0 8px; font-size:20px; }
    p { margin:0 0 16px; color:#555; font-size:14px; line-height:1.4; }
    .err { background:#fdecea; border:1px solid #f5c6cb; color:#7a1c1c; padding:10px 12px; border-radius:8px; margin-bottom:12px; font-size:13px; }
    .note { background:#fff8e1; border-left:4px solid #ff8f00; padding:10px 12px; border-radius:8px; margin-top:16px; font-size:13px; color:#555; }
    a { color:#0052cc; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Vault MCP Server</h1>
    <div class="err">{{.}}</div>
    <div class="note">Please close this tab and restart the sign-in flow from your MCP client.</div>
  </div>
</body>
</html>`))

func truncateErr(err error) string {
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(s) > 240 {
		return s[:240] + "…"
	}
	return s
}
