// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the OAuth Authorization Server configuration, loaded from the
// environment. OAuth is enabled only when MCPAuthSecret is set.
type Config struct {
	// MCPAuthSecret is the base64url (32-byte) symmetric key used to seal all
	// stateless OAuth tokens. Empty disables OAuth entirely.
	MCPAuthSecret string

	// ServerURL is the public base URL advertised in OAuth metadata and used to
	// build redirect targets. When empty it is derived per-request from the
	// incoming Host (and X-Forwarded-Proto/Host when behind a proxy).
	ServerURL string

	// Default upstream Vault address and namespace used for the login flows.
	VaultAddr      string
	VaultNamespace string

	// Vault auth method mount points used by the login page.
	LDAPMount     string
	UserpassMount string
	OIDCMount     string
	OIDCRole      string

	// OIDCCallbackPort is the port the server listens on to receive the OIDC
	// callback from the identity provider. Vault's default OIDC role pre-registers
	// http://localhost:8250/oidc/callback (the Vault CLI default), so using port
	// 8250 here requires no Vault admin changes. Set VAULT_OIDC_CALLBACK_PORT=0 to
	// disable the separate listener and use the main port's /vault/oidc/callback
	// route instead (requires that URI to be added to the Vault OIDC role's
	// allowed_redirect_uris by an admin).
	OIDCCallbackPort int

	AuthCodeTTL    time.Duration
	AccessTokenTTL time.Duration
}

// LoadConfigFromEnv builds a Config from environment variables. It never errors;
// call Enabled to decide whether OAuth should be wired in, and Validate to check
// the secret before constructing a Service.
func LoadConfigFromEnv() Config {
	cfg := Config{
		MCPAuthSecret:  strings.TrimSpace(os.Getenv("MCP_AUTH_SECRET")),
		ServerURL:      strings.TrimRight(strings.TrimSpace(os.Getenv("MCP_SERVER_URL")), "/"),
		VaultAddr:      strings.TrimRight(strings.TrimSpace(getenv("VAULT_ADDR", "")), "/"),
		VaultNamespace: strings.TrimSpace(os.Getenv("VAULT_NAMESPACE")),
		LDAPMount:      getenv("VAULT_AUTH_LDAP_MOUNT", "ldap"),
		UserpassMount:  getenv("VAULT_AUTH_USERPASS_MOUNT", "userpass"),
		OIDCMount:        getenv("VAULT_OIDC_MOUNT", "oidc"),
		OIDCRole:         strings.TrimSpace(os.Getenv("VAULT_OIDC_ROLE")),
		OIDCCallbackPort: intEnv("VAULT_OIDC_CALLBACK_PORT", 8250),
		AuthCodeTTL:      durationEnv("MCP_AUTH_CODE_TTL", 5*time.Minute),
		AccessTokenTTL: durationEnv("MCP_AUTH_ACCESS_TTL", 12*time.Hour),
	}
	return cfg
}

// Enabled reports whether OAuth should be activated.
func (c Config) Enabled() bool {
	return c.MCPAuthSecret != ""
}

// Validate checks the auth secret is a usable sealer key.
func (c Config) Validate() error {
	return ValidateKey(c.MCPAuthSecret)
}

// BaseURL returns the public base URL for this server for the given request.
// It prefers an explicitly configured ServerURL, otherwise derives it from the
// request, honoring X-Forwarded-Proto / X-Forwarded-Host set by reverse proxies.
func (c Config) BaseURL(r *http.Request) string {
	if c.ServerURL != "" {
		return c.ServerURL
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); proto != "" {
		scheme = strings.Split(proto, ",")[0]
	}

	host := r.Host
	if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); fwd != "" {
		host = strings.Split(fwd, ",")[0]
	}

	return scheme + "://" + strings.TrimSpace(host)
}

// BasePath returns the URL path prefix under which this server is publicly
// mounted (e.g. "/mcps/vault-mcp"), derived from ServerURL. It is empty when the
// server is served at the host root or ServerURL is unset.
//
// Interactive HTML served by this server (the login page's form actions) MUST
// prefix its links with this value. A reverse proxy strips the prefix before the
// request reaches us, so we never see it on the wire and cannot infer it from the
// request; only ServerURL carries the public mount point. Root-relative links
// (e.g. "/vault/oidc/start") resolve against the host root in the browser and 404
// behind a path prefix.
func (c Config) BasePath() string {
	if c.ServerURL == "" {
		return ""
	}
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return ""
	}
	return strings.TrimRight(u.Path, "/")
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func intEnv(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// OIDCCallbackURL returns the redirect_uri to register with Vault's auth_url
// endpoint. When OIDCCallbackPort > 0 it uses the Vault CLI's pre-registered
// http://localhost:<port>/oidc/callback URI so no Vault admin changes are needed.
// When OIDCCallbackPort == 0 the main server's /vault/oidc/callback is used
// (requires admin registration of that URI in the Vault OIDC role).
func (c Config) OIDCCallbackURL(mainServerURL string) string {
	if c.OIDCCallbackPort > 0 {
		return fmt.Sprintf("http://localhost:%d/oidc/callback", c.OIDCCallbackPort)
	}
	// Default: callback on the main server. The path /oidc/callback matches the
	// URI Vault has pre-registered for localhost:8250 (the Vault CLI default), so
	// running the main server on port 8250 requires no Vault admin changes.
	return mainServerURL + "/oidc/callback"
}
