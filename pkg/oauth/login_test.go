// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"bytes"
	"strings"
	"testing"
)

// TestLoginTemplateBasePath ensures the login page's form actions are prefixed
// with the public BasePath so they resolve behind a reverse-proxy path prefix
// (e.g. /mcps/vault-mcp) instead of the host root — the bug that broke terminal
// MCP clients ("No authorization support detected" / 404 on /vault/oidc/start).
func TestLoginTemplateBasePath(t *testing.T) {
	render := func(basePath string) string {
		var buf bytes.Buffer
		if err := loginTemplate.Execute(&buf, loginPageData{
			AuthState:   "state",
			VaultAddr:   "https://vault.example.com",
			OIDCEnabled: true,
			BasePath:    basePath,
		}); err != nil {
			t.Fatalf("execute template: %v", err)
		}
		return buf.String()
	}

	t.Run("behind path prefix", func(t *testing.T) {
		out := render("/mcps/vault-mcp")
		for _, want := range []string{
			`action="/mcps/vault-mcp/vault/login"`,
			`action="/mcps/vault-mcp/vault/oidc/start"`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("login page missing prefixed form action %q", want)
			}
		}
		if strings.Contains(out, `action="/vault/login"`) {
			t.Error("login page still emits a root-relative action (would 404 behind a prefix)")
		}
	})

	t.Run("at host root", func(t *testing.T) {
		out := render("")
		for _, want := range []string{
			`action="/vault/login"`,
			`action="/vault/oidc/start"`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("root login page missing form action %q", want)
			}
		}
	})
}
