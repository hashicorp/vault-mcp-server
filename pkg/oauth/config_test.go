// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import "testing"

func TestConfigBasePath(t *testing.T) {
	cases := []struct {
		name      string
		serverURL string
		want      string
	}{
		{"prefixed", "https://dev.vionix.kortex.vionix.viasat.io/mcps/vault-mcp", "/mcps/vault-mcp"},
		{"prefixed trailing slash", "https://host/mcps/vault-mcp/", "/mcps/vault-mcp"},
		{"deep path", "https://host/a/b/c", "/a/b/c"},
		{"root host only", "https://host", ""},
		{"root slash", "https://host/", ""},
		{"empty (localhost/no prefix)", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Config{ServerURL: tc.serverURL}.BasePath()
			if got != tc.want {
				t.Errorf("BasePath(%q) = %q, want %q", tc.serverURL, got, tc.want)
			}
		})
	}
}
