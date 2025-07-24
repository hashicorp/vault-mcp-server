// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"
)

func TestParseVaultUIURL(t *testing.T) {
	tests := []struct {
		name           string
		url            string
		expectedMount  string
		expectedSecret string
		expectedPolicy string
		expectedType   string
		expectError    bool
	}{
		{
			name:           "secrets with mount and secret",
			url:            "http://localhost:4200/ui/vault/secrets/kv-random/kv/alpha",
			expectedMount:  "kv-random",
			expectedSecret: "alpha",
			expectedPolicy: "",
			expectedType:   "secrets",
			expectError:    false,
		},
		{
			name:           "secrets with mount and list",
			url:            "http://localhost:4200/ui/vault/secrets/kv-random/kv/list",
			expectedMount:  "kv-random",
			expectedSecret: "",
			expectedPolicy: "",
			expectedType:   "secrets",
			expectError:    false,
		},
		{
			name:           "policy URL",
			url:            "http://localhost:4200/ui/vault/policy/acl/default",
			expectedMount:  "",
			expectedSecret: "",
			expectedPolicy: "default",
			expectedType:   "policy",
			expectError:    false,
		},
		{
			name:           "secrets with complex mount name",
			url:            "http://localhost:4200/ui/vault/secrets/my-complex-mount-123/kv/my-secret",
			expectedMount:  "my-complex-mount-123",
			expectedSecret: "my-secret",
			expectedPolicy: "",
			expectedType:   "secrets",
			expectError:    false,
		},
		{
			name:           "policy with complex policy name",
			url:            "http://localhost:4200/ui/vault/policy/acl/my-complex-policy-123",
			expectedMount:  "",
			expectedSecret: "",
			expectedPolicy: "my-complex-policy-123",
			expectedType:   "policy",
			expectError:    false,
		},
		{
			name:           "policy with complex policy name",
			url:            "http://hcp.portal.com/ui/vault/policy/acl/my-complex-policy-123",
			expectedMount:  "",
			expectedSecret: "",
			expectedPolicy: "my-complex-policy-123",
			expectedType:   "policy",
			expectError:    false,
		},
		{
			name:        "invalid URL - not vault UI",
			url:         "http://localhost:4200/some/other/path",
			expectError: true,
		},
		{
			name:        "invalid URL - malformed",
			url:         "not-a-url",
			expectError: true,
		},
		{
			name:        "incomplete secrets URL",
			url:         "http://localhost:4200/ui/vault/secrets/kv-random",
			expectError: true,
		},
		{
			name:        "incomplete policy URL",
			url:         "http://localhost:4200/ui/vault/policy/acl",
			expectError: true,
		},
		{
			name:        "unsupported URL type",
			url:         "http://localhost:4200/ui/vault/unsupported/something",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseVaultUIURL(tt.url)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result.MountName != tt.expectedMount {
				t.Errorf("mount name: expected %q, got %q", tt.expectedMount, result.MountName)
			}

			if result.SecretName != tt.expectedSecret {
				t.Errorf("secret name: expected %q, got %q", tt.expectedSecret, result.SecretName)
			}

			if result.PolicyName != tt.expectedPolicy {
				t.Errorf("policy name: expected %q, got %q", tt.expectedPolicy, result.PolicyName)
			}

			if result.URLType != tt.expectedType {
				t.Errorf("URL type: expected %q, got %q", tt.expectedType, result.URLType)
			}
		})
	}
}
