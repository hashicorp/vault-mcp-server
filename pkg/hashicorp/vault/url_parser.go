// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"net/url"
	"regexp"
)

// VaultUIComponents represents the extracted components from a Vault UI URL
type VaultUIComponents struct {
	MountName  string `json:"mount_name,omitempty"`
	SecretName string `json:"secret_name,omitempty"`
	PolicyName string `json:"policy_name,omitempty"`
	URLType    string `json:"url_type,omitempty"`
}

var (
	// Regex patterns for different Vault UI URL types
	secretsURLPattern  = regexp.MustCompile(`^.*/ui/vault/secrets/([^/]+)/([^/]+)/([^/]+?)/?$`)
	secretsListPattern = regexp.MustCompile(`^.*/ui/vault/secrets/([^/]+)/([^/]+)/list/?$`)
	policyURLPattern   = regexp.MustCompile(`^.*/ui/vault/policy/([^/]+)/([^/]+)/?$`)
)

// ParseVaultUIURL extracts mount names, secret names, and policy names from Vault UI URL patterns
//
// Supported URL patterns:
// - http://localhost:4200/ui/vault/secrets/{mount}/{engine}/{secret} - extracts mount and secret
// - http://localhost:4200/ui/vault/secrets/{mount}/{engine}/list - extracts mount only
// - http://localhost:4200/ui/vault/policy/acl/{policy} - extracts policy name
//
// Examples:
//   - http://localhost:4200/ui/vault/secrets/kv-random/kv/alpha -> mount: "kv-random", secret: "alpha"
//   - http://localhost:4200/ui/vault/secrets/kv-random/kv/list -> mount: "kv-random"
//   - http://localhost:4200/ui/vault/policy/acl/default -> policy: "default"
func ParseVaultUIURL(rawURL string) (*VaultUIComponents, error) {
	// Parse the URL to validate it's a proper URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	path := parsedURL.Path
	result := &VaultUIComponents{}

	// Try to match secrets list URL first (more specific pattern)
	if matches := secretsListPattern.FindStringSubmatch(path); matches != nil {
		result.URLType = "secrets"
		result.MountName = matches[1]
		// SecretName remains empty for list operations
		return result, nil
	}

	// Try to match secrets URL with specific secret
	if matches := secretsURLPattern.FindStringSubmatch(path); matches != nil {
		result.URLType = "secrets"
		result.MountName = matches[1]
		result.SecretName = matches[3]
		return result, nil
	}

	// Try to match policy URL
	if matches := policyURLPattern.FindStringSubmatch(path); matches != nil {
		result.URLType = "policy"
		result.PolicyName = matches[2]
		return result, nil
	}

	return nil, fmt.Errorf("URL does not match any supported Vault UI pattern")
}
