// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"strings"

	"github.com/hashicorp/vault/api"
)

func withOptionalNamespace(vault *api.Client, namespace string) *api.Client {
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		return vault
	}
	return vault.WithNamespace(ns)
}