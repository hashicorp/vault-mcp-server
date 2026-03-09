// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"fmt"

	"github.com/hashicorp/vault/api"
)

// getMountInfo checks whether a mount exists and if it's a KV v2 mount.
// Returns isV2=true for KV v2 mounts, isV2=false for KV v1 mounts.
// Returns an error if the mount does not exist.
func getMountInfo(vault *api.Client, mount string) (isV2 bool, err error) {
	mounts, err := vault.Sys().ListMounts()
	if err != nil {
		return false, fmt.Errorf("failed to list mounts: %v", err)
	}

	m, ok := mounts[mount+"/"]
	if !ok {
		return false, fmt.Errorf("mount path '%s' does not exist. Use 'create_mount' with the type kv2 to create the mount", mount)
	}

	if m.Options["version"] == "2" {
		return true, nil
	}

	return false, nil
}
