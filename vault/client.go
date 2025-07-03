// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"sync"
)

var activeClients sync.Map

func NewVaultClient(sessionId string, vaultAddress string, vaultToken string) (*api.Client, error) {
	// Initialize Vault client
	config := api.DefaultConfig()
	config.Address = vaultAddress

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %v", err)
	}

	client.SetToken(vaultToken)

	//client.Auth().Login(ctx, &api.TokenAuth{})
	activeClients.Store(sessionId, client)

	return client, nil
}

func GetVaultClient(sessionId string) *api.Client {
	if value, ok := activeClients.Load(sessionId); ok {
		return value.(*api.Client)
	}

	return nil
}

func DeleteVaultClient(sessionId string) {
	activeClients.Delete(sessionId)
}
