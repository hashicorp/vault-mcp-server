// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

type folderEntry struct {
	Path   string                 `json:"path"`
	Keys   []string               `json:"keys,omitempty"`
	SHA256 map[string]string      `json:"sha256,omitempty"`
	Data   map[string]interface{} `json:"data,omitempty"`
	Error  string                 `json:"error,omitempty"`
}

type folderResult struct {
	Mount   string        `json:"mount"`
	Path    string        `json:"path"`
	Count   int           `json:"count"`
	Secrets []folderEntry `json:"secrets"`
}

// ReadFolder creates a bulk-read tool that collapses an entire KV folder into one MCP response.
func ReadFolder(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_folder",
			mcp.WithDescription("Read ALL secrets under a KV mount path in one call. "+
				"Defaults to key names + SHA-256 of each value (safe, no plaintext exposure). "+
				"Set include_values=true to return actual secret values."),
			mcp.WithToolAnnotation(mcp.ToolAnnotation{ReadOnlyHint: utils.ToBoolPtr(true)}),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The mount path of the secret engine (e.g. 'secrets')."),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("Folder path within the mount (e.g. 'application/prod'). Use '' for the root of the mount."),
			),
			mcp.WithBoolean("include_values",
				mcp.DefaultBool(false),
				mcp.Description("Return actual secret values; default false returns key names + SHA-256 fingerprints only."),
			),
			mcp.WithString("filter_keys",
				mcp.DefaultString(""),
				mcp.Description("Comma-separated list of key names to include from each secret; empty means all keys."),
			),
			mcp.WithBoolean("recursive",
				mcp.DefaultBool(false),
				mcp.Description("Recursively read sub-folders; default false reads only the immediate folder."),
			),
			mcp.WithNumber("max_concurrency",
				mcp.DefaultNumber(10),
				mcp.Description("Maximum number of concurrent secret reads (1–50); default 10."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readFolderHandler(ctx, req, logger)
		},
	}
}

func readFolderHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_folder request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	folderPath, _ := args["path"].(string)
	folderPath = strings.Trim(folderPath, "/")

	includeValues, _ := args["include_values"].(bool)
	recursive, _ := args["recursive"].(bool)

	var filterKeys []string
	if fk, _ := args["filter_keys"].(string); fk != "" {
		for _, k := range strings.Split(fk, ",") {
			if k = strings.TrimSpace(k); k != "" {
				filterKeys = append(filterKeys, k)
			}
		}
	}

	maxConcurrency := 10
	if mc, ok := args["max_concurrency"].(float64); ok && mc >= 1 {
		maxConcurrency = int(mc)
		if maxConcurrency > 50 {
			maxConcurrency = 50
		}
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	leafPaths, err := collectLeafPaths(ctx, vault, mount, folderPath, recursive)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list folder: %v", err)), nil
	}

	if len(leafPaths) == 0 {
		out, _ := json.Marshal(folderResult{Mount: mount, Path: folderPath, Count: 0, Secrets: []folderEntry{}})
		return mcp.NewToolResultText(string(out)), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  folderPath,
		"count": len(leafPaths),
	}).Debug("Reading secrets from folder")

	entries := make([]folderEntry, len(leafPaths))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, lp := range leafPaths {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, secretPath string) {
			defer wg.Done()
			defer func() { <-sem }()

			entry := folderEntry{Path: secretPath}
			kvSecret, readErr := vault.KVv2(mount).Get(ctx, secretPath)
			if readErr != nil {
				entry.Error = readErr.Error()
			} else if kvSecret == nil || kvSecret.Data == nil {
				entry.Error = "secret not found"
			} else {
				data := kvSecret.Data
				if len(filterKeys) > 0 {
					data = applyKeyFilter(data, filterKeys)
				}
				if includeValues {
					entry.Data = data
				} else {
					entry.Keys = sortedMapKeys(data)
					entry.SHA256 = computeValueSHA256(data)
				}
			}

			mu.Lock()
			entries[idx] = entry
			mu.Unlock()
		}(i, lp)
	}
	wg.Wait()

	result := folderResult{
		Mount:   mount,
		Path:    folderPath,
		Count:   len(entries),
		Secrets: entries,
	}
	out, err := json.Marshal(result)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling result: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  folderPath,
		"count": len(entries),
	}).Debug("Successfully read folder")

	return mcp.NewToolResultText(string(out)), nil
}

// collectLeafPaths lists all non-directory secret paths under basePath in the KV v2 mount.
// Directories (keys ending in "/") are recursed when recursive=true.
func collectLeafPaths(ctx context.Context, vault *vaultapi.Client, mount, basePath string, recursive bool) ([]string, error) {
	listPath := mount + "/metadata"
	if basePath != "" {
		listPath += "/" + basePath
	} else {
		listPath += "/"
	}

	secret, err := vault.Logical().ListWithContext(ctx, listPath)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}

	rawKeys, _ := secret.Data["keys"]
	var keys []string
	switch v := rawKeys.(type) {
	case []interface{}:
		for _, k := range v {
			if s, ok := k.(string); ok {
				keys = append(keys, s)
			}
		}
	case []string:
		keys = v
	}

	var leaves []string
	for _, key := range keys {
		if strings.HasSuffix(key, "/") {
			if !recursive {
				continue
			}
			sub := strings.TrimSuffix(key, "/")
			subPath := sub
			if basePath != "" {
				subPath = basePath + "/" + sub
			}
			subs, err := collectLeafPaths(ctx, vault, mount, subPath, recursive)
			if err != nil {
				return nil, err
			}
			leaves = append(leaves, subs...)
		} else {
			leafPath := key
			if basePath != "" {
				leafPath = basePath + "/" + key
			}
			leaves = append(leaves, leafPath)
		}
	}
	return leaves, nil
}

func applyKeyFilter(data map[string]interface{}, filterKeys []string) map[string]interface{} {
	keep := make(map[string]bool, len(filterKeys))
	for _, k := range filterKeys {
		keep[k] = true
	}
	out := make(map[string]interface{}, len(filterKeys))
	for k, v := range data {
		if keep[k] {
			out[k] = v
		}
	}
	return out
}

func sortedMapKeys(data map[string]interface{}) []string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// computeValueSHA256 returns a map of key → hex(sha256(value)) for each entry.
// String values are hashed as raw bytes; other types are JSON-serialized first.
func computeValueSHA256(data map[string]interface{}) map[string]string {
	out := make(map[string]string, len(data))
	for k, v := range data {
		var b []byte
		if s, ok := v.(string); ok {
			b = []byte(s)
		} else {
			b, _ = json.Marshal(v)
		}
		sum := sha256.Sum256(b)
		out[k] = hex.EncodeToString(sum[:])
	}
	return out
}
