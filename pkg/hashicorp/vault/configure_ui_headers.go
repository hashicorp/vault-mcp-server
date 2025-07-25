// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// ConfigureUIHeaders creates a tool for configuring custom UI headers in Vault
func ConfigureUIHeaders(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("configure_ui_headers",
			mcp.WithDescription("Configure custom UI headers in Vault for environment identification. These headers help identify which Vault environment (dev, staging, prod) is being accessed through the UI."),
			mcp.WithString("headers", mcp.Required(), mcp.Description("JSON object or key=value pairs (comma-separated) of headers to set. Example: '{\"X-Environment\":\"Production\",\"X-Cluster\":\"us-east-1\"}' or 'X-Environment=Production,X-Cluster=us-east-1'")),
			mcp.WithString("operation", mcp.DefaultString("update"), mcp.Description("Operation to perform: 'update' (merge with existing), 'replace' (replace all), or 'delete' (remove specific headers)")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return configureUIHeadersHandler(ctx, req, logger)
		},
	}
}

func configureUIHeadersHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling configure_ui_headers request")

	// Extract parameters
	var headers, operation string

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if headers, ok = args["headers"].(string); !ok || headers == "" {
				return mcp.NewToolResultError("Missing or invalid 'headers' parameter"), nil
			}
			operation, _ = args["operation"].(string)
		} else {
			return mcp.NewToolResultError("Invalid arguments format"), nil
		}
	} else {
		return mcp.NewToolResultError("Missing arguments"), nil
	}

	// Default operation to update if not specified
	if operation == "" {
		operation = "update"
	}

	// Validate operation
	if operation != "update" && operation != "replace" && operation != "delete" {
		return mcp.NewToolResultError("Invalid operation. Must be 'update', 'replace', or 'delete'"), nil
	}

	logger.WithFields(log.Fields{
		"headers":   headers,
		"operation": operation,
	}).Debug("Configuring UI headers")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Parse headers input
	headerMap, err := parseHeaders(headers)
	if err != nil {
		logger.WithError(err).Error("Failed to parse headers")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to parse headers: %v", err)), nil
	}

	switch operation {
	case "update":
		// Get existing headers first, then merge
		existing, err := getExistingUIHeaders(ctx, client, logger)
		if err != nil {
			logger.WithError(err).Warn("Failed to get existing headers, proceeding with new headers only")
			existing = make(map[string]string)
		}

		// Merge existing with new headers
		for k, v := range headerMap {
			existing[k] = v
		}
		headerMap = existing

	case "replace":
		// Clear all existing headers first, then set new ones
		existing, err := getExistingUIHeaders(ctx, client, logger)
		if err != nil {
			logger.WithError(err).Warn("Failed to get existing headers for replacement")
		} else {
			// Delete existing headers
			for headerName := range existing {
				if _, isNewHeader := headerMap[headerName]; !isNewHeader {
					path := fmt.Sprintf("sys/config/ui/headers/%s", headerName)
					_, err := client.Logical().Delete(path)
					if err != nil {
						logger.WithError(err).Warnf("Failed to delete existing header %s", headerName)
					}
				}
			}
		}

	case "delete":
		// Delete specified headers
		for headerName := range headerMap {
			path := fmt.Sprintf("sys/config/ui/headers/%s", headerName)
			_, err := client.Logical().Delete(path)
			if err != nil {
				logger.WithError(err).Errorf("Failed to delete header %s", headerName)
				return mcp.NewToolResultError(fmt.Sprintf("Failed to delete header %s: %v", headerName, err)), nil
			}
		}

		successMsg := fmt.Sprintf("Successfully deleted %d UI headers.", len(headerMap))
		logger.WithFields(log.Fields{
			"operation":    operation,
			"header_count": len(headerMap),
			"header_names": getHeaderNamesFromMap(headerMap),
		}).Info("UI headers deleted successfully")

		return mcp.NewToolResultText(successMsg), nil
	}

	// Configure each header individually using POST method
	for headerName, headerValue := range headerMap {
		path := fmt.Sprintf("sys/config/ui/headers/%s", headerName)
		configData := map[string]interface{}{
			"values": []string{headerValue},
		}

		_, err = client.Logical().Write(path, configData)
		if err != nil {
			logger.WithError(err).Errorf("Failed to configure UI header %s", headerName)
			return mcp.NewToolResultError(fmt.Sprintf("Failed to configure UI header %s: %v", headerName, err)), nil
		}

		logger.WithFields(log.Fields{
			"header_name":  headerName,
			"header_value": headerValue,
		}).Debug("UI header configured successfully")
	}

	successMsg := fmt.Sprintf("Successfully %sd UI headers. %d headers configured.", operation, len(headerMap))
	logger.WithFields(log.Fields{
		"operation":    operation,
		"header_count": len(headerMap),
		"header_names": getHeaderNamesFromMap(headerMap),
	}).Info("UI headers configured successfully")

	return mcp.NewToolResultText(successMsg), nil
}

// parseHeaders parses the headers input which can be JSON or key=value pairs
func parseHeaders(input string) (map[string]string, error) {
	headers := make(map[string]string)

	// Trim whitespace
	input = strings.TrimSpace(input)

	// Try to parse as JSON first
	if strings.HasPrefix(input, "{") && strings.HasSuffix(input, "}") {
		// JSON format - we'll parse it manually to avoid importing json
		// Remove outer braces
		jsonContent := strings.TrimSpace(input[1 : len(input)-1])
		if jsonContent == "" {
			return headers, nil // Empty object
		}

		// Split by comma, but be careful about quoted values
		pairs := parseJSONPairs(jsonContent)
		for _, pair := range pairs {
			key, value, err := parseJSONPair(pair)
			if err != nil {
				return nil, fmt.Errorf("invalid JSON pair '%s': %v", pair, err)
			}
			headers[key] = value
		}
	} else {
		// Key=value format
		pairs := strings.Split(input, ",")
		for _, pair := range pairs {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}

			parts := strings.SplitN(pair, "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid key=value pair: %s", pair)
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			if key == "" {
				return nil, fmt.Errorf("empty key in pair: %s", pair)
			}

			headers[key] = value
		}
	}

	return headers, nil
}

// parseJSONPairs splits JSON content by commas, respecting quoted strings
func parseJSONPairs(content string) []string {
	var pairs []string
	var current strings.Builder
	inQuotes := false
	escapeNext := false

	for _, char := range content {
		if escapeNext {
			current.WriteRune(char)
			escapeNext = false
			continue
		}

		if char == '\\' {
			escapeNext = true
			current.WriteRune(char)
			continue
		}

		if char == '"' {
			inQuotes = !inQuotes
			current.WriteRune(char)
			continue
		}

		if char == ',' && !inQuotes {
			pairs = append(pairs, strings.TrimSpace(current.String()))
			current.Reset()
			continue
		}

		current.WriteRune(char)
	}

	if current.Len() > 0 {
		pairs = append(pairs, strings.TrimSpace(current.String()))
	}

	return pairs
}

// parseJSONPair parses a single JSON key:value pair
func parseJSONPair(pair string) (string, string, error) {
	colonIndex := strings.Index(pair, ":")
	if colonIndex == -1 {
		return "", "", fmt.Errorf("missing colon")
	}

	keyPart := strings.TrimSpace(pair[:colonIndex])
	valuePart := strings.TrimSpace(pair[colonIndex+1:])

	// Remove quotes from key
	if len(keyPart) >= 2 && keyPart[0] == '"' && keyPart[len(keyPart)-1] == '"' {
		keyPart = keyPart[1 : len(keyPart)-1]
	} else {
		return "", "", fmt.Errorf("key must be quoted")
	}

	// Remove quotes from value if present
	if len(valuePart) >= 2 && valuePart[0] == '"' && valuePart[len(valuePart)-1] == '"' {
		valuePart = valuePart[1 : len(valuePart)-1]
	}

	return keyPart, valuePart, nil
}

// getExistingUIHeaders retrieves current UI headers configuration
func getExistingUIHeaders(ctx context.Context, client *api.Client, logger *log.Logger) (map[string]string, error) {
	// First, list all configured headers
	listPath := "sys/config/ui/headers"
	secret, err := client.Logical().List(listPath)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string)
	if secret == nil || secret.Data == nil {
		return headers, nil
	}

	// Get the list of header names
	var headerNames []string
	if keys, ok := secret.Data["keys"]; ok {
		if keyList, ok := keys.([]interface{}); ok {
			for _, key := range keyList {
				if headerName, ok := key.(string); ok {
					headerNames = append(headerNames, headerName)
				}
			}
		}
	}

	// Read each header individually
	for _, headerName := range headerNames {
		readPath := fmt.Sprintf("sys/config/ui/headers/%s", headerName)
		headerSecret, err := client.Logical().Read(readPath)
		if err != nil {
			logger.WithError(err).Warnf("Failed to read header %s", headerName)
			continue
		}

		if headerSecret != nil && headerSecret.Data != nil {
			// Try to get single value first
			if value, ok := headerSecret.Data["value"]; ok {
				if strVal, ok := value.(string); ok {
					headers[headerName] = strVal
				}
			} else if values, ok := headerSecret.Data["values"]; ok {
				// Handle multiple values - use the first one
				if valueList, ok := values.([]interface{}); ok && len(valueList) > 0 {
					if strVal, ok := valueList[0].(string); ok {
						headers[headerName] = strVal
					}
				}
			}
		}
	}

	return headers, nil
}

// getHeaderNamesFromMap returns a slice of header names for logging
func getHeaderNamesFromMap(headerMap map[string]string) []string {
	names := make([]string, 0, len(headerMap))
	for name := range headerMap {
		names = append(names, name)
	}
	return names
}
