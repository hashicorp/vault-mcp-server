// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package e2e

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVaultMCPServerE2E(t *testing.T) {
	// This is a placeholder for end-to-end tests
	// In a real scenario, you would:
	// 1. Start a Vault server
	// 2. Start the MCP server
	// 3. Test the MCP tools against the running Vault instance
	// 4. Clean up resources

	t.Skip("E2E tests require a running Vault instance")
}

// buildDockerImage builds the Docker image required for the tests.
func buildDockerImage(t *testing.T) {
	t.Log("Building Docker image for e2e tests...")

	cmd := exec.Command("make", "VERSION=test-e2e", "docker-build")
	cmd.Dir = ".." // Run this in the context of the root, where the Makefile is located.
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected to build Docker image successfully, output: %s", string(output))
}

// cleanupAllTestContainers stops all containers created by this test
func cleanupAllTestContainers(t *testing.T) {
	t.Log("Cleaning up all test containers...")

	// Find all containers with our test image
	cmd := exec.Command("docker", "ps", "-q", "--filter", "ancestor=vault-mcp-server:test-e2e")
	output, err := cmd.Output()
	if err != nil {
		t.Logf("Warning: failed to list test containers: %v", err)
		return
	}

	containerIDs := string(output)
	if containerIDs == "" {
		t.Log("No test containers found to cleanup")
		return
	}

	// Stop all found containers
	stopCmd := exec.Command("docker", "stop")
	stopCmd.Stdin = strings.NewReader(containerIDs)
	if err := stopCmd.Run(); err != nil {
		t.Logf("Warning: failed to stop some test containers: %v", err)
	} else {
		t.Log("Successfully cleaned up all test containers")
	}
}
