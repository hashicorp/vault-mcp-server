// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"fmt"
	"os/exec"
	"runtime"

	log "github.com/sirupsen/logrus"
)

// OpenBrowser attempts to open the default system browser with the given URL
// Returns error if the browser could not be launched
func OpenBrowser(url string, logger *log.Logger) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin": // macOS
		cmd = exec.Command("open", url)
	case "linux":
		// Try xdg-open first, fallback to other common browsers
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	logger.WithFields(log.Fields{
		"os":  runtime.GOOS,
		"url": url,
	}).Debug("Attempting to open browser")

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to open browser: %w", err)
	}

	logger.Info("Browser opened successfully")
	return nil
}

// OpenBrowserWithFallback attempts to open the browser, and prints the URL if it fails
func OpenBrowserWithFallback(url string, logger *log.Logger) {
	err := OpenBrowser(url, logger)
	if err != nil {
		logger.WithError(err).Warn("Could not automatically open browser")
		logger.Infof("\nPlease open this URL in your browser:\n\n%s\n", url)
	} else {
		logger.Infof("\nOpening browser to: %s", url)
		logger.Info("If the browser doesn't open automatically, please open the URL manually")
	}
}
