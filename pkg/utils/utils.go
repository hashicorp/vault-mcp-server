package utils

import (
	"fmt"
	"net/url"
	"strings"
)

func ExtractMountPath(args map[string]any) (string, error) {
	mount, ok := args["mount"].(string)
	if !ok || mount == "" || mount == "/" {
		return "", fmt.Errorf("missing or invalid 'mount' parameter")
	}

	// Remove trailing slash if present
	mount = strings.TrimSuffix(mount, "/")

	return mount, nil
}

func ToBoolPtr(b bool) *bool {
	return &b
}

// SanitizeOrigin returns the scheme, hostname, and port from an origin string, or the original string if invalid
func SanitizeOrigin(origin string) string {
	parsedURL, err := url.Parse(origin)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return origin
	}
	host := parsedURL.Host
	// If host does not contain port, but parsedURL.Port() is set, append it
	if parsedURL.Port() == "" && strings.Contains(host, ":") {
		// host already contains port
	} else if parsedURL.Port() != "" && !strings.Contains(host, ":") {
		host = fmt.Sprintf("%s:%s", parsedURL.Hostname(), parsedURL.Port())
	}
	return fmt.Sprintf("%s://%s", parsedURL.Scheme, host)
}
