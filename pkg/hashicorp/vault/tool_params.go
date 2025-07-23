package vault

import (
	"fmt"
	"strings"
)

func extractMountPath(args map[string]any) (string, error) {
	mount, ok := args["mount"].(string)
	if !ok || mount == "" || mount == "/" {
		return "", fmt.Errorf("missing or invalid 'mount' parameter")
	}

	// Remove trailing slash if present
	mount = strings.TrimSuffix(mount, "/")

	return mount, nil
}
