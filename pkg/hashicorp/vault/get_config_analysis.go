package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
)

// SanitizedConfig represents the sanitized Vault configuration
type SanitizedConfig struct {
	APIAddr                   string           `json:"api_addr"`
	ClusterAddr               string           `json:"cluster_addr"`
	ClusterName               string           `json:"cluster_name"`
	DefaultLeaseTTL           int              `json:"default_lease_ttl"`
	MaxLeaseTTL               int              `json:"max_lease_ttl"`
	DefaultMaxRequestDuration int              `json:"default_max_request_duration"`
	DisableCache              bool             `json:"disable_cache"`
	DisableClustering         bool             `json:"disable_clustering"`
	DisableIndexing           bool             `json:"disable_indexing"`
	DisableMlock              bool             `json:"disable_mlock"`
	DisablePerformanceStandby bool             `json:"disable_performance_standby"`
	DisablePrintableCheck     bool             `json:"disable_printable_check"`
	DisableSealwrap           bool             `json:"disable_sealwrap"`
	EnableUI                  bool             `json:"enable_ui"`
	LogFormat                 string           `json:"log_format"`
	LogLevel                  string           `json:"log_level"`
	PIDFile                   string           `json:"pid_file"`
	PluginDirectory           string           `json:"plugin_directory"`
	RawStorageEndpoint        bool             `json:"raw_storage_endpoint"`
	CacheSize                 int              `json:"cache_size"`
	ClusterCipherSuites       string           `json:"cluster_cipher_suites"`
	Listeners                 []ListenerConfig `json:"listeners"`
	Storage                   StorageConfig    `json:"storage"`
	Seals                     []SealConfig     `json:"seals"`

	// Metadata
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ListenerConfig represents listener configuration
type ListenerConfig struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

// StorageConfig represents storage configuration
type StorageConfig struct {
	Type              string `json:"type"`
	ClusterAddr       string `json:"cluster_addr"`
	DisableClustering bool   `json:"disable_clustering"`
	RedirectAddr      string `json:"redirect_addr"`
}

// SealConfig represents seal configuration
type SealConfig struct {
	Type     string `json:"type"`
	Disabled bool   `json:"disabled"`
}

// CORSConfig represents CORS configuration
type CORSConfig struct {
	Enabled        bool     `json:"enabled"`
	AllowedOrigins []string `json:"allowed_origins"`
	AllowedHeaders []string `json:"allowed_headers"`

	// Metadata
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// getSanitizedConfig retrieves the sanitized Vault configuration
func getSanitizedConfig(ctx context.Context, client *api.Client) (*SanitizedConfig, error) {
	secret, err := client.Logical().Read("sys/config/state/sanitized")
	if err != nil {
		return nil, fmt.Errorf("failed to read sanitized config: %w", err)
	}

	config := &SanitizedConfig{
		Timestamp: getCurrentTimestamp(),
		Source:    "vault_api",
		Metadata:  make(map[string]interface{}),
	}

	if secret != nil && secret.Data != nil {
		// Parse configuration fields
		if v, ok := secret.Data["api_addr"].(string); ok {
			config.APIAddr = v
		}
		if v, ok := secret.Data["cluster_addr"].(string); ok {
			config.ClusterAddr = v
		}
		if v, ok := secret.Data["cluster_name"].(string); ok {
			config.ClusterName = v
		}
		if v, ok := secret.Data["default_lease_ttl"].(int); ok {
			config.DefaultLeaseTTL = v
		}
		if v, ok := secret.Data["max_lease_ttl"].(int); ok {
			config.MaxLeaseTTL = v
		}
		if v, ok := secret.Data["enable_ui"].(bool); ok {
			config.EnableUI = v
		}
		if v, ok := secret.Data["disable_cache"].(bool); ok {
			config.DisableCache = v
		}
		if v, ok := secret.Data["disable_clustering"].(bool); ok {
			config.DisableClustering = v
		}
		if v, ok := secret.Data["disable_mlock"].(bool); ok {
			config.DisableMlock = v
		}
		if v, ok := secret.Data["plugin_directory"].(string); ok {
			config.PluginDirectory = v
		}
		if v, ok := secret.Data["raw_storage_endpoint"].(bool); ok {
			config.RawStorageEndpoint = v
		}

		// Parse listeners
		if listenersData, ok := secret.Data["listeners"].([]interface{}); ok {
			config.Listeners = make([]ListenerConfig, 0, len(listenersData))
			for _, listenerData := range listenersData {
				if listener, ok := listenerData.(map[string]interface{}); ok {
					listenerConfig := ListenerConfig{}
					if v, ok := listener["type"].(string); ok {
						listenerConfig.Type = v
					}
					if v, ok := listener["config"].(map[string]interface{}); ok {
						listenerConfig.Config = v
					}
					config.Listeners = append(config.Listeners, listenerConfig)
				}
			}
		}

		// Parse storage
		if storageData, ok := secret.Data["storage"].(map[string]interface{}); ok {
			if v, ok := storageData["type"].(string); ok {
				config.Storage.Type = v
			}
			if v, ok := storageData["cluster_addr"].(string); ok {
				config.Storage.ClusterAddr = v
			}
			if v, ok := storageData["redirect_addr"].(string); ok {
				config.Storage.RedirectAddr = v
			}
			if v, ok := storageData["disable_clustering"].(bool); ok {
				config.Storage.DisableClustering = v
			}
		}

		// Parse seals
		if sealsData, ok := secret.Data["seals"].([]interface{}); ok {
			config.Seals = make([]SealConfig, 0, len(sealsData))
			for _, sealData := range sealsData {
				if seal, ok := sealData.(map[string]interface{}); ok {
					sealConfig := SealConfig{}
					if v, ok := seal["type"].(string); ok {
						sealConfig.Type = v
					}
					if v, ok := seal["disabled"].(bool); ok {
						sealConfig.Disabled = v
					}
					config.Seals = append(config.Seals, sealConfig)
				}
			}
		}

		// Add security metadata
		config.Metadata["has_clustering"] = !config.DisableClustering
		config.Metadata["has_ui_enabled"] = config.EnableUI
		config.Metadata["has_mlock_disabled"] = config.DisableMlock
		config.Metadata["has_plugin_directory"] = config.PluginDirectory != ""
		config.Metadata["storage_type"] = config.Storage.Type
		config.Metadata["listener_count"] = len(config.Listeners)
		config.Metadata["seal_count"] = len(config.Seals)

		// Security assessments
		securityIssues := make([]string, 0)
		if config.DisableMlock {
			securityIssues = append(securityIssues, "Memory locking disabled")
		}
		if config.EnableUI {
			securityIssues = append(securityIssues, "Web UI enabled")
		}
		if config.RawStorageEndpoint {
			securityIssues = append(securityIssues, "Raw storage endpoint enabled")
		}

		if len(securityIssues) > 0 {
			config.Metadata["security_concerns"] = securityIssues
		}
	}

	return config, nil
}

// getCORSConfig retrieves CORS configuration
func getCORSConfig(ctx context.Context, client *api.Client) (*CORSConfig, error) {
	secret, err := client.Logical().Read("sys/config/cors")
	if err != nil {
		return nil, fmt.Errorf("failed to read CORS config: %w", err)
	}

	config := &CORSConfig{
		Timestamp: getCurrentTimestamp(),
		Source:    "vault_api",
		Metadata:  make(map[string]interface{}),
	}

	if secret != nil && secret.Data != nil {
		if v, ok := secret.Data["enabled"].(bool); ok {
			config.Enabled = v
		}
		if v, ok := secret.Data["allowed_origins"].([]interface{}); ok {
			config.AllowedOrigins = make([]string, 0, len(v))
			for _, origin := range v {
				if originStr, ok := origin.(string); ok {
					config.AllowedOrigins = append(config.AllowedOrigins, originStr)
				}
			}
		}
		if v, ok := secret.Data["allowed_headers"].([]interface{}); ok {
			config.AllowedHeaders = make([]string, 0, len(v))
			for _, header := range v {
				if headerStr, ok := header.(string); ok {
					config.AllowedHeaders = append(config.AllowedHeaders, headerStr)
				}
			}
		}

		// Add security metadata
		config.Metadata["cors_enabled"] = config.Enabled
		config.Metadata["has_wildcard_origins"] = false
		config.Metadata["origin_count"] = len(config.AllowedOrigins)
		config.Metadata["header_count"] = len(config.AllowedHeaders)

		for _, origin := range config.AllowedOrigins {
			if origin == "*" {
				config.Metadata["has_wildcard_origins"] = true
				break
			}
		}

		// Security assessment
		securityLevel := "secure"
		if config.Enabled {
			if config.Metadata["has_wildcard_origins"].(bool) {
				securityLevel = "permissive"
			} else if len(config.AllowedOrigins) > 10 {
				securityLevel = "moderate"
			}
		}
		config.Metadata["security_level"] = securityLevel
	} else {
		// CORS not configured
		config.Enabled = false
		config.Metadata["cors_enabled"] = false
		config.Metadata["security_level"] = "disabled"
	}

	return config, nil
}
