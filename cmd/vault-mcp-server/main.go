// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/oauth"
	"github.com/hashicorp/vault-mcp-server/pkg/tools"

	"github.com/hashicorp/vault-mcp-server/version"

	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	DefaultBindAddress  = "127.0.0.1"
	DefaultBindPort     = "8080"
	DefaultEndPointPath = "/mcp"
)

var (
	rootCmd = &cobra.Command{
		Use:     "vault-mcp-server",
		Short:   "Vault MCP Server",
		Long:    `A Vault MCP server that handles various tools and resources for HashiCorp Vault.`,
		Version: fmt.Sprintf("Version: %s\nCommit: %s\nBuild Date: %s", version.GetHumanVersion(), version.GitCommit, version.BuildDate),
		Run:     runDefaultCommand,
	}

	stdioCmd = &cobra.Command{
		Use:   "stdio",
		Short: "Start stdio server",
		Long:  `Start a server that communicates via standard input/output streams using JSON-RPC messages.`,
		Run: func(_ *cobra.Command, _ []string) {
			logFile, err := rootCmd.PersistentFlags().GetString("log-file")
			if err != nil {
				stdlog.Fatal("Failed to get log file:", err)
			}
			logger, err := initLogger(logFile)
			if err != nil {
				stdlog.Fatal("Failed to initialize logger:", err)
			}

			if err := runStdioServer(logger); err != nil {
				stdlog.Fatal("failed to run stdio server:", err)
			}
		},
	}

	streamableHTTPCmd = &cobra.Command{
		Use:   "streamable-http",
		Short: "Start StreamableHTTP server",
		Long: `Start a server that communicates using the StreamableHTTP transport.
This mode allows clients to interact with the Vault MCP server over HTTP.
You can specify the host, port, and endpoint path to customize where the server listens.`,
		Run: func(cmd *cobra.Command, _ []string) {
			logFile, err := rootCmd.PersistentFlags().GetString("log-file")
			if err != nil {
				stdlog.Fatal("Failed to get log file:", err)
			}
			logger, err := initLogger(logFile)
			if err != nil {
				stdlog.Fatal("Failed to initialize logger:", err)
			}

			port, err := cmd.Flags().GetString("transport-port")
			if err != nil {
				stdlog.Fatal("Failed to get streamableHTTP port:", err)
			}
			host, err := cmd.Flags().GetString("transport-host")
			if err != nil {
				stdlog.Fatal("Failed to get streamableHTTP host:", err)
			}

			endpointPath, err := cmd.Flags().GetString("mcp-endpoint")
			if err != nil {
				stdlog.Fatal("Failed to get endpoint path:", err)
			}

			if err := runHTTPServer(logger, host, port, endpointPath); err != nil {
				stdlog.Fatal("failed to run streamableHTTP server:", err)
			}
		},
	}

	// Create an alias for backward compatibility
	httpCmdAlias = &cobra.Command{
		Use:        "http",
		Short:      "Start StreamableHTTP server (deprecated, use 'streamable-http' instead)",
		Long:       `This command is deprecated. Please use 'streamable-http' instead.`,
		Deprecated: "Use 'streamable-http' instead",
		Run: func(cmd *cobra.Command, args []string) {
			// Forward to the new command
			streamableHTTPCmd.Run(cmd, args)
		},
	}
)

func runHTTPServer(logger *log.Logger, host string, port string, endpointPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hcServer := NewServer(version.Version, logger)
	tools.InitTools(hcServer, logger)

	return httpServerInit(ctx, hcServer, logger, host, port, endpointPath)
}

func httpServerInit(ctx context.Context, hcServer *server.MCPServer, logger *log.Logger, host string, port string, endpointPath string) error {
	// Ensure endpoint path starts with /
	endpointPath = path.Join("/", endpointPath)
	// Create StreamableHTTP server which implements the new streamable-http transport
	// This is the modern MCP transport that supports both direct HTTP responses and SSE streams
	opts := []server.StreamableHTTPOption{
		server.WithEndpointPath(endpointPath),
		server.WithLogger(logger),
	}

	// Load TLS configuration
	tlsConfig, err := client.GetTLSConfigFromEnv()
	if err != nil {
		return fmt.Errorf("TLS configuration error: %w", err)
	}
	if tlsConfig != nil {
		opts = append(opts, server.WithTLSCert(tlsConfig.CertFile, tlsConfig.KeyFile))
	}

	baseStreamableServer := server.NewStreamableHTTPServer(hcServer, opts...)

	// Load CORS configuration
	corsConfig := client.LoadCORSConfigFromEnv()

	var streamableServer http.Handler = baseStreamableServer

	mux := http.NewServeMux()

	// StreamableHTTP supports browser-based OAuth (OIDC / LDAP / userpass) to obtain
	// an upstream Vault token. MCP_AUTH_SECRET is optional: when unset, a random
	// secret is generated at startup and logged at INFO level.
	var bearer func(http.Handler) http.Handler
	oauthCfg := oauth.LoadConfigFromEnv()
	if !oauthCfg.Enabled() {
		secret, err := generateMCPAuthSecret()
		if err != nil {
			return fmt.Errorf("generate MCP_AUTH_SECRET: %w", err)
		}
		oauthCfg.MCPAuthSecret = secret
		logger.WithFields(log.Fields{
			"mcp_auth_secret": secret,
			"hint":            "set MCP_AUTH_SECRET to persist bearer tokens across restarts",
		}).Info("generated MCP_AUTH_SECRET")
	}

	// Require the configured private CA bundle to be present on disk before booting.
	// Bootstrap (download) should be performed out-of-process (e.g. docker-compose-viasat.yaml's
	// certs-puller or scripts/fetch-secrets).
	if err := requireConfiguredCACert(logger); err != nil {
		return err
	}

	if err := oauthCfg.Validate(); err != nil {
		return fmt.Errorf("OAuth configuration error: %w", err)
	}
	oauthRouter, err := oauth.NewRouter(oauthCfg, logger)
	if err != nil {
		return fmt.Errorf("OAuth init error: %w", err)
	}
	oauthRouter.Register(mux)
	bearer = oauthRouter.BearerMiddleware

	if oauthCfg.OIDCCallbackPort > 0 {
		callbackServer := &http.Server{
			Addr:              fmt.Sprintf(":%d", oauthCfg.OIDCCallbackPort),
			Handler:           oauthRouter.OIDCCallbackMux(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
		}
		go func() {
			if err := callbackServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.WithError(err).Warn("OIDC callback server error")
			}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = callbackServer.Shutdown(shutdownCtx)
		}()
	}

	// Apply middleware (innermost first).
	// - bearer: validates OAuth bearer tokens (or allows VAULT_TOKEN from env/header)
	// - VaultContext: picks up Vault settings from request/env (bearer wins when present)
	// - security handler: enforces CORS and handles OPTIONS preflight
	// - logging: outermost request logging
	streamableServer = bearer(streamableServer)
	streamableServer = client.VaultContextMiddleware(logger)(streamableServer)
	streamableServer = client.NewSecurityHandler(streamableServer, corsConfig.AllowedOrigins, corsConfig.Mode, logger)
	streamableServer = client.LoggingMiddleware(logger)(streamableServer)

	// Handle the /mcp endpoint with the streamable server (with security wrapper)
	mux.Handle(endpointPath, streamableServer)
	mux.Handle(endpointPath+"/", streamableServer)

	// Add health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := fmt.Sprintf(`{"status":"ok","service":"vault-mcp-server","transport":"streamable-http","endpoint":"%s"}`, endpointPath)
		if _, err := w.Write([]byte(response)); err != nil {
			logger.WithError(err).Error("Failed to write health check response")
		}
	})

	addr := fmt.Sprintf("%s:%s", host, port)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Minute, // Set to 60 minutes to support long-lived connections
	}

	if tlsConfig != nil {
		httpServer.TLSConfig = tlsConfig.Config
	} else if !client.IsLocalHost(host) {
		return fmt.Errorf("TLS is required for non-localhost binding (%s). Set MCP_TLS_CERT_FILE and MCP_TLS_KEY_FILE environment variables", host)
	}

	// ── Bootstrap summary ────────────────────────────────────────────────────
	// Print a single structured block before starting, mirroring the pattern
	// used by the other Viasat MCP tools (delinea, blackduck, tenable, etc.).
	{
		vaultAddr := oauthCfg.VaultAddr
		if vaultAddr == "" {
			vaultAddr = client.DefaultVaultAddress
		}

		tlsMode := "disabled (not recommended for production)"
		if tlsConfig != nil {
			tlsMode = "enabled (" + tlsConfig.CertFile + ")"
		}

		corsOrigins := strings.Join(corsConfig.AllowedOrigins, ", ")
		if corsOrigins == "" {
			corsOrigins = "(none)"
		}

		logger.WithFields(log.Fields{
			"addr":      addr,
			"endpoint":  endpointPath,
			"tls":       tlsMode,
			"cors_mode": corsConfig.Mode,
		}).Info("http server starting")

		logger.WithFields(log.Fields{
			"vault_addr":      vaultAddr,
			"vault_namespace": oauthCfg.VaultNamespace,
			"cacert_file":     client.EffectiveCACertFile(),
		}).Info("vault connection")

		oidcCallback := oauthCfg.OIDCCallbackURL(fmt.Sprintf("http://%s", addr))
		logger.WithFields(log.Fields{
			"login_page":       fmt.Sprintf("http://%s/vault/login", addr),
			"login_methods":    "ldap, userpass, oidc",
			"ldap_mount":       oauthCfg.LDAPMount,
			"userpass_mount":   oauthCfg.UserpassMount,
			"oidc_mount":       oauthCfg.OIDCMount,
			"oidc_role":        oauthCfg.OIDCRole,
			"oidc_callback":    oidcCallback,
			"access_token_ttl": oauthCfg.AccessTokenTTL.String(),
		}).Info("oauth enabled")
	}
	// ── End bootstrap summary ─────────────────────────────────────────────────

	// Start server in goroutine
	errC := make(chan error, 1)
	go func() {
		errC <- httpServer.ListenAndServe()
	}()

	// Wait for shutdown signal
	select {
	case <-ctx.Done():
		logger.Infof("Shutting down StreamableHTTP server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errC:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("StreamableHTTP server error: %w", err)
		}
	}

	return nil
}

func runStdioServer(logger *log.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hcServer := NewServer(version.Version, logger)
	tools.InitTools(hcServer, logger)

	return serverInit(ctx, hcServer, logger)
}

func NewServer(version string, logger *log.Logger, opts ...server.ServerOption) *server.MCPServer {
	// Create rate limiting middleware with environment-based configuration
	rateLimitConfig := client.LoadRateLimitConfigFromEnv()
	rateLimitMiddleware := client.NewRateLimitMiddleware(rateLimitConfig, logger)

	// Add default options
	defaultOpts := []server.ServerOption{
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithToolHandlerMiddleware(rateLimitMiddleware.Middleware()),
	}
	opts = append(defaultOpts, opts...)

	// Create hooks for session management
	hooks := &server.Hooks{}
	hooks.AddOnRegisterSession(func(ctx context.Context, session server.ClientSession) {
		client.NewSessionHandler(ctx, session, logger)
	})
	hooks.AddOnUnregisterSession(func(ctx context.Context, session server.ClientSession) {
		client.EndSessionHandler(ctx, session, logger)
	})

	// Add hooks to options
	opts = append(opts, server.WithHooks(hooks))

	// Create a new MCP server
	s := server.NewMCPServer(
		"vault-mcp-server",
		version,
		opts...,
	)
	return s
}

// runDefaultCommand handles the default behavior when no subcommand is provided
func runDefaultCommand(cmd *cobra.Command, _ []string) {
	// Default to stdio mode when no subcommand is provided
	logFile, err := cmd.PersistentFlags().GetString("log-file")
	if err != nil {
		stdlog.Fatal("Failed to get log file:", err)
	}
	logger, err := initLogger(logFile)
	if err != nil {
		stdlog.Fatal("Failed to initialize logger:", err)
	}

	if err := runStdioServer(logger); err != nil {
		stdlog.Fatal("failed to run stdio server:", err)
	}
}

func main() {
	// Check environment variables first - they override command line args
	if shouldUseHTTPMode() {
		port := getHTTPPort()
		host := getHTTPHost()
		endpointPath := getEndpointPath(nil)

		logFile, _ := rootCmd.PersistentFlags().GetString("log-file")
		logger, err := initLogger(logFile)
		if err != nil {
			stdlog.Fatal("Failed to initialize logger:", err)
		}

		if err := runHTTPServer(logger, host, port, endpointPath); err != nil {
			stdlog.Fatal("failed to run HTTP server:", err)
		}
		return
	}

	// Fall back to normal CLI behavior
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// shouldUseHTTPMode checks if environment variables indicate HTTP mode
func shouldUseHTTPMode() bool {
	transportMode := os.Getenv("TRANSPORT_MODE")
	return transportMode == "http" || transportMode == "streamable-http" ||
		os.Getenv("TRANSPORT_PORT") != "" ||
		os.Getenv("TRANSPORT_HOST") != "" ||
		os.Getenv("MCP_ENDPOINT") != ""
}

// getHTTPPort returns the port from environment variables or default
func getHTTPPort() string {
	if port := os.Getenv("TRANSPORT_PORT"); port != "" {
		return port
	}
	return DefaultBindPort
}

// getHTTPHost returns the host from environment variables or default
func getHTTPHost() string {
	if host := os.Getenv("TRANSPORT_HOST"); host != "" {
		return host
	}
	return DefaultBindAddress
}

// Add function to get endpoint path from environment or flag
func getEndpointPath(cmd *cobra.Command) string {
	// First check environment variable
	if envPath := os.Getenv("MCP_ENDPOINT"); envPath != "" {
		return envPath
	}

	// Fall back to command line flag
	if cmd != nil {
		if path, err := cmd.Flags().GetString("mcp-endpoint"); err == nil && path != "" {
			return path
		}
	}

	return DefaultEndPointPath
}

func generateMCPAuthSecret() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key), nil
}

func requireConfiguredCACert(logger *log.Logger) error {
	candidates := make([]string, 0, 2)
	for _, key := range []string{client.VaultCACert, client.VIASATIOCACertFile} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			candidates = append(candidates, v)
		}
	}

	// No explicit CA bundle configured; rely on the system trust store.
	if len(candidates) == 0 {
		return nil
	}

	for _, p := range candidates {
		info, err := os.Stat(p)
		if err == nil && !info.IsDir() && info.Size() > 0 {
			if logger != nil {
				logger.WithFields(log.Fields{
					"path":       p,
					"size_bytes": info.Size(),
				}).Info("private ca root ready")
			}
			return nil
		}
	}

	return fmt.Errorf("private ca root missing: expected one of %v to exist; bootstrap it (e.g. scripts/fetch-secrets) or mount it into the container", candidates)
}
