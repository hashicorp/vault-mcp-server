// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/hashicorp/vault"
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

	httpCmd = &cobra.Command{
		Use:   "http",
		Short: "Start StreamableHTTP server",
		Long:  fmt.Sprintf("Start a server that communicates via StreamableHTTP transport on port %s at %s endpoint.", DefaultBindPort, DefaultEndPointPath),
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

			if err := runHTTPServer(logger, host, port); err != nil {
				stdlog.Fatal("failed to run streamableHTTP server:", err)
			}
		},
	}
)

func runHTTPServer(logger *log.Logger, host string, port string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hcServer := NewServer(version.Version, logger)
	vault.InitTools(hcServer, logger)

	return httpServerInit(ctx, hcServer, logger, host, port)
}

func httpServerInit(ctx context.Context, hcServer *server.MCPServer, logger *log.Logger, host string, port string) error {
	// Create StreamableHTTP server which implements the new streamable-http transport
	// This is the modern MCP transport that supports both direct HTTP responses and SSE streams
	streamableServer := server.NewStreamableHTTPServer(hcServer,
		server.WithEndpointPath(DefaultEndPointPath), // Default MCP endpoint path
		server.WithLogger(logger),
	)

	mux := http.NewServeMux()

	// Handle the /mcp endpoint with the StreamableHTTP server
	mux.Handle(DefaultEndPointPath, streamableServer)
	mux.Handle(DefaultEndPointPath+"/", streamableServer)

	// Add health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"status":"ok","service":"vault-mcp-server","transport":"streamable-http"}`))
		if err != nil {
			logger.WithError(err).Error("Error writing to response on /health")
		}
	})

	// Apply middleware stack
	handler := vault.CORSMiddleware()(mux)
	handler = vault.VaultContextMiddleware(logger)(handler)
	handler = vault.LoggingMiddleware(logger)(handler)

	addr := fmt.Sprintf("%s:%s", host, port)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Start server in goroutine
	errC := make(chan error, 1)
	go func() {
		logger.Infof("Starting StreamableHTTP server on %s%s", addr, DefaultEndPointPath)
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
	vault.InitTools(hcServer, logger)

	return serverInit(ctx, hcServer, logger)
}

func NewServer(version string, logger *log.Logger, opts ...server.ServerOption) *server.MCPServer {
	// Add default options
	defaultOpts := []server.ServerOption{
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
	}
	opts = append(defaultOpts, opts...)

	// Create hooks for session management
	hooks := &server.Hooks{}
	hooks.AddOnRegisterSession(func(ctx context.Context, session server.ClientSession) {
		vault.NewSessionHandler(ctx, session, logger)
	})
	hooks.AddOnUnregisterSession(func(ctx context.Context, session server.ClientSession) {
		vault.EndSessionHandler(ctx, session, logger)
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

		logFile, _ := rootCmd.PersistentFlags().GetString("log-file")
		logger, err := initLogger(logFile)
		if err != nil {
			stdlog.Fatal("Failed to initialize logger:", err)
		}

		if err := runHTTPServer(logger, host, port); err != nil {
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
	return os.Getenv("TRANSPORT_MODE") == "http" || os.Getenv("TRANSPORT_PORT") != ""
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
