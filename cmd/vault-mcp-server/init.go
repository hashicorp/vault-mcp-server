// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"io"
	stdlog "log"
	"os"

	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.SetVersionTemplate("{{.Short}}\n{{.Version}}\n")
	rootCmd.PersistentFlags().String("log-file", "", "Path to log file")

	// Add StreamableHTTP command flags (avoid 'h' shorthand conflict with help)
	streamableHTTPCmd.Flags().String("transport-host", DefaultBindAddress, "Host to bind to")
	streamableHTTPCmd.Flags().StringP("transport-port", "p", DefaultBindPort, "Port to listen on")
	streamableHTTPCmd.Flags().String("mcp-endpoint", DefaultEndPointPath, "Path for streamable HTTP endpoint")

	// Add the same flags to the alias command for backward compatibility
	httpCmdAlias.Flags().String("transport-host", DefaultBindAddress, "Host to bind to")
	httpCmdAlias.Flags().StringP("transport-port", "p", DefaultBindPort, "Port to listen on")
	httpCmdAlias.Flags().String("mcp-endpoint", DefaultEndPointPath, "Path for streamable HTTP endpoint")

	rootCmd.AddCommand(stdioCmd)
	rootCmd.AddCommand(streamableHTTPCmd)
	rootCmd.AddCommand(httpCmdAlias) // Add the alias for backward compatibility
}

func initConfig() {
	viper.AutomaticEnv()
}

func initLogger(outPath string) (*log.Logger, error) {
	logger := log.New()
	logger.SetLevel(log.DebugLevel)

	if outPath == "" {
		return logger, nil
	}

	file, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger.SetOutput(file)
	return logger, nil
}

func serverInit(ctx context.Context, hcServer *server.MCPServer, logger *log.Logger) error {
	stdioServer := server.NewStdioServer(hcServer)
	stdLogger := stdlog.New(logger.Writer(), "stdioserver", 0)
	stdioServer.SetErrorLogger(stdLogger)

	// Start listening for messages
	errC := make(chan error, 1)
	go func() {
		in, out := io.Reader(os.Stdin), io.Writer(os.Stdout)
		errC <- stdioServer.Listen(ctx, in, out)
	}()

	_, _ = fmt.Fprintf(os.Stderr, "Vault MCP Server running on stdio\n")

	// Wait for shutdown signal
	select {
	case <-ctx.Done():
		logger.Infof("shutting down server...")
	case err := <-errC:
		if err != nil {
			return fmt.Errorf("error running server: %w", err)
		}
	}

	return nil
}
