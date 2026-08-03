// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	envCACertFilePrimary = "ENTERPRISE_IO_CACERT_FILE"
	envCACertURLPrimary  = "ENTERPRISE_IO_CACERT_URL"

	// Backward-compatibility with older compose files.
	envCACertFileCompat = "VIASAT_IO_CACERT_FILE"
	envCACertURLCompat  = "VIASAT_IO_CACERT_URL"
)

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func main() {
	fileDefault := firstNonEmptyEnv(envCACertFilePrimary, envCACertFileCompat)
	urlDefault := firstNonEmptyEnv(envCACertURLPrimary, envCACertURLCompat)

	file := flag.String("file", fileDefault, "Destination file path for the private CA bundle PEM")
	url := flag.String("url", urlDefault, "Source URL to fetch the private CA bundle PEM from when the file is missing")
	timeout := flag.Duration("timeout", 30*time.Second, "HTTP timeout (e.g. 30s)")
	force := flag.Bool("force", false, "Force re-fetch even if the destination file already exists")
	flag.Parse()

	if strings.TrimSpace(*file) == "" {
		_, _ = fmt.Fprintf(
			os.Stderr,
			"error: %s (or %s) or --file is required\n",
			envCACertFilePrimary,
			envCACertFileCompat,
		)
		os.Exit(2)
	}

	if !*force {
		if info, err := os.Stat(*file); err == nil && !info.IsDir() && info.Size() > 0 {
			_, _ = fmt.Fprintf(os.Stdout, "private ca root ready: %s (%d bytes)\n", *file, info.Size())
			return
		}
	}

	if strings.TrimSpace(*url) == "" {
		_, _ = fmt.Fprintf(
			os.Stderr,
			"error: %s (or %s) or --url is required when the CA file is missing\n",
			envCACertURLPrimary,
			envCACertURLCompat,
		)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: build request: %v\n", err)
		os.Exit(1)
	}

	httpClient := &http.Client{Timeout: *timeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: fetch CA bundle: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintf(os.Stderr, "error: fetch CA bundle: unexpected status %s\n", resp.Status)
		os.Exit(1)
	}

	pemBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: read CA bundle: %v\n", err)
		os.Exit(1)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
		_, _ = fmt.Fprintf(os.Stderr, "error: CA bundle did not contain PEM certificates (%s)\n", *url)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(*file), 0o755); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: create directory: %v\n", err)
		os.Exit(1)
	}

	// Write atomically via a temp file + rename.
	tmp, err := os.CreateTemp(filepath.Dir(*file), "private-ca-*.pem")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: create temp file: %v\n", err)
		os.Exit(1)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(pemBytes); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: write CA bundle: %v\n", err)
		os.Exit(1)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: chmod CA bundle: %v\n", err)
		os.Exit(1)
	}
	if err := tmp.Close(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: close temp file: %v\n", err)
		os.Exit(1)
	}
	if err := os.Rename(tmpPath, *file); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: install CA bundle: %v\n", err)
		os.Exit(1)
	}
	cleanup = false

	if info, err := os.Stat(*file); err == nil && !info.IsDir() {
		_, _ = fmt.Fprintf(os.Stdout, "private ca root fetched: %s (%d bytes)\n", *file, info.Size())
		return
	}

	_, _ = fmt.Fprintf(os.Stdout, "private ca root fetched: %s\n", *file)
}
