// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// CallbackResult represents the result of an OAuth callback
type CallbackResult struct {
	Code  string
	State string
	Error string
}

// CallbackServer represents an ephemeral HTTP server for OAuth callbacks
type CallbackServer struct {
	server   *http.Server
	listener net.Listener
	logger   *log.Logger
	resultCh chan *CallbackResult
	once     sync.Once
}

// NewCallbackServer creates a new callback server
func NewCallbackServer(port int, logger *log.Logger) (*CallbackServer, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to start callback server: %w", err)
	}

	cs := &CallbackServer{
		listener: listener,
		logger:   logger,
		resultCh: make(chan *CallbackResult, 1),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", cs.handleCallback)
	mux.HandleFunc("/health", cs.handleHealth)

	cs.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	logger.WithField("port", port).Info("Callback server created")
	return cs, nil
}

// Start starts the callback server in a goroutine
func (cs *CallbackServer) Start() {
	go func() {
		cs.logger.WithField("addr", cs.listener.Addr().String()).Info("Callback server listening")
		if err := cs.server.Serve(cs.listener); err != nil && err != http.ErrServerClosed {
			cs.logger.WithError(err).Error("Callback server error")
		}
	}()
}

// WaitForCallback waits for the OAuth callback or timeout
func (cs *CallbackServer) WaitForCallback(timeout time.Duration) (*CallbackResult, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case result := <-cs.resultCh:
		if result.Error != "" {
			return nil, fmt.Errorf("OAuth error: %s", result.Error)
		}
		return result, nil
	case <-timer.C:
		return nil, fmt.Errorf("authentication timeout after %v", timeout)
	}
}

// Shutdown gracefully shuts down the callback server
func (cs *CallbackServer) Shutdown(ctx context.Context) error {
	cs.logger.Info("Shutting down callback server")
	return cs.server.Shutdown(ctx)
}

// handleCallback handles the OAuth callback request
func (cs *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	cs.logger.WithFields(log.Fields{
		"method":     r.Method,
		"remote_ip":  r.RemoteAddr,
		"user_agent": r.UserAgent(),
	}).Info("Received OAuth callback")

	// Parse query parameters
	query := r.URL.Query()
	code := query.Get("code")
	state := query.Get("state")
	errorParam := query.Get("error")
	errorDescription := query.Get("error_description")

	result := &CallbackResult{
		Code:  code,
		State: state,
	}

	if errorParam != "" {
		result.Error = errorParam
		if errorDescription != "" {
			result.Error = fmt.Sprintf("%s: %s", errorParam, errorDescription)
		}
	}

	// Send result to channel (non-blocking, only first result matters)
	cs.once.Do(func() {
		cs.resultCh <- result
		close(cs.resultCh)
	})

	// Render success/error page
	cs.renderResultPage(w, result)
}

// handleHealth handles health check requests
func (cs *CallbackServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// renderResultPage renders the callback result page
func (cs *CallbackServer) renderResultPage(w http.ResponseWriter, result *CallbackResult) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if result.Error != "" {
		w.WriteHeader(http.StatusBadRequest)
		cs.renderErrorPage(w, result.Error)
	} else {
		w.WriteHeader(http.StatusOK)
		cs.renderSuccessPage(w)
	}
}

// renderSuccessPage renders the authentication success page
func (cs *CallbackServer) renderSuccessPage(w http.ResponseWriter) {
	tmpl := template.Must(template.New("success").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Authentication Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 500px;
        }
        .icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
        h1 {
            color: #333;
            margin: 0 0 1rem 0;
        }
        p {
            color: #666;
            margin: 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✓</div>
        <h1>Authentication Successful</h1>
        <p>You have successfully authenticated with Vault MCP Server.</p>
        <p>You can now close this window and return to your application.</p>
    </div>
</body>
</html>
`))

	if err := tmpl.Execute(w, nil); err != nil {
		cs.logger.WithError(err).Error("Failed to render success page")
	}
}

// renderErrorPage renders the authentication error page
func (cs *CallbackServer) renderErrorPage(w http.ResponseWriter, errorMsg string) {
	tmpl := template.Must(template.New("error").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Authentication Failed</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 500px;
        }
        .icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
        h1 {
            color: #333;
            margin: 0 0 1rem 0;
        }
        p {
            color: #666;
            margin: 0;
        }
        .error {
            background: #fee;
            border: 1px solid #fcc;
            border-radius: 5px;
            padding: 1rem;
            margin-top: 1rem;
            color: #c33;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✗</div>
        <h1>Authentication Failed</h1>
        <p>There was an error during authentication.</p>
        <div class="error">{{ . }}</div>
        <p style="margin-top: 1rem;">Please close this window and try again.</p>
    </div>
</body>
</html>
`))

	if err := tmpl.Execute(w, errorMsg); err != nil {
		cs.logger.WithError(err).Error("Failed to render error page")
	}
}

// GetPort returns the port the callback server is listening on
func (cs *CallbackServer) GetPort() int {
	if cs.listener == nil {
		return 0
	}
	addr := cs.listener.Addr().(*net.TCPAddr)
	return addr.Port
}
