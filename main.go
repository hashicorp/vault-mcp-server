package main

import (
	"context"
	"flag"
	"github.com/mark3labs/mcp-go/server"
	"log"
	"net/http"
	"os"
	"vault-mcp-server/tools"
	"vault-mcp-server/vault"
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

var VaultAddressHeader string = "VAULT_ADDR"
var VaultTokenHeader string = "VAULT_TOKEN"

func newSession(ctx context.Context, session server.ClientSession) {
	// Initialize a new Vault client for this session
	vaultAddress, ok := ctx.Value(VaultAddressHeader).(string)
	if !ok {
		// TODO: Disconnect the session if the token is not provided
		return
	}

	vaultToken, ok := ctx.Value(VaultTokenHeader).(string)
	if !ok {
		// TODO: Disconnect the session if the token is not provided
		return
	}

	_, err := vault.NewVaultClient(session.SessionID(), vaultAddress, vaultToken)

	if err != nil {
		return
	}
	return
}

func endSession(_ context.Context, session server.ClientSession) {
	vault.DeleteVaultClient(session.SessionID())
}

// HeaderMiddleware adds header values to the request context
func HeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		neededHeaders := [2]string{VaultAddressHeader, VaultTokenHeader}

		ctx := r.Context()

		for _, header := range neededHeaders {
			// Get the header value from the request
			headerValue := r.Header.Get(header)

			if headerValue == "" {
				headerValue = r.URL.Query().Get(header)
			}

			if headerValue == "" {
				headerValue = getEnv(header, "")
			}

			// Create a new context with the header value
			ctx = context.WithValue(ctx, header, headerValue)
		}

		// Call the next handler with the new context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func main() {
	var addr string

	flag.StringVar(&addr, "addr", "127.0.0.1:3000", "address to listen on")
	flag.Parse()

	hooks := &server.Hooks{}

	hooks.AddOnRegisterSession(newSession)
	hooks.AddOnUnregisterSession(endSession)

	mcpServer := server.NewMCPServer("mcp-server-vault",
		"0.0.1",
		server.WithHooks(hooks),
	)

	var serverTools = []server.ServerTool{tools.ReadSecrets()}

	mcpServer.AddTools(serverTools...)

	handler := server.NewStreamableHTTPServer(
		mcpServer,
		server.WithSessionIdManager(&VaultStatefulSessionIdManager{}),
	)

	//mux := http.NewServeMux()
	//mux.Handle("/mcp", HeaderMiddleware(handler))

	http.Handle("/streamable-http", handler)

	log.Printf("Streamable HTTP server listening on %s", addr)
	if err := http.ListenAndServe(addr, HeaderMiddleware(handler)); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
