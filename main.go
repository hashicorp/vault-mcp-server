package main

import (
    "flag"
    "github.com/mark3labs/mcp-go/server"
    "log"
    "net/http"
    tools "vault-mcp-server/tools/vault"
)

func main() {
    var addr string
    flag.StringVar(&addr, "addr", ":3000", "address to listen on")
    flag.Parse()

    mcpServer := server.NewMCPServer("mcp-server-vault", "0.0.1")

    var serverTools = []server.ServerTool{tools.ReadSecrets()}

    mcpServer.AddTools(serverTools...)

    handler := server.NewStreamableHTTPServer(
        mcpServer,
    )

    mux := http.NewServeMux()
    mux.Handle("/mcp", handler)

    http.Handle("/streamable-http", handler)

    log.Printf("Streamable HTTP server listening on %s", addr)
    if err := http.ListenAndServe(addr, handler); err != nil {
        log.Fatalf("Server error: %v", err)
    }
}
