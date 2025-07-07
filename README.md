# Vault MCP Server

A Model Context Protocol (MCP) server that provides integration with HashiCorp
Vault for managing secrets and mounts. This server uses both stdio and StreamableHTTP
transports for MCP communication, making it compatible with Claude for Desktop 
and other MCP clients.

## Features

- Create new mounts in Vault (KV v1, KV v2)
- List all available mounts
- Delete a mount
- Write secrets to KV mounts
- Read secrets from KV mounts
- List all secrets under a path
- Comprehensive HTTP middleware stack (CORS, logging, Vault context)
- Session-based Vault client management
- Structured logging with configurable output

## Prerequisites
- Go 1.24 or later (if building from source)
- Docker
- HashiCorp Vault server running locally or remotely
- A valid Vault token with appropriate permissions

## Setup

1. Clone the repository:
    ```bash
    git clone https://github.com/hashicorp/vault-mcp-server.git
    cd vault-mcp-server
    ```

2. Build the binary:
    ```bash
    make build
    ```

3. Run the server:

    **Stdio mode (default):**
    ```bash
    ./vault-mcp-server
    # or explicitly
    ./vault-mcp-server stdio
    ```

    **HTTP mode:**
    ```bash
    ./vault-mcp-server http --transport-port 8080
    # or using make
    make run-http
    ```

## Environment Variables

The server can be configured using environment variables:

- `VAULT_ADDR`: Vault server address (default: `http://127.0.0.1:8200`)
- `VAULT_TOKEN`: Vault authentication token (required)
- `TRANSPORT_MODE`: Set to `http` to enable HTTP mode
- `TRANSPORT_HOST`: Host to bind to for HTTP mode (default: `127.0.0.1`)
- `TRANSPORT_PORT`: Port for HTTP mode (default: `8080`)

## HTTP Mode Configuration

In HTTP mode, Vault configuration can be provided through multiple methods (in order of precedence):

1. **HTTP Headers**: `VAULT_ADDR` and `VAULT_TOKEN` headers
2. **Query Parameters**: `?VAULT_ADDR=...&VAULT_TOKEN=...`
3. **Environment Variables**: Standard `VAULT_ADDR` and `VAULT_TOKEN` env vars

### Middleware Stack

The HTTP server includes a comprehensive middleware stack:

- **CORS Middleware**: Enables cross-origin requests with appropriate headers
- **Vault Context Middleware**: Extracts Vault configuration and adds to request context
- **Logging Middleware**: Structured HTTP request logging

## Integration with Visual Studio Code

1. Open or create your Visual Studio Code configuration file:

    ```bash
    # On macOS
    code ~/Library/Application\ Support/Code/User/settings.json
    ```

2. Add the Vault MCP server configuration in the mcp section:

    ```json
    "mcp": {
         "inputs": [
             {
                 "type": "promptString",
                 "id": "vault-token",
                 "description": "Vault Token",
                 "password": true
             }
         ],
         "servers": {
             "MCP Server Vault": {
                 "url": "http://localhost:8080/mcp?VAULT_ADDR=http://127.0.0.1:8200",
                 "headers": {
                     "VAULT_TOKEN" : "${input:vault-token}"
                 }
             }
         }
     }
    ```

3. Restart Visual Studio Code (or start server in settings.json)

**Note: Visual Studio Code will prompt you for the VAULT_TOKEN once and store
it securely in the client.**

## Working with Docker

Build the docker image:

```bash
make docker-build
```

Run the Vault container and get the root token:

```bash
docker network create mcp
docker run --cap-add=IPC_LOCK --name=vault-dev --network=mcp -p 8200:8200 hashicorp/vault server -dev
docker logs vault-dev
```

Run the Vault MCP server:

```bash
docker run --network=mcp -p 8080:8080 -e VAULT_ADDR='http://vault-dev:8200' -e VAULT_TOKEN='<your-token-from-last-step>' -e TRANSPORT_MODE='http' vault-mcp-server:dev
```

## Available Tools

### create_mount

Creates a new mount in Vault.

- `type`: The type of mount (e.g., 'kv', 'kv2')
- `path`: The path where the mount will be created
- `description`: (Optional) Description for the mount

### list_mounts

Lists all mounts in Vault.

- No parameters required

### delete_mount

Delete a mount in Vault.

- `path`: The path to the mount to be deleted

### list_secrets

Lists secrets in a KV mount under a specific path in Vault.

- `mount`: The mount path of the secret engine
- `path`: (Optional) The path to list secrets from (defaults to root)

### write_secret

Writes a secret to a KV mount in Vault.

- `mount`: The mount path of the secret engine
- `path`: The full path to write the secret to
- `key`: The key name for the secret
- `value`: The value to store

### read_secret

Reads a secret from a KV mount in Vault.

- `mount`: The mount path of the secret engine
- `path`: The full path to read the secret from

## Command Line Usage

```bash
# Show help
./vault-mcp-server --help

# Run in stdio mode (default)
./vault-mcp-server
./vault-mcp-server stdio

# Run in HTTP mode
./vault-mcp-server http --transport-port 8080 --transport-host 127.0.0.1

# Show version
./vault-mcp-server --version

# Run with custom log file
./vault-mcp-server --log-file /path/to/logfile.log
```

## Using the MCP Inspector

You can use
the [@modelcontextprotocol/inspector](https://www.npmjs.com/package/@modelcontextprotocol/inspector)
tool to inspect and interact with your running Vault MCP server via a web UI.

For HTTP mode:
```bash
npx @modelcontextprotocol/inspector http://localhost:8080/mcp
```

For stdio mode:
```bash
npx @modelcontextprotocol/inspector ./vault-mcp-server
```

## Development

### Building

```bash
# Build the binary
make build

# Build with Docker
make docker-build

# Clean build artifacts
make clean
```

### Testing

```bash
# Run tests
make test

# Run end-to-end tests
make test-e2e

# Test HTTP endpoint
make test-http
```

### Project Structure

```
vault-mcp-server/
├── cmd/vault-mcp-server/          # Main application entry point
├── pkg/hashicorp/vault/           # Core vault functionality
│   ├── client.go                  # Vault client management
│   ├── middleware.go              # HTTP middleware stack
│   ├── tools.go                   # Tool registration
│   └── *_test.go                  # Unit tests
├── version/                       # Version management
├── e2e/                          # End-to-end tests
└── resources/                     # Resource definitions
```
