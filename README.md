# <img src="public/images/Vault-LogoMark_onDark.svg" width="30" align="left" style="margin-right: 12px;"/> Vault MCP Server

The Vault MCP Server is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/introduction)
server implementation that provides integration with HashiCorp
Vault for managing secrets and mounts. This server uses both stdio and StreamableHTTP
transports for MCP communication, making it compatible with Claude for Desktop 
and other MCP clients.

> **Security Note:** At this stage, the MCP server is intended for local use only. If using the StreamableHTTP transport in production, always configure the MCP_ALLOWED_ORIGINS environment variable to restrict access to trusted origins only. This helps prevent DNS rebinding attacks and other cross-origin vulnerabilities.

> **Security Note:** Depending on the query, the MCP server may expose certain Vault data, including Vault secrets, to the MCP client and LLM. Do not use the MCP server with untrusted MCP clients or LLMs.

> **Legal Note:** Your use of a third party MCP Client/LLM is subject solely to the terms of use for such MCP/LLM, and IBM is not responsible for the performance of such third party tools. IBM expressly disclaims any and all warranties and liability for third party MCP Clients/LLMs, and may not be able to provide support to resolve issues which are caused by the third party tools. 

> **Caution:**  The outputs and recommendations provided by the MCP server are generated dynamically and may vary based on the query, model, and the connected MCP client. Users should thoroughly review all outputs/recommendations to ensure they align with their organization’s security best practices, cost-efficiency goals, and compliance requirements before implementation.

## Features

- Create new mounts in Vault (KV v1, KV v2)
- List all available mounts
- Delete a mount
- Write secrets to KV mounts
- Read secrets from KV mounts
- List all secrets under a path
- Delete a complete secret or a key of a secret 
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
- `VAULT_NAMESPACE`: Vault namespace (optional)
- `TRANSPORT_MODE`: Set to `http` to enable HTTP mode
- `TRANSPORT_HOST`: Host to bind to for HTTP mode (default: `127.0.0.1`)
- `TRANSPORT_PORT`: Port for HTTP mode (default: `8080`)
- `MCP_ENDPOINT`: HTTP server endpoint path (default: `/mcp`)
- `MCP_ALLOWED_ORIGINS`: Comma-separated list of allowed origins for CORS (default: `""`)
- `MCP_CORS_MODE`: CORS mode: `strict`, `development`, or `disabled` (default: `strict`)

## HTTP Mode Configuration

In HTTP mode, Vault configuration can be provided through multiple methods (in order of precedence):

- **HTTP Query**: `VAULT_ADDR`
- **HTTP Headers**: `VAULT_ADDR`, `X-Vault-Token`, and `X-Vault-Namespace`
- **Environment Variables**: Standard `VAULT_ADDR`, `VAULT_TOKEN`, and `VAULT_NAMESPACE` env vars

### Middleware Stack

The HTTP server includes a comprehensive middleware stack:

- **CORS Middleware**: Enables cross-origin requests with appropriate headers
- **Vault Context Middleware**: Extracts Vault configuration and adds to request context
- **Logging Middleware**: Structured HTTP request logging

## Integration with Visual Studio Code


1. In your project workspace root, create or open the `.vscode/mcp.json` configuration file. Alternatively, to add an MCP to your user configuration, run the `MCP: Open User Configuration` command, which opens the mcp.json file in your user profile. If the file does not exist, VS Code creates it for you.

    ```json
    {
      "inputs": [
        {
          "type": "promptString",
          "id": "vault-token",
          "description": "Vault Token",
          "password": true
        },
        {
          "type": "promptString",
          "id": "vault-namespace",
          "description": "Vault Namespace (optional)",
          "password": false
        }
      ],
      "servers": {
        "MCP Server Vault": {
          "url": "http://localhost:8080/mcp?VAULT_ADDR=http://127.0.0.1:8200",
          "headers": {
            "X-Vault-Token": "${input:vault-token}",
            "X-Vault-Namespace": "${input:vault-namespace}"
          }
        }
      }
    }
    ```

2. Save `mcp.json` file.

3. Restart Visual Studio Code (or reload the window).

**Note:** Visual Studio Code will prompt you for the VAULT_TOKEN once and store it securely in the client.

## Working with Docker

Build the docker image:

```bash
make docker-build
```

Build the image with a custom registry:
```bash
make docker-build DOCKER_REGISTRY=your-registry.com
```

Push the image to a custom registry:
```bash
make docker-push DOCKER_REGISTRY=your-registry.com
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

### Mount Management Tools

#### create_mount
Creates a new mount in Vault.
- `type`: The type of mount (e.g., 'kv', 'kv2', 'pki')
- `path`: The path where the mount will be created
- `description`: (Optional) Description for the mount

#### list_mounts
Lists all mounts in Vault.
- No parameters required

#### delete_mount
Delete a mount in Vault.
- `path`: The path to the mount to be deleted

### Key-Value Tools

#### list_secrets
Lists secrets in a KV mount under a specific path in Vault.
- `mount`: The mount path of the secret engine
- `path`: (Optional) The path to list secrets from (defaults to root)

#### delete_secret
Delete secrets (or keys) in a KV mount under a specific path in Vault.
- `mount`: The mount path of the secret engine
- `path`: The path to the secret to delete
- `key`: (Optional) The key name to delete from the entire secret (defaults to deleting the entire secret)

#### write_secret
Writes a secret to a KV mount in Vault.
- `mount`: The mount path of the secret engine
- `path`: The full path to write the secret to
- `key`: The key name for the secret
- `value`: The value to store

#### read_secret
Reads a secret from a KV mount in Vault.
- `mount`: The mount path of the secret engine
- `path`: The full path to read the secret from

### PKI Tools

#### enable_pki
Enables and configures a PKI secrets engine.
- `path`: The path where the PKI engine will be mounted
- `description`: (Optional) Description for the PKI mount

#### create_pki_issuer
Creates a new PKI issuer.
- `mount`: The mount path of the PKI engine
- `name`: Name of the issuer
- `certificate`: The PEM-encoded certificate
- `privateKey`: The PEM-encoded private key

#### list_pki_issuers
Lists all PKI issuers in a mount.
- `mount`: The mount path of the PKI engine

#### read_pki_issuer
Reads details about a specific PKI issuer.
- `mount`: The mount path of the PKI engine
- `name`: Name of the issuer

#### create_pki_role
Creates a new PKI role for issuing certificates.
- `mount`: The mount path of the PKI engine
- `name`: Name of the role
- `config`: Role configuration parameters (TTL, allowed domains, etc.)

#### read_pki_role
Reads a PKI role configuration.
- `mount`: The mount path of the PKI engine
- `name`: Name of the role

#### list_pki_roles
Lists all PKI roles in a mount.
- `mount`: The mount path of the PKI engine

#### delete_pki_role
Deletes a PKI role.
- `mount`: The mount path of the PKI engine
- `name`: Name of the role

#### issue_pki_certificate
Issues a new certificate using a PKI role.
- `mount`: The mount path of the PKI engine
- `role`: Name of the role to use
- `commonName`: Common name for the certificate
- `altNames`: (Optional) Alternative names for the certificate
- `ipSans`: (Optional) IP SANs for the certificate
- `ttl`: (Optional) Time-to-live for the certificate

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
├── bin/                                  # Binary output directory
│   └── vault-mcp-server                  # Compiled binary
├── cmd/vault-mcp-server/                 # Main application entry point
│   ├── init.go                           # Initialization code
│   └── main.go                           # Main application
├── pkg/                                  # Package directory
│   ├── client/                           # Client implementation
│   │   ├── client.go                     # Core client functionality
│   │   └── middleware.go                 # HTTP middleware
│   ├── tools/                            # MCP tools implementation
│   │   ├── kv/                           # Key-Value tools
│   │   ├── pki/                          # PKI certificate tools
│   │   ├── sys/                          # System management tools
│   │   └── tools.go                      # Tool registration
│   └── utils/                            # Utility functions
├── scripts/                              # Build and utility scripts
├── version/                              # Version information
├── e2e/                                  # End-to-end tests
├── Dockerfile                            # Container build definition
├── Makefile                              # Build automation
├── go.mod                                # Go module definition
└── LICENSE                               # License information
```
