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
    ./vault-mcp-server http --port 8080
    # or using make
    make run-http
    ```

## Configuration

### Environment Variables

The server can be configured using the following environment variables:

- `VAULT_ADDR`: Vault server address (default: `http://127.0.0.1:8200`)
- `VAULT_TOKEN`: Vault authentication token (required)
- `TRANSPORT_MODE`: Set to `http` to enable HTTP mode
- `TRANSPORT_HOST`: Host to bind to for HTTP mode (default: `0.0.0.0`)
- `TRANSPORT_PORT`: Port for HTTP mode (default: `8080`)

### streamableHTTP Mode

In streamableHTTP mode, configuration can be provided through multiple methods with different precedence:

#### Transport Host/Port
Priority order:
1. **Flags**: `--transport-host` or `--transport-port`
2. **Environment Variables**: `TRANSPORT_HOST` or `TRANSPORT_PORT` env var

#### Vault Address
Priority order:
1. **HTTP Headers**: `VAULT_ADDR` header
2. **Query Parameters**: `?VAULT_ADDR=http://vault:8200`
3. **Environment Variables**: `VAULT_ADDR` env var

#### Vault Token
Priority order (for security, query parameters are NOT supported):
1. **HTTP Headers**: `VAULT_TOKEN` header
2. **Environment Variables**: `VAULT_TOKEN` env var

### stdio Mode

In stdio mode, Vault configuration can only be provided via environment variables

## Usage with Visual Studio Code

Add the following JSON block to your User Settings (JSON) file in VS Code. You can do this by pressing `Ctrl + Shift + P` and typing `Preferences: Open User Settings (JSON)`. 

More about using MCP server tools in VS Code's [agent mode documentation](https://code.visualstudio.com/docs/copilot/chat/mcp-servers).


```json
{
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
}
```

Restart Visual Studio Code (or start server in settings.json. Optionally, you can add a similar example (i.e. without the mcp key) to a file called `.vscode/mcp.json` in your workspace. This will allow you to share the configuration with others.

**Note: Visual Studio Code will prompt you for the VAULT_TOKEN once and store it securely in the client.**

## ## Building the Docker Image locally

Before using the server, you need to build the Docker image locally

```bash
git clone https://github.com/hashicorp/vault-mcp-server.git
cd vault-mcp-server
make docker-build
```

Create a shared Docker network

```bash
docker network create mcp
```

Run the Vault container, get the root token and connect with the MCP server:

```bash
# Run Vault in dev mode
docker run --cap-add=IPC_LOCK --name=vault-dev --network=mcp -p 8200:8200 hashicorp/vault server -dev

# Extract the Vault root token
export VAULT_TOKEN=$(docker logs vault-dev 2>&1 | grep 'Root Token:' | awk '{print $NF}')

# Run the Vault MCP server
docker run --network=mcp -p 8080:8080 -e VAULT_ADDR='http://vault-dev:8200' -e VAULT_TOKEN=\$VAULT_TOKEN -e TRANSPORT_MODE='http' vault-mcp-server:dev
```

## Available Toolsets

| Tool Name      | Description                                 | Parameters                                                                                  |
|----------------|---------------------------------------------|---------------------------------------------------------------------------------------------|
| createMount    | Creates a new mount in Vault                | `type` (mount type, e.g., `kv`, `kv2`), `path` (mount path), `description` (optional)       |
| deleteMount    | Deletes a mount in Vault                    | `path` (mount path to delete)                                                               |
| listMounts     | Lists all mounts in Vault                   | _None_                                                                                      |
| listSecrets    | Lists secrets in a KV mount under a path    | `mount` (mount path), `path` (optional, defaults to root)                                   |
| readSecret     | Reads a secret from a KV mount in Vault     | `mount` (mount path), `path` (secret path)                                                  |
| writeSecret    | Writes a secret to a KV mount in Vault      | `mount` (mount path), `path` (secret path), `key` (secret key), `value` (secret value)      |

## Command Line Usage

```bash
# Show help
./vault-mcp-server --help

# Run with custom log file
./vault-mcp-server --log-file /path/to/logfile.log

# Run in stdio mode (default)
./vault-mcp-server
./vault-mcp-server stdio

# Run in HTTP mode
./vault-mcp-server http --port 8080 --host 0.0.0.0
```

## Using the MCP Inspector

You can use the [@modelcontextprotocol/inspector](https://www.npmjs.com/package/@modelcontextprotocol/inspector) tool to inspect and interact with your running Vault MCP server via a web UI.

For streamableHTTP mode:
```bash
npx @modelcontextprotocol/inspector http://localhost:8080/mcp
```

For stdio mode:
```bash
npx @modelcontextprotocol/inspector ./vault-mcp-server
```

## Development

### Prerequisites

* Go (check go.mod file for specific version)
* Docker (optional, for container builds)

### Available Make Commands

| Command                         | Description                        |
|---------------------------------|------------------------------------|
| `make build`                    | Build the binary                   |
| `make test`                     | Run all tests                      |
| `make test-e2e`                 | Run end-to-end tests               |
| `make docker-build`             | Build Docker image                 |
| `make run-http`                 | Run HTTP server locally            |
| `make docker-run-http`          | Run HTTP server in Docker          |
| `make test-http`                | Test HTTP health endpoint          |
| `make clean`                    | Remove build artifacts             |
| `make cleanup-test-containers`  | Stop and remove all test containers|
| `make help`                     | Show all available commands        |

## Contributing

1. Fork the repository
2. Create your feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

This project is licensed under the terms of the MPL-2.0 open source license. Please refer to [LICENSE](./LICENSE) file for the full terms.

## Security

For security issues, please contact security@hashicorp.com or follow our [security policy](https://www.hashicorp.com/en/trust/security/vulnerability-management).

## Support

For bug reports and feature requests, please open an issue on GitHub.

For general questions and discussions, open a GitHub Discussion.
