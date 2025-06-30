# Vault MCP Server

A Model Context Protocol (MCP) server that provides integration with HashiCorp
Vault for managing secrets and mounts. This server uses the Streamable HTTP
transport for MCP communication, making it compatible with Claude for Desktop 
and other MCP clients.

## Features

- Create new mounts in Vault (KV v1, KV v2)
- List all available mounts
- Deletes a mount
- Write secrets to KV mounts
- Read secrets from KV mounts
- List all secrets under a path

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
2. Build the Docker image:

    ```bash
    make
    ```

3. Start the server:

    ```bash
    vault-mcp-server -addr 127.0.0.1:3000
    ```

## Integration with Visual Studio Code

1. Open or create your Visual Studio Code configuration file:

    ```bash
    # On macOS
    code ~/Library/Application\ Support/Code/User/settings.json
    ```

2. Add the Vault MCP server configuration in the mcp section:

    ```
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
                 "url": "http://localhost:3000/mcp?VAULT_ADDR=http://127.0.0.1:8200",
                 "headers": {
                     "VAULT_TOKEN" : "${input:vault-token}"
                 }
             },
         }
     }
    ```

3. Restart Visual Studio Code (or start server in settings.json)

<b>Note: Visual Studio Code will prompt you for the VAULT_TOKEN once and, store
it securely in the client.</b>

## Working with Docker

Build the docker image and create a network

```
make docker-build
docker network create mcp
```

Run the Vault container and get the root token

```
docker run --cap-add=IPC_LOCK --name=vault-dev --network=mcp -p 8200:8200 hashicorp/vault server -dev
docker logs vault-dev
```

Run the Vault MCP server

```
docker run --network=mcp -p 3000:3000 -e VAULT_ADDR='http://vault-dev:8200' -e VAULT_TOKEN='<your-token-from-last-step>' vault-mcp-server:dev
```

## Available Tools

### create-mount

Creates a new mount in Vault.

- `type`: The type of mount (e.g., 'kv', 'kv2')
- `path`: The path where the mount will be created
- `description`: (Optional) Description for the mount

### list-mounts

Lists all mounts in Vault.

- No parameters required

### delete-mount

Delete a mounts in Vault.

- `path`: The path to the mount to be deleted

### list-secrets

Lists secrets in a KV mount under a specific path in Vault.

- `mount`: The mount path of the secret engine
- `path`: The full path to write the secret to

### write-secret

Writes a secret to a KV mount in Vault.

- `mount`: The mount path of the secret engine
- `path`: The full path to write the secret to
- `key`: The key name for the secret
- `value`: The value to store

### read-secret

Reads a secret from a KV mount in Vault.

- `mount`: The mount path of the secret engine
- `path`: The full path to read the secret from, including the mount

## Using the MCP Inspector

You can use
the [@modelcontextprotocol/inspector](https://www.npmjs.com/package/@modelcontextprotocol/inspector)
tool to inspect and interact with your running Vault MCP server via a web UI.

```bash
npx @modelcontextprotocol/inspector
```

---
