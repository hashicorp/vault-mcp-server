## 0.2.2

FEATURES

* Adding this server to official MCP server registry. See [61](https://github.com/hashicorp/vault-mcp-server/pull/61)

UPDATES

* Bump github.com/hashicorp/vault/api from 1.21.0 to 1.22.0 [58](https://github.com/hashicorp/vault-mcp-server/pull/58)
* Bump golang.org/x/time from 0.13.0 to 0.14.0 [59](https://github.com/hashicorp/vault-mcp-server/pull/59)
* Bump github.com/mark3labs/mcp-go from 0.41.1 to 0.42.0 [60](https://github.com/hashicorp/vault-mcp-server/pull/60)

## 0.2.1

FEATURES

* Adding Gemini extension. See [56](https://github.com/hashicorp/vault-mcp-server/pull/56)

## 0.2.0

FEATURES

- Support for Vault PKI operations (create, list, read, delete)
- Comprehensive HTTP middleware stack (CORS, TLS, logging, Vault context, rate limiting)
- Session-based Vault client management
- Structured logging with configurable output

## 0.1.0

FEATURES

- Initial release of Vault MCP Server
- Support for Vault mount operations (create, list, delete)
- Support for Vault secret operations (read, write, list)
- Docker support
- Basic HTTP & STDIO transport support
