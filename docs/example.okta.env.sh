# Example configuration for Vault MCP Server with Okta authentication

# Vault Configuration
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="your-vault-token-here"
# export VAULT_NAMESPACE="namespace" # Optional

# Transport Configuration
export TRANSPORT_MODE="http"
export TRANSPORT_HOST="0.0.0.0"  # Listen on all interfaces
export TRANSPORT_PORT="8080"
export MCP_ENDPOINT="/mcp"

# TLS Configuration (recommended for production)
# export MCP_TLS_CERT_FILE="/path/to/cert.pem"
# export MCP_TLS_KEY_FILE="/path/to/key.pem"

# CORS Configuration
export MCP_CORS_MODE="development"  # Use "strict" in production
# export MCP_ALLOWED_ORIGINS="https://app.example.com,https://admin.example.com"

# Rate Limiting
export MCP_RATE_LIMIT_GLOBAL="10:20"  # 10 requests per second, burst of 20
export MCP_RATE_LIMIT_SESSION="5:10"  # 5 requests per second per session, burst of 10

# Okta Authentication
export MCP_AUTH_ENABLED="true"
export MCP_AUTH_PROVIDER="okta"  # Optional, auto-detected if OKTA_DOMAIN is set
export OKTA_DOMAIN="dev-12345.okta.com"
export OKTA_AUDIENCE="api://default"
export OKTA_AUTH_SERVER_ID="default"  # Optional, defaults to "default"
# export OKTA_ISSUER="https://dev-12345.okta.com/oauth2/default"  # Optional, auto-detected
export OKTA_REQUIRED_SCOPES="mcp:tools,mcp:resources"

# Start the server
./bin/vault-mcp-server streamable-http
