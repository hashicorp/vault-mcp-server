1. Login
MCP Client → MCP Server: Login request

2. OpenID Connect Authentication
MCP Server → IdP: OIDC Auth (RFC 9728)
IdP → MCP Server: ID Token (with exp, aud, scope claims)

3. Tool Invocation
MCP Client → MCP Server: Tool call + ID token (with audience, scope)

4. Token Exchange (RFC 8693)
MCP Server → Token Broker: Token Exchange Request
  - grant_type: urn:ietf:params:oauth:grant-type:token-exchange
  - subject_token: [ID Token]
  - subject_token_type: urn:ietf:params:oauth:token-type:id_token
  - scope: [requested permissions, e.g., "repo:read", "repo:write"]
  - audience: [target service, e.g., "github.com"]
  - resource: [specific resource, e.g., "https://api.github.com"]

5. Token Validation
Token Broker → IdP: Validate ID token (introspection)
  - POST /oauth/introspect
  - token: [ID Token]
  - token_type_hint: id_token
IdP → Token Broker: Token validity response
  - active: true/false
  - exp: [expiration timestamp]
  - aud: [audience]
  - sub: [subject]
  - scope: [original scopes]

6. Third-Party Token Generation
The token broker would need access to 3rd Party credentials used to generate other tokens
Token Broker → Third Party (GitHub): Generate scoped token
  - Request limited-scope token based on:
    - Original token claims
    - Requested scope (downscoped e.g., "repo:read")
    - Resource restrictions
    - Time limitations
Third Party → Token Broker: Scoped access token
  - access_token: [limited permissions token]
  - token_type: "Bearer"
  - expires_in: [short duration, e.g., 3600]
  - scope: [actual granted scope]

7. Token Exchange Response
Token Broker → MCP Server: Token exchange response
  - access_token: [GitHub token]
  - token_type: "Bearer"
  - expires_in: [token lifetime]
  - scope: [granted permissions]
  - audit_id: [log entry identifier]

8. Third-Party API Call
MCP Server → Third Party: Authenticated API call
  - Authorization: Bearer [scoped token]
  - Request to specific GitHub API endpoint
Third Party → MCP Server: API response
  - JSON response with requested data

9. Tool Response
MCP Server → MCP Client: Tool response
  - Processed API response
  - No token information exposed
 