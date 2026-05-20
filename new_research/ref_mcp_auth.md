The Authorization Flow: Step by Step
Let’s walk through what happens when a client wants to connect to your protected MCP server:
1
Initial Handshake

When your MCP client first tries to connect, your server responds with a 401 Unauthorized and tells the client where to find authorization information, captured in a Protected Resource Metadata (PRM) document. The document is hosted by the MCP server, follows a predictable path pattern, and is provided to the client in the resource_metadata parameter within the WWW-Authenticate header.
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="mcp",
  resource_metadata="https://your-server.com/.well-known/oauth-protected-resource"
This tells the client that authorization is required for the MCP server and where to get the necessary information to kickstart the authorization flow.
2
Protected Resource Metadata Discovery

With the URI pointer to the PRM document, the client will fetch the metadata to learn about the authorization server, supported scopes, and other resource information. The data is typically encapsulated in a JSON blob, similar to the one below.
{
  "resource": "https://your-server.com/mcp",
  "authorization_servers": ["https://auth.your-server.com"],
  "scopes_supported": ["mcp:tools", "mcp:resources"]
}
You can see a more comprehensive example in RFC 9728 Section 3.2.
3
Authorization Server Discovery

Next, the client discovers what the authorization server can do by fetching its metadata. If the PRM document lists more than one authorization server, the client can decide which one to use.
With an authorization server selected, the client will then construct a standard metadata URI and issue a request to the OpenID Connect (OIDC) Discovery or OAuth 2.0 Auth Server Metadata endpoints (depending on authorization server support) and retrieve another set of metadata properties that will allow it to know the endpoints it needs to complete the authorization flow.
{
  "issuer": "https://auth.your-server.com",
  "authorization_endpoint": "https://auth.your-server.com/authorize",
  "token_endpoint": "https://auth.your-server.com/token",
  "registration_endpoint": "https://auth.your-server.com/register"
}
4
Client Registration

With all the metadata out of the way, the client now needs to make sure that it’s registered with the authorization server. This can be done in two ways.
First, the client can be pre-registered with a given authorization server, in which case it can have embedded client registration information that it uses to complete the authorization flow.
Alternatively, the client can use Dynamic Client Registration (DCR) to dynamically register itself with the authorization server. The latter scenario requires the authorization server to support DCR. If the authorization server does support DCR, the client will send a request to the registration_endpoint with its information:
{
  "client_name": "My MCP Client",
  "redirect_uris": ["http://localhost:3000/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"]
}
If the registration succeeds, the authorization server will return a JSON blob with client registration information.
No DCR or Pre-Registration
In case an MCP client connects to an MCP server that doesn’t use an authorization server that supports DCR and the client is not pre-registered with said authorization server, it’s the responsibility of the client developer to provide an affordance for the end-user to enter client information manually.
5
User Authorization

The client will now need to open a browser to the /authorize endpoint, where the user can log in and grant the required permissions. The authorization server will then redirect back to the client with an authorization code that the client exchanges for tokens:
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "def502...",
  "token_type": "Bearer",
  "expires_in": 3600
}
The access token is what the client will use to authenticate requests to the MCP server. This step follows standard OAuth 2.1 authorization code with PKCE conventions.
6
Making Authenticated Requests

Finally, the client can make requests to your MCP server using the access token embedded in the Authorization header:
GET /mcp HTTP/1.1
Host: your-server.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
The MCP server will need to validate the token and process the request if the token is valid and has the required permissions.