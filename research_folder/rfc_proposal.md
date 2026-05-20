# RFC: OIDC Authentication and Audit-First Traceability for Vault MCP Server

## Overview

This RFC proposes implementing enterprise-grade authentication and comprehensive audit capabilities for the Vault MCP Server to enable secure adoption in single-user, AI-assisted workflows. The solution replaces static token authentication with OIDC-based identity flows, implements dynamic tool filtering based on user permissions, enforces safety-first operation modes with explicit approval gates for sensitive operations, and ensures complete traceability of all agent actions in both MCP server logs and Vault audit logs. This transformation enables platform engineers to deploy Vault MCP Server with confidence that agent interactions respect enterprise security boundaries, maintain clear human attribution, and provide the governance visibility required for compliance and operational trust.

## Background

### Current State and Enterprise Adoption Barriers

Vault has evolved from a generic secrets management primitive into an opinionated platform that guides users toward secure, governable patterns across its UI, CLI, Terraform provider, and API. As AI-assisted workflows emerge as a critical interaction model, the Vault MCP Server must similarly provide an opinionated, secure interface that respects enterprise boundaries while enabling natural agent interactions.

Currently, the Vault MCP Server presents significant barriers to enterprise adoption:

**Identity and Access Management Gaps**: The reliance on static, long-lived Vault tokens creates fundamental security risks. Without user-scoped authentication, agents operate with potentially broader permissions than intended, creating unclear authorization boundaries and preventing proper attribution of actions to human operators. Enterprise customers require assurance that agents operate within specific user sessions with appropriate permission scoping.

**Audit and Traceability Deficiencies**: The absence of comprehensive logging makes it impossible to answer critical questions: Who initiated an action? What was the agent's intent versus what was actually executed? When did the action occur? Without this traceability in both MCP server logs and Vault audit logs, platform engineers cannot investigate incidents, satisfy compliance requirements, or build operational trust in AI-assisted workflows.

**Unsafe Default Behavior**: The current implementation lacks safety guardrails. Write operations execute without explicit approval, sensitive operations have no gating mechanisms, and there's no concept of read-only default modes. This creates unacceptable blast radius for enterprise environments where a single errant agent action could compromise security posture.

**Generic Interface Without Guidance**: The MCP server functions as a raw API proxy rather than an opinionated assistant. It lacks the ability to guide users toward secure patterns, provide contextual warnings about sensitive operations, or enforce organizational policies about tool usage.

### Why This Matters Now

The convergence of AI-assisted workflows and enterprise security requirements creates an urgent need for this RFC. Customers are actively exploring AI integration with Vault but cannot adopt the current MCP server due to the security and governance gaps outlined above. Without addressing these issues, HashiCorp risks losing market position as competitors deliver more secure AI integration patterns, and customers may build insecure workarounds that create long-term technical debt and security exposure.

The Model Context Protocol (MCP) standard provides the foundation for agent-to-system interactions, but the protocol itself is security-agnostic. This RFC defines how Vault MCP Server implements security-first patterns on top of MCP, establishing a reference architecture that can guide future HashiCorp product integrations with AI workflows.

## Proposal

This RFC proposes a comprehensive security and governance framework for Vault MCP Server, delivered in Milestone 1 (M1) to enable single-user, local execution with enterprise-grade controls. The solution consists of five integrated capabilities:

**OIDC-Based Authentication**: Replace static token authentication with enterprise identity flows using OIDC/JWT. Users authenticate through their identity provider before establishing MCP sessions, and all subsequent operations inherit the user's Vault policies and namespace access. This ensures agent actions are always scoped to authenticated human identities.

**Pre-Tool Filtering**: Dynamically filter the tool catalog exposed to MCP clients based on the authenticated user's effective Vault permissions. Tools requiring capabilities the user lacks are never exposed, preventing authorization confusion and reducing attack surface. This filtering occurs at session initialization and updates dynamically as permissions change.

**Safety-First Operation Mode**: Default to read-only operations with explicit configuration and approval gates for sensitive write operations. Platform engineers can configure which operations require approval, and users must explicitly confirm sensitive actions before execution. This reduces blast radius while maintaining workflow utility.

**Audit-First Traceability**: Implement comprehensive structured logging in both MCP server logs and Vault audit logs. Every action includes human-attributable identity context, agent intent, execution result, and timestamps. Denied actions and blocked attempts are logged even when they never reach Vault, providing complete visibility for investigation and compliance.

**Operator Visibility Tools**: Provide platform engineers with real-time and historical visibility into MCP usage patterns, permission utilization, approval patterns, and denied actions. This enables proactive security posture management and informed decision-making about tool exposure and policy refinement.

The implementation leverages Vault's existing JWT auth method for identity flows, extends the MCP protocol with custom metadata for audit context, and introduces a permission evaluation engine that maps Vault capabilities to tool exposure decisions.

## Architecture

### System Components

The proposed architecture introduces four major components that integrate with existing Vault infrastructure:

**Authentication Manager**: Handles OIDC flows, JWT token exchange, and Vault token lifecycle management. Coordinates with enterprise identity providers and Vault's JWT auth method to establish authenticated sessions.

**Permission Evaluator**: Analyzes user's effective Vault policies and namespace access to determine tool exposure. Maintains a mapping between MCP tools and required Vault capabilities, performing real-time evaluation at session initialization and on-demand during tool invocation.

**Approval Gateway**: Intercepts sensitive operations, presents approval prompts to users, and enforces timeout policies. Maintains configuration defining which operations require approval and tracks approval decisions for audit purposes.

**Audit Logger**: Enriches all MCP JSON-RPC requests with identity context and emits structured logs. Coordinates with Vault's audit system to ensure consistent attribution across both MCP server logs and Vault audit logs.

### Authentication Flow

The authentication sequence establishes user identity before any MCP operations:

1. User initiates MCP server connection (stdio or HTTP mode)
2. MCP server redirects to OIDC provider for authentication
3. User completes authentication with enterprise identity provider
4. OIDC provider returns JWT token to MCP server
5. MCP server exchanges JWT with Vault's JWT auth method
6. Vault validates JWT, applies policies, returns Vault token
7. MCP server associates session with authenticated identity
8. Permission Evaluator determines tool catalog based on policies
9. MCP session established with filtered tool list

If authentication fails at any step, the session is denied and no tools are exposed. The Vault token is stored securely in the MCP server's session context and used for all downstream Vault operations.

### Tool Filtering Logic

Pre-tool filtering prevents unauthorized tool exposure through capability-based evaluation:

**Capability Mapping**: Each MCP tool declares required Vault capabilities (read, write, delete, list) and path patterns. For example, a "read-secret" tool requires ["read"] capability on "secret/data/*" paths.

**Policy Evaluation**: At session initialization, the Permission Evaluator queries Vault for the user's effective policies and namespace access. It builds a capability matrix showing which paths the user can access with which operations.

**Tool Exposure Decision**: For each tool in the catalog, the evaluator checks if the user's capability matrix satisfies the tool's requirements. Tools are exposed only if all required capabilities are present for at least one matching path pattern.

**Dynamic Updates**: If user permissions change during the session (policy updates, token renewal), the Permission Evaluator re-evaluates and updates the exposed tool list. Clients receive notification of tool catalog changes.

**Bypass Prevention**: Even if a client attempts to invoke a filtered tool directly, the MCP server validates permissions before execution and rejects unauthorized requests.

### Approval Flow for Sensitive Operations

Safety-first operation mode introduces explicit approval gates:

**Operation Classification**: Tools are classified as read-only, standard-write, or sensitive-write based on their potential impact. Classification is configurable by platform engineers.

**Approval Requirement**: Sensitive-write operations trigger an approval prompt before execution. The prompt includes operation details, affected resources, and potential impact.

**User Confirmation**: The user must explicitly approve or deny the operation within a configured timeout period (default: 60 seconds). Approval decisions are logged with full context.

**Execution or Denial**: Approved operations proceed with execution and full audit logging. Denied or timed-out operations are blocked and logged as denied attempts.

**Configuration Options**: Platform engineers can configure which operations require approval, timeout durations, and whether to allow approval bypass for specific tool categories.

### Audit and Logging Architecture

Comprehensive traceability requires coordinated logging across MCP server and Vault:

**MCP Server Logs**: Structured JSON logs emitted for every JSON-RPC request, including:
- Authenticated user identity (entity ID, username, namespace)
- Timestamp (ISO 8601 UTC)
- Requested tool and parameters
- Execution result (success, failure, denied)
- Approval decision (if applicable)
- Session context (session ID, client identifier)

**Vault Audit Logs**: All Vault API calls from MCP server include enriched audit context:
- Source: "mcp-server"
- User identity: authenticated entity
- Original intent: MCP tool name and parameters
- Correlation ID: links MCP request to Vault operations

**Denied Action Logging**: Actions blocked by permission filtering or approval denial are logged in MCP server logs even if they never reach Vault, ensuring complete visibility.

**Log Aggregation**: MCP server logs can be forwarded to enterprise SIEM systems using standard log shippers. Correlation IDs enable joining MCP and Vault logs for end-to-end tracing.

## Implementation

### Phase 1: Authentication Infrastructure (Weeks 1-2)

**Authentication Manager Component**:
- Implement OIDC client library integration
- Build JWT token exchange handler for Vault JWT auth method
- Create session management with secure token storage
- Implement token refresh and expiration handling
- Add authentication state machine (unauthenticated → authenticating → authenticated → expired)

**Configuration Schema**:
```
{
  "auth": {
    "method": "oidc",
    "oidc_discovery_url": "https://idp.example.com/.well-known/openid-configuration",
    "client_id": "vault-mcp-server",
    "client_secret": "${OIDC_CLIENT_SECRET}",
    "redirect_uri": "http://localhost:8080/callback",
    "scopes": ["openid", "profile", "email"]
  },
  "vault": {
    "address": "https://vault.example.com",
    "jwt_auth_path": "auth/jwt",
    "namespace": "admin"
  }
}
```

**API Changes**:
- MCP server startup requires authentication before exposing tools
- New `/auth/status` endpoint for authentication state queries
- Session context includes authenticated identity metadata

### Phase 2: Permission Evaluation Engine (Weeks 3-4)

**Permission Evaluator Component**:
- Build capability matrix data structure
- Implement Vault policy parser and evaluator
- Create tool-to-capability mapping registry
- Develop dynamic tool filtering algorithm
- Add permission cache with TTL and invalidation

**Tool Capability Declarations**:
```
{
  "tool": "read-secret",
  "required_capabilities": {
    "paths": ["secret/data/*", "kv/data/*"],
    "operations": ["read"]
  }
},
{
  "tool": "write-secret",
  "required_capabilities": {
    "paths": ["secret/data/*"],
    "operations": ["create", "update"]
  }
}
```

**Evaluation Algorithm**:
1. Query Vault for user's token capabilities on relevant paths
2. Build capability matrix: {path_pattern: [operations]}
3. For each tool, check if any path pattern satisfies requirements
4. Return filtered tool list to MCP client
5. Cache results with 5-minute TTL

**Performance Optimization**:
- Batch capability queries to Vault
- Cache evaluation results per session
- Lazy-load tool metadata on first access
- Implement capability query result streaming for large policy sets

### Phase 3: Approval Gateway (Weeks 5-6)

**Approval Gateway Component**:
- Implement operation classification engine
- Build approval prompt generation
- Create approval decision tracking
- Add timeout handling with configurable durations
- Implement approval bypass for configured tool categories

**Operation Classification**:
```
{
  "operation_classes": {
    "read-only": {
      "tools": ["read-secret", "list-secrets", "get-policy"],
      "requires_approval": false
    },
    "standard-write": {
      "tools": ["write-secret", "update-policy"],
      "requires_approval": false,
      "requires_config": true
    },
    "sensitive-write": {
      "tools": ["delete-secret", "revoke-token", "seal-vault"],
      "requires_approval": true,
      "timeout_seconds": 60
    }
  }
}
```

**Approval Prompt Format**:
```
{
  "type": "approval_required",
  "operation": "delete-secret",
  "details": {
    "path": "secret/data/production/api-key",
    "impact": "Permanent deletion of secret version",
    "classification": "sensitive-write"
  },
  "timeout_seconds": 60,
  "approval_id": "apr_1234567890"
}
```

**User Response**:
```
{
  "approval_id": "apr_1234567890",
  "decision": "approved|denied",
  "timestamp": "2026-05-11T01:50:00Z"
}
```

### Phase 4: Audit Logging System (Weeks 7-8)

**Audit Logger Component**:
- Implement structured log emitter
- Build Vault audit context enrichment
- Create correlation ID generation and propagation
- Add log level configuration (debug, info, warn, error)
- Implement log rotation and retention policies

**MCP Server Log Format**:
```
{
  "timestamp": "2026-05-11T01:50:00.000Z",
  "level": "info",
  "event": "tool_invocation",
  "session_id": "sess_abc123",
  "correlation_id": "corr_xyz789",
  "user": {
    "entity_id": "entity_123",
    "username": "alice@example.com",
    "namespace": "admin"
  },
  "tool": {
    "name": "read-secret",
    "parameters": {
      "path": "secret/data/app/config"
    }
  },
  "result": {
    "status": "success",
    "duration_ms": 45
  },
  "approval": {
    "required": false
  }
}
```

**Vault Audit Context Enrichment**:
- Add custom HTTP headers to Vault requests:
  - `X-MCP-Correlation-ID`: correlation ID
  - `X-MCP-Tool`: tool name
  - `X-MCP-Session`: session ID
- Vault audit logs capture these headers for correlation

**Denied Action Logging**:
```
{
  "timestamp": "2026-05-11T01:50:00.000Z",
  "level": "warn",
  "event": "tool_denied",
  "session_id": "sess_abc123",
  "correlation_id": "corr_xyz789",
  "user": {
    "entity_id": "entity_123",
    "username": "alice@example.com"
  },
  "tool": {
    "name": "delete-secret",
    "parameters": {
      "path": "secret/data/production/api-key"
    }
  },
  "denial_reason": "approval_timeout",
  "approval": {
    "required": true,
    "timeout_seconds": 60,
    "decision": "timeout"
  }
}
```

### Phase 5: Operator Visibility Tools (Weeks 9-10)

**Visibility Dashboard Components**:
- Real-time session monitoring
- Historical usage analytics
- Permission utilization reports
- Approval pattern analysis
- Denied action summaries

**Metrics Collection**:
- Active sessions count
- Tool invocation frequency by tool and user
- Approval rates (approved vs denied vs timeout)
- Permission evaluation cache hit rates
- Authentication success/failure rates

**Query API**:
```
GET /api/v1/visibility/sessions
GET /api/v1/visibility/usage?start=2026-05-01&end=2026-05-11
GET /api/v1/visibility/denials?user=alice@example.com
GET /api/v1/visibility/approvals?tool=delete-secret
```

**Response Format**:
```
{
  "sessions": [
    {
      "session_id": "sess_abc123",
      "user": "alice@example.com",
      "started_at": "2026-05-11T01:00:00Z",
      "last_activity": "2026-05-11T01:50:00Z",
      "tool_invocations": 42,
      "approvals_required": 3,
      "approvals_granted": 2,
      "approvals_denied": 1
    }
  ]
}
```

### Phase 6: Integration and Testing (Weeks 11-12)

**Integration Testing**:
- End-to-end authentication flows with multiple OIDC providers
- Permission evaluation with complex policy sets
- Approval gateway with various timeout scenarios
- Audit log correlation across MCP and Vault
- Session lifecycle management (creation, refresh, expiration)

**Security Testing**:
- Authentication bypass attempts
- Permission filter bypass attempts
- Approval gateway bypass attempts
- Token theft and replay scenarios
- Session hijacking attempts

**Performance Testing**:
- Concurrent session handling (100+ simultaneous users)
- Permission evaluation latency under load
- Audit log throughput and backpressure handling
- Memory usage with long-running sessions
- Token refresh performance

**Compatibility Testing**:
- Multiple Vault versions (1.15+, 1.16+, 1.17+)
- Various OIDC providers (Okta, Azure AD, Auth0, Keycloak)
- Different MCP client implementations
- Stdio and HTTP transport modes

## User Experience

### Configuration Experience

**Initial Setup**:
Platform engineers configure Vault MCP Server through a YAML configuration file:

```yaml
# vault-mcp-server.yaml
server:
  mode: stdio  # or http
  port: 8080   # for http mode

auth:
  method: oidc
  oidc_discovery_url: https://idp.example.com/.well-known/openid-configuration
  client_id: vault-mcp-server
  client_secret_env: OIDC_CLIENT_SECRET
  redirect_uri: http://localhost:8080/callback
  scopes:
    - openid
    - profile
    - email

vault:
  address: https://vault.example.com
  jwt_auth_path: auth/jwt
  namespace: admin
  tls_skip_verify: false

operations:
  default_mode: read_only
  sensitive_operations:
    - delete-secret
    - revoke-token
    - seal-vault
  approval_timeout_seconds: 60
  allow_approval_bypass: false

logging:
  level: info
  format: json
  output: stdout
  audit_log_path: /var/log/vault-mcp-server/audit.log
```

**Vault JWT Auth Method Setup**:
Platform engineers must configure Vault's JWT auth method:

```bash
# Enable JWT auth method
vault auth enable jwt

# Configure OIDC discovery
vault write auth/jwt/config \
    oidc_discovery_url="https://idp.example.com/.well-known/openid-configuration" \
    oidc_client_id="vault-mcp-server" \
    oidc_client_secret="$OIDC_CLIENT_SECRET" \
    default_role="mcp-user"

# Create role mapping JWT claims to Vault policies
vault write auth/jwt/role/mcp-user \
    bound_audiences="vault-mcp-server" \
    user_claim="email" \
    role_type="jwt" \
    policies="mcp-base-policy" \
    ttl=1h
```

### User Authentication Experience

**Session Initiation**:
1. User starts MCP client (e.g., Claude Desktop, custom agent)
2. MCP client connects to Vault MCP Server
3. Server responds with authentication required message
4. Server opens browser to OIDC provider login page
5. User authenticates with enterprise credentials
6. Browser redirects back to MCP server with JWT
7. Server exchanges JWT for Vault token
8. MCP client receives session established confirmation
9. Filtered tool list is presented to user

**Authentication Failure Handling**:
- Clear error messages for invalid credentials
- Guidance on contacting IT support for access issues
- Retry mechanism with exponential backoff
- Session timeout notifications with re-authentication prompts

### Tool Invocation Experience

**Read-Only Operations** (no approval required):
```
User: "Read the secret at secret/data/app/config"
Agent: [Invokes read-secret tool]
MCP Server: [Validates permissions, executes, logs]
Agent: "The secret contains: {api_key: '...', db_url: '...'}"
```

**Standard Write Operations** (requires explicit configuration):
```
User: "Update the API key in secret/data/app/config"
Agent: [Attempts write-secret tool]
MCP Server: [Checks configuration, finds write operations disabled by default]
MCP Server: "Write operations require explicit configuration. Please enable standard_write mode."
User: [Updates configuration to allow standard writes]
Agent: [Retries write-secret tool]
MCP Server: [Validates permissions, executes, logs]
Agent: "Secret updated successfully"
```

**Sensitive Write Operations** (requires approval):
```
User: "Delete the secret at secret/data/production/api-key"
Agent: [Invokes delete-secret tool]
MCP Server: [Generates approval prompt]
MCP Server: "⚠️ APPROVAL REQUIRED
Operation: delete-secret
Path: secret/data/production/api-key
Impact: Permanent deletion of secret version
Classification: sensitive-write
Timeout: 60 seconds

Do you approve this operation? (yes/no)"
User: "yes"
MCP Server: [Records approval, executes, logs]
Agent: "Secret deleted successfully"
```

**Permission Denied Experience**:
```
User: "Delete the secret at secret/data/admin/root-token"
Agent: [Attempts delete-secret tool]
MCP Server: [Evaluates permissions, finds insufficient capabilities]
MCP Server: "Permission denied: You lack 'delete' capability on path 'secret/data/admin/*'"
Agent: "I don't have permission to delete that secret. You may need to contact your Vault administrator."
```

### Operator Visibility Experience

**Real-Time Monitoring**:
Platform engineers can query active sessions:

```bash
curl http://localhost:8080/api/v1/visibility/sessions
```

Response shows active users, tool usage, and approval patterns.

**Historical Analysis**:
Query usage patterns over time:

```bash
curl "http://localhost:8080/api/v1/visibility/usage?start=2026-05-01&end=2026-05-11&user=alice@example.com"
```

Response includes tool invocation frequency, approval rates, and denied actions.

**Audit Investigation**:
Correlate MCP and Vault logs for incident investigation:

```bash
# Find MCP log entry
grep "corr_xyz789" /var/log/vault-mcp-server/audit.log

# Find corresponding Vault audit entry
vault audit log | grep "corr_xyz789"
```

Both logs contain the correlation ID for end-to-end tracing.

## Security Considerations

### Threat Model

**Threat: Static Token Compromise**
- **Mitigation**: OIDC authentication with short-lived tokens (1-hour TTL)
- **Detection**: Audit logs show token usage patterns and anomalies
- **Response**: Token revocation and user notification

**Threat: Permission Escalation**
- **Mitigation**: Pre-tool filtering prevents exposure of unauthorized tools
- **Detection**: Attempted invocation of filtered tools logged as denied actions
- **Response**: Security team investigation of repeated escalation attempts

**Threat: Approval Bypass**
- **Mitigation**: Server-side enforcement of approval requirements
- **Detection**: All approval decisions logged with full context
- **Response**: Configuration audit and user training

**Threat: Audit Log Tampering**
- **Mitigation**: Immutable log forwarding to SIEM
- **Detection**: Log integrity checks and correlation ID validation
- **Response**: Forensic investigation and log restoration

**Threat: Session Hijacking**
- **Mitigation**: Secure session token storage and transport
- **Detection**: Session activity monitoring for anomalies
- **Response**: Session termination and user notification

### Compliance Alignment

**SOC 2 Type II**:
- **Access Control**: OIDC authentication with enterprise identity
- **Audit Logging**: Comprehensive structured logs with human attribution
- **Change Management**: Approval gates for sensitive operations

**GDPR**:
- **Data Minimization**: Logs contain only necessary identity information
- **Right to Erasure**: Log retention policies and user data deletion procedures
- **Audit Trail**: Complete traceability for data access and modifications

**HIPAA**:
- **Access Control**: Role-based access through Vault policies
- **Audit Controls**: Detailed logging of all PHI access attempts
- **Integrity Controls**: Approval gates prevent unauthorized modifications

### Secrets Management

**OIDC Client Secret**:
- Stored in environment variable, not configuration file
- Rotated quarterly through automated process
- Access restricted to MCP server process only

**Vault Token Storage**:
- Stored in memory only, never persisted to disk
- Encrypted in transit using TLS
- Cleared on session termination

**Session Tokens**:
- Generated using cryptographically secure random number generator
- 256-bit entropy minimum
- Invalidated on logout or timeout

## Performance Considerations

### Latency Budget

**Authentication Flow**: < 2 seconds end-to-end
- OIDC redirect: 500ms
- JWT exchange: 300ms
- Vault token generation: 200ms
- Permission evaluation: 500ms
- Session establishment: 500ms

**Tool Invocation**: < 100ms overhead
- Permission validation: 10ms (cached)
- Approval check: 5ms
- Audit logging: 20ms
- Vault API call: 50ms (variable)
- Response processing: 15ms

**Permission Evaluation**: < 500ms for initial evaluation
- Policy parsing: 100ms
- Capability matrix building: 200ms
- Tool filtering: 100ms
- Cache population: 100ms

### Scalability Targets

**Concurrent Sessions**: 1,000 simultaneous users per server instance
**Tool Invocations**: 10,000 requests per second per instance
**Audit Log Throughput**: 50,000 log entries per second
**Permission Cache Size**: 10,000 cached evaluations per instance

### Resource Requirements

**Memory**: 512MB base + 1MB per active session
**CPU**: 2 cores minimum, 4 cores recommended
**Disk**: 10GB for logs (with rotation)
**Network**: 100Mbps minimum bandwidth

### Optimization Strategies

**Permission Caching**:
- Cache evaluation results for 5 minutes
- Invalidate on policy changes or token refresh
- LRU eviction for cache size management

**Batch Operations**:
- Batch capability queries to Vault
- Aggregate audit logs before writing
- Batch session state updates

**Connection Pooling**:
- Maintain persistent connections to Vault
- Connection pool size: 10-50 connections
- Connection reuse for multiple requests

## Backwards Compatibility

### Breaking Changes

**Authentication Requirement**:
- **Change**: OIDC authentication now required before session establishment
- **Impact**: Existing deployments using static tokens will break
- **Migration**: Platform engineers must configure OIDC and JWT auth method
- **Timeline**: 3-month deprecation period for static token support

**Tool Filtering**:
- **Change**: Tools are filtered based on user permissions
- **Impact**: Users may see fewer tools than before
- **Migration**: Review and update Vault policies to grant necessary capabilities
- **Timeline**: Immediate, no migration path for unfiltered access

**Approval Requirements**:
- **Change**: Sensitive operations require explicit approval
- **Impact**: Workflows requiring sensitive operations will prompt for approval
- **Migration**: Configure approval bypass for specific tools if needed
- **Timeline**: Immediate, configurable per deployment

### Migration Path

**Phase 1: Parallel Operation** (Month 1)
- Deploy new MCP server version alongside existing version
- Configure OIDC authentication for new version
- Test authentication and permission filtering with pilot users
- Validate audit logging and approval flows

**Phase 2: User Migration** (Month 2)
- Migrate users in waves (10% → 50% → 100%)
- Provide migration documentation and support
- Monitor for authentication issues and permission gaps
- Adjust policies based on user feedback

**Phase 3: Deprecation** (Month 3)
- Announce deprecation of static token support
- Provide final migration deadline
- Disable static token authentication
- Decommission old MCP server version

### Configuration Compatibility

**Old Configuration Format**:
```yaml
vault:
  address: https://vault.example.com
  token: s.abc123xyz789
```

**New Configuration Format**:
```yaml
vault:
  address: https://vault.example.com
  jwt_auth_path: auth/jwt
auth:
  method: oidc
  oidc_discovery_url: https://idp.example.com/.well-known/openid-configuration
  client_id: vault-mcp-server
```

**Migration Tool**:
Provide CLI tool to convert old configuration to new format:

```bash
vault-mcp-server migrate-config \
  --old-config vault-mcp-server-old.yaml \
  --new-config vault-mcp-server-new.yaml \
  --oidc-discovery-url https://idp.example.com/.well-known/openid-configuration \
  --client-id vault-mcp-server
```

## Testing Strategy

### Unit Testing

**Authentication Manager**:
- OIDC flow with valid credentials
- OIDC flow with invalid credentials
- JWT token exchange success and failure
- Token refresh and expiration handling
- Session state transitions

**Permission Evaluator**:
- Capability matrix building from policies
- Tool filtering with various permission sets
- Cache hit and miss scenarios
- Dynamic permission updates
- Edge cases (empty policies, wildcard paths)

**Approval Gateway**:
- Approval prompt generation
- User approval and denial handling
- Timeout scenarios
- Approval bypass configuration
- Concurrent approval requests

**Audit Logger**:
- Structured log emission
- Vault audit context enrichment
- Correlation ID generation and propagation
- Denied action logging
- Log rotation and retention

### Integration Testing

**End-to-End Authentication**:
- Complete OIDC flow with Okta
- Complete OIDC flow with Azure AD
- Complete OIDC flow with Auth0
- JWT exchange with Vault
- Session establishment and tool exposure

**Permission Evaluation**:
- Complex policy sets with multiple namespaces
- Dynamic policy updates during session
- Tool filtering with various capability combinations
- Permission cache invalidation
- Concurrent permission evaluations

**Approval Flows**:
- Sensitive operation with approval
- Sensitive operation with denial
- Sensitive operation with timeout
- Multiple concurrent approval requests
- Approval bypass configuration

**Audit Correlation**:
- MCP log and Vault audit log correlation
- Correlation ID propagation across systems
- Denied action logging without Vault interaction
- Log aggregation and SIEM integration

### Security Testing

**Authentication Security**:
- Token theft and replay attacks
- Session hijacking attempts
- OIDC redirect manipulation
- JWT signature validation
- Token expiration enforcement

**Authorization Security**:
- Permission filter bypass attempts
- Tool invocation without authentication
- Capability escalation attempts
- Namespace boundary violations
- Policy evaluation bypass

**Approval Security**:
- Approval gateway bypass attempts
- Approval decision tampering
- Timeout manipulation
- Concurrent approval race conditions
- Approval replay attacks

### Performance Testing

**Load Testing**:
- 1,000 concurrent sessions
- 10,000 tool invocations per second
- 50,000 audit log entries per second
- Permission evaluation under load
- Token refresh under load

**Stress Testing**:
- Gradual load increase to failure point
- Sustained high load for 24 hours
- Memory leak detection
- Connection pool exhaustion
- Audit log backpressure handling

**Scalability Testing**:
- Horizontal scaling with multiple instances
- Load balancing across instances
- Session affinity and failover
- Distributed caching coordination
- Multi-region deployment

## Rollout Plan

### Phase 1: Internal Dogfooding (Weeks 1-2)

**Participants**: HashiCorp engineering teams (10-20 users)
**Goals**:
- Validate authentication flows with HashiCorp's OIDC provider
- Test permission filtering with real Vault policies
- Gather feedback on approval UX
- Identify performance bottlenecks

**Success Criteria**:
- 100% authentication success rate
- Zero permission escalation incidents
- < 100ms tool invocation overhead
- Positive user feedback on approval UX

### Phase 2: Design Partner Beta (Weeks 3-6)

**Participants**: 3-5 enterprise customers (50-100 users total)
**Goals**:
- Validate OIDC integration with diverse identity providers
- Test permission filtering with complex enterprise policies
- Gather feedback on operator visibility tools
- Validate audit log correlation with customer SIEM systems

**Success Criteria**:
- 95% authentication success rate across all providers
- Zero security incidents or permission bypasses
- Positive feedback from platform engineers on visibility tools
- Successful audit log integration with at least 2 SIEM systems

**Support Model**:
- Dedicated Slack channel for beta participants
- Weekly office hours with engineering team
- 24-hour response time for critical issues
- Monthly feedback sessions

### Phase 3: Public Beta (Weeks 7-10)

**Participants**: Open to all Vault Enterprise customers
**Goals**:
- Scale testing with hundreds of users
- Validate performance under production load
- Gather broad feedback on feature completeness
- Identify edge cases and compatibility issues

**Success Criteria**:
- 98% authentication success rate
- < 100ms tool invocation overhead at scale
- Zero critical security vulnerabilities
- 80% positive feedback on overall experience

**Communication**:
- Beta announcement blog post
- Documentation and migration guides
- Video tutorials and webinars
- Community forum for support

### Phase 4: General Availability (Week 11+)

**Release**:
- Full production release for all Vault Enterprise customers
- Complete documentation and migration guides
- Training materials and certification updates
- Support team training and runbooks

**Success Metrics**:
- 3 customers adopt MCP server within first quarter (per PRD KPI)
- 99% authentication success rate
- < 50ms tool invocation overhead
- Zero critical security vulnerabilities in first 90 days

## Monitoring and Observability

### Key Metrics

**Authentication Metrics**:
- Authentication success rate (target: 99%)
- Authentication latency (target: < 2s)
- Token refresh success rate (target: 99.9%)
- Session establishment rate
- Authentication failure reasons (invalid credentials, expired tokens, etc.)

**Authorization Metrics**:
- Permission evaluation latency (target: < 10ms)
- Permission cache hit rate (target: > 90%)
- Tool filtering accuracy (zero false positives)
- Authorization denial rate by user and tool
- Permission escalation attempts

**Approval Metrics**:
- Approval request rate by tool
- Approval decision distribution (approved, denied, timeout)
- Approval latency (time to user decision)
- Approval bypass usage
- Timeout rate by tool

**Audit Metrics**:
- Audit log emission rate
- Audit log latency (target: < 20ms)
- Correlation ID propagation success rate (target: 100%)
- Denied action logging coverage
- Log aggregation lag

**Performance Metrics**:
- Tool invocation latency (target: < 100ms overhead)
- Concurrent session count
- Request throughput (requests per second)
- Memory usage per session
- CPU utilization

### Alerting

**Critical Alerts**:
- Authentication success rate < 95% for 5 minutes
- Authorization bypass detected
- Audit log emission failure
- Session hijacking detected
- Memory usage > 90% for 10 minutes

**Warning Alerts**:
- Authentication latency > 5s for 5 minutes
- Permission cache hit rate < 80% for 10 minutes
- Approval timeout rate > 20% for 15 minutes
- Audit log lag > 1 minute
- CPU utilization > 80% for 15 minutes

**Informational Alerts**:
- New user first authentication
- Permission policy changes detected
- Approval pattern anomalies
- Unusual tool usage patterns
- Session count milestones

### Dashboards

**Operator Dashboard**:
- Active sessions count and list
- Real-time tool invocation rate
- Authentication success rate (24h)
- Top users by tool invocations
- Recent denied actions

**Security Dashboard**:
- Authentication failure reasons
- Authorization denial patterns
- Approval decision distribution
- Permission escalation attempts
- Anomalous user behavior

**Performance Dashboard**:
- Tool invocation latency (p50, p95, p99)
- Authentication latency (p50, p95, p99)
- Permission evaluation latency
- Memory and CPU utilization
- Request throughput

## Documentation Requirements

### User Documentation

**Getting Started Guide**:
- Prerequisites (Vault version, OIDC provider)
- Installation and configuration
- First authentication and session establishment
- Basic tool usage examples
- Troubleshooting common issues

**Configuration Reference**:
- Complete configuration schema
- Configuration examples for common scenarios
- Environment variable reference
- Security best practices
- Performance tuning guide

**User Guide**:
- Authentication and session management
- Understanding tool filtering
- Approval workflow and best practices
- Reading audit logs
- Common workflows and examples

### Operator Documentation

**Deployment Guide**:
- System requirements and architecture
- Installation procedures
- OIDC provider configuration
- Vault JWT auth method setup
- High availability and scaling

**Operations Guide**:
- Monitoring and alerting setup
- Log aggregation and SIEM integration
- Backup and disaster recovery
- Upgrade procedures
- Troubleshooting runbook

**Security Guide**:
- Threat model and mitigations
- Security best practices
- Compliance alignment (SOC 2, GDPR, HIPAA)
- Incident response procedures
- Security audit checklist

### Developer Documentation

**Architecture Documentation**:
- System architecture and component interactions
- Authentication flow diagrams
- Permission evaluation algorithm
- Approval gateway design
- Audit logging architecture

**API Reference**:
- MCP protocol extensions
- Visibility API endpoints
- Configuration API
- Webhook integration
- Custom tool development

**Integration Guide**:
- OIDC provider integration
- SIEM integration
- Custom MCP client development
- Vault plugin integration
- Monitoring system integration

## Success Criteria

### Milestone 1 Success Criteria

**Functional Requirements**:
- ✅ OIDC authentication with 3+ identity providers (Okta, Azure AD, Auth0)
- ✅ Pre-tool filtering based on Vault policies and namespace access
- ✅ Safety-first operation mode with approval gates for sensitive operations
- ✅ Audit-first traceability in both MCP and Vault logs
- ✅ Operator visibility tools for usage monitoring

**Non-Functional Requirements**:
- ✅ Authentication latency < 2 seconds
- ✅ Tool invocation overhead < 100ms
- ✅ Support 1,000 concurrent sessions per instance
- ✅ 99% authentication success rate
- ✅ Zero critical security vulnerabilities

**Business Requirements**:
- ✅ 3 customers adopt MCP server within first quarter (per PRD KPI)
- ✅ Positive qualitative feedback on overall experience
- ✅ Positive qualitative feedback on controls and features
- ✅ Zero security incidents in first 90 days
- ✅ Documentation and training materials complete

### Acceptance Testing

**Authentication Acceptance**:
- User authenticates with valid enterprise credentials → session established
- User authenticates with invalid credentials → session denied
- User's Vault policies determine tool exposure → correct tools shown
- Token expires during session → automatic refresh or re-authentication prompt

**Authorization Acceptance**:
- User with read-only access → only read tools exposed
- User with write access → read and write tools exposed
- User attempts unauthorized tool → request denied and logged
- User's permissions change → tool list updates dynamically

**Approval Acceptance**:
- User invokes sensitive operation → approval prompt shown
- User approves operation → operation executes and logs
- User denies operation → operation blocked and logged
- User ignores prompt → operation times out and logs

**Audit Acceptance**:
- User invokes tool → MCP log emitted with full context
- MCP server calls Vault → Vault audit log includes correlation ID
- User denied access → denial logged in MCP logs
- Logs aggregated to SIEM → correlation ID enables end-to-end tracing

## Future Enhancements

### Milestone 2: Agent-Scoped Permissions

**Goal**: Enable fine-grained permission scoping for different agent types beyond user identity.

**Capabilities**:
- Agent registry integration for agent validation
- Agent-specific permission ceilings independent of user permissions
- Agent classification (read-only agent, write-enabled agent, admin agent)
- Dynamic agent permission adjustment based on behavior

**Use Case**: Platform engineer wants to allow a monitoring agent read-only access to secrets even when the user has write permissions, preventing accidental modifications.

### Milestone 3: Human-in-the-Loop (HITL) Approval Workflows

**Goal**: Extend approval system to support multi-party approval and external approval systems.

**Capabilities**:
- Multi-party approval (require 2+ approvers for critical operations)
- External approval system integration (ServiceNow, Jira)
- Approval delegation and escalation
- Approval audit trail with approver identity

**Use Case**: Security team requires two approvers for production secret deletions, with approval requests routed through ServiceNow.

### Milestone 4: Response Wrapping for In-Context Secrets

**Goal**: Provide time-limited, single-use secret access through response wrapping.

**Capabilities**:
- Automatic response wrapping for secret reads
- Configurable TTL for wrapped responses
- Single-use token enforcement
- Wrapped response audit logging

**Use Case**: Agent retrieves database credentials wrapped with 5-minute TTL, ensuring credentials are only accessible within the agent's execution context.

### Milestone 5: Risk-Based Tool Classification

**Goal**: Automatically classify tools by risk level and adjust approval requirements dynamically.

**Capabilities**:
- Risk scoring algorithm based on operation type, path sensitivity, and user history
- Dynamic approval requirements based on risk score
- Risk-based rate limiting
- Anomaly detection and automatic risk elevation

**Use Case**: System detects unusual pattern of secret deletions and automatically elevates approval requirements for that user.

### Milestone 6: Multi-Tenant MCP Server

**Goal**: Support shared MCP server deployment with tenant isolation.

**Capabilities**:
- Tenant-scoped authentication and authorization
- Tenant-specific configuration and policies
- Resource isolation and quotas
- Cross-tenant audit log separation

**Use Case**: Managed service provider operates single MCP server instance serving multiple customer tenants with complete isolation.

## Conclusion

This RFC establishes the foundation for enterprise-grade Vault MCP Server adoption through comprehensive authentication, authorization, and audit capabilities. The proposed solution addresses the critical security and governance gaps that currently prevent enterprise customers from adopting AI-assisted Vault workflows.

The implementation delivers immediate value through Milestone 1 while establishing an architecture that supports future enhancements for agent-scoped permissions, advanced approval workflows, and multi-tenant deployments. The success criteria align with the PRD's goal of enabling 3 customers to adopt MCP server within the first quarter while building the foundation for broader enterprise adoption.

The security-first approach, comprehensive audit capabilities, and operator visibility tools provide the governance framework necessary for enterprise compliance requirements while maintaining the natural interaction model that makes AI-assisted workflows valuable. This positions HashiCorp to lead the market in secure AI integration patterns for infrastructure and secrets management.