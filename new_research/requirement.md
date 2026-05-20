This PRD outlines authentication improvements to the Vault MCP server to make it more secure for customers to adopt it for single-user use-cases. As AI-assisted workflows scale, this version requires users to authenticate via OIDC.

Background

Problems

Currently, the Vault MCP Server lacks critical capabilities for it to be adopted by Vault Enterprise customers such as better identity and access management controls on when to use MCP vs other interfaces.

Identity & Access Management Controls

Reliance on static, long-lived tokens is insecure. Most critically at the very least, customers need to ensure the agents are operating within a specific user’s session. Without this, there is no way to prevent an agent from inheriting broader permissions than intended, leading to potential unauthorized access or bad actor scenarios.

Given the dynamic nature of agents and a focus on completing their objective, it’s also important to provide the capabilities to validate the agent in the customer environment’s agent registry, scoping the permissions for the agent, defining ceiling permissions, and finally enabling or leveraging HITL (human-in-the-loop) patterns.


Persona, CUJ & JTBD

Platform Engineer / Vault Operator

When enabling AI-assisted workflows to interact with Vault, I want the Vault MCP Server to authenticate the user through enterprise identity and expose only the tools that user is authorized to use, so that I can allow adoption without giving agents broad static credentials or creating unclear authorization boundaries.

CUJs

Platform Engineer / Vault Operator can:

Configure OIDC-based authentication for Vault MCP Server so that users authenticate with enterprise identity rather than static Vault tokens.

Security / Compliance Stakeholder can:

Confirm that all MCP-originated Vault actions are attributable to a human identity.

Milestones & Requirements

Milestones

Requirements

M1: Local Mode Execution for Platform Engineer Visibility with OIDC Controls & Auditability

OIDC-based authentication

Future Milestones

Scoping Agent Permissions

Rotating or Dynamic Secret Creation Tools

HITL Approval for Sensitive Write Operations

In-Context Secret Window via Response Wrapping

Risk Level Classification on Tool Metadata

Milestone 1: Local Mode Execution for Platform Engineer Visibility with OIDC Controls & Auditability

Platform engineers must be able to deploy Vault MCP Server for a single-user, local execution model in which the user authenticates with enterprise identity, the server exposes only authorized tools, sensitive operations are gated by explicit approval, and all activity is traceable in both Vault audit logs and MCP server logs.

Hypothesis Outcomes & KPIs

Hypothesis 1

Within the quarter after Milestone 1 is released, 3 customers are willing to use Vault MCP Server for single-user, local AI-assisted workflows.


Requirement 1

The system shall require users to authenticate to Vault MCP Server through OIDC-based authentication that will generate the JWT token before establishing an MCP session, and the authenticated user’s access permissions in Vault shall be determined by the Vault policies applicable to the JWT token provided via the OIDC exchange and correspondingly the Vault token is generated.

Acceptance Criteria

Positive test: Given a user with valid enterprise identity access and an applicable Vault policy set, when the user initiates a Vault MCP Server session, then the server completes OIDC authentication, JWT token exchange for a Vault Token and establishes the session using that authenticated user identity.

Positive test: Given a successfully authenticated user, when the MCP session starts, then the server associates the session with the authenticated subject and all downstream authorization is based on the Vault policies applicable to that user.

Negative test: Given a user with invalid or expired identity credentials, when the user attempts to start a session, then the server denies session establishment.

Negative test: Given no completed OIDC authentication flow, when an MCP client attempts to access tools, then the server does not expose tools or permit requests.

Considerations

Milestone 1 likely requires the customer to enable the JWT auth method in Vault to support this identity flow, but this dependency should be confirmed with engineering.

Note: Currently, the MCP server will be hosted stdio or http mode and will be hosted locally and operate on a per-user basis rather than a per-tenant model. Each user will host and manage their own MCP instance. The agent will impersonate the authenticated user while performing actions and accessing resources. We will focus on leveraging OIDC/JWT authentication with Vault as the primary authentication mechanism. The Vault token returned as part of the authentication flow will then be used to complete subsequent authentication and authorization operations.