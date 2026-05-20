This PRD outlines authentication and traceability improvements to the Vault MCP server to make it more secure for customers to adopt it for single-user use-cases. As AI-assisted workflows scale, this version requires users to authenticate via OIDC, dynamically hiding unauthorized tools based on user permissions, and ensuring every interaction is captured in the MCP and Vault logs to provide governance.  

Background 

Vault has a massive surface area as a product and feature set, and customers use it in materially different ways depending on their platform architecture, security model, and operating practices. That breadth is reflected across Vault’s UI, CLI, Terraform provider, and API. As Vault evolves, we are making the product experience more opinionated so users can adopt Vault in ways that are easier to operate, easier to govern, and more aligned with recommended patterns rather than treating Vault as only a generic set of primitives. 

The rise of AI-assisted workflows creates a similar need for a secure and opinionated interaction model for agents. Different types of agents should be able to work with Vault through MCP in a way that feels natural, but also respects enterprise security boundaries and guides usage toward safer patterns. Vault’s API remains comprehensive but complex; exposing that raw surface area directly to agents would create usability, governance, and safety risks. 

Problems 

Currently, the Vault MCP Server lacks critical capabilities for it to be adopted by Vault Enterprise customers such as better identity and access management controls, auditability of agent intent and actions, and opinionated guidance on when to use MCP vs other interfaces.  

Identity & Access Management Controls 

Reliance on static, long-lived tokens is insecure. Most critically at the very least, customers need to ensure the agents are operating within a specific user’s session. Without this, there is no way to prevent an agent from inheriting broader permissions than intended, leading to potential unauthorized access or bad actor scenarios. 

Given the dynamic nature of agents and a focus on completing their objective, it’s also important to provide the capabilities to validate the agent in the customer environment’s agent registry, scoping the permissions for the agent, defining ceiling permissions, and finally enabling or leveraging HITL (human-in-the-loop) patterns.  

Agent Traceability  

Providing clear traceability of interactions with the MCP Server as well as Vault in the logs is critical. This includes the source identity (entity), source agent, the actual action being intended as well as the performed and the corresponding timestamp.  

Providing this information in real time during the session back to the user can also help in verification of the agent actions.  

Guided Usage  

Currently, the agent functions as a generic interface rather than a specialized assistant. It lacks an Onboarding Patterns Library (Skills) to provide proactive instructions on how to use tools within the organizational framework. This prevents the agent from guiding users toward secure supported product usage patterns.  

Scalability 

Other additional key items for enterprise adoption are around scalability ensuring that a shared MCP server can support the right isolation patterns and support the scale of usage while interacting with Vault.  

Persona, CUJ & JTBD 

Platform Engineer / Vault Operator 

When enabling AI-assisted workflows to interact with Vault, I want the Vault MCP Server to authenticate the user through enterprise identity and expose only the tools that user is authorized to use, so that I can allow adoption without giving agents broad static credentials or creating unclear authorization boundaries. 

When introducing Vault MCP Server in my environment, I want write access to be disabled by default and sensitive operations to require explicit user confirmation, so that I can reduce blast radius while still allowing useful day-to-day workflows. 

When reviewing or troubleshooting MCP usage, I want Vault and MCP activity to be attributable to a real human identity and visible in logs, so that I can investigate behavior, satisfy audit needs, and build trust in the operational model. 

Security / Compliance Stakeholder 

When approving AI access to Vault, I want clear identity attribution and traceability for both attempted and completed actions, so that I can verify that the MCP model preserves operator control and supports compliance requirements. 

CUJs 

Platform Engineer / Vault Operator can: 

Configure OIDC-based authentication for Vault MCP Server so that users authenticate with enterprise identity rather than static Vault tokens. 

Verify that the MCP Server exposes only the tools permitted by the user’s Vault policies and namespace access. 

Enable MCP usage in read-only mode by default and selectively allow sensitive operations only with user confirmation. 

Review Vault audit data and MCP server logs to understand who initiated an action, what was attempted, and what was executed or blocked. 

Security / Compliance Stakeholder can: 

Confirm that all MCP-originated Vault actions are attributable to a human identity. 

Review structured logs and audit records for successful actions, denied actions, and blocked access attempts. 

 

Milestones & Requirements 

Milestones 

Requirements 

M1: Local Mode Execution for Platform Engineer Visibility with OIDC Controls & Auditability 

OIDC-based authentication 

Audit-First / Traceability in Vault audit logs and MCP server logs 

Operator Visibility Tools 

Pre-Tool Filtering based on effective Vault permissions and namespace access 

Safety-first gating for sensitive operations 

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

Supporting KPI 

Qualitative customer feedback on the overall Vault MCP Server experience. 

Qualitative customer feedback on additional tools, controls, or features needed for broader adoption. 

Requirement 1 

The system shall require users to authenticate to Vault MCP Server through OIDC-based authentication that will generate the JWT token before establishing an MCP session, and the authenticated user’s access permissions in Vault shall be determined by the Vault policies applicable to the JWT token provided via the OIDC exchange and correspondingly the Vault token is generated.  

Acceptance Criteria 

Positive test: Given a user with valid enterprise identity access and an applicable Vault policy set, when the user initiates a Vault MCP Server session, then the server completes OIDC authentication, JWT token exchange for a Vault Token and establishes the session using that authenticated user identity. 

Positive test: Given a successfully authenticated user, when the MCP session starts, then the server associates the session with the authenticated subject and all downstream authorization is based on the Vault policies applicable to that user. 

Negative test: Given a user with invalid or expired identity credentials, when the user attempts to start a session, then the server denies session establishment. 

Negative test: Given no completed OIDC authentication flow, when an MCP client attempts to access tools, then the server does not expose tools or permit requests. 

Considerations 

Milestone 1 likely requires the customer to enable the JWT auth method in Vault to support this identity flow, but this dependency should be confirmed with engineering. 

Requirement 2 

The system shall implement Pre-Tool Filtering so that only tools authorized by the user’s effective Vault permissions and namespace access are exposed to the MCP client. 

Acceptance Criteria 

Positive test: Given a user with access to a defined set of Vault paths and namespaces, when the MCP session is initialized, then the server exposes only the tools permitted by those capabilities. 

Positive test: Given a user authorized for read operations but not write or delete operations on a path, when tools are listed, then the client receives only the tools consistent with the user’s effective capabilities. 

Negative test: Given a user lacking required capability or namespace access for a tool, when the tool list is generated, then that tool is omitted from the response. 

Negative test: Given a mismatch between requested tool scope and the user’s Vault permissions, when the client attempts invocation, then the server rejects the request even if the client attempts to bypass the filtered tool list. 

 

 

Requirement 3 

The system shall default Vault MCP Server to a safety-first operating mode in which sensitive write operations require an explicit configuration and explicit user approval before execution. 

Acceptance Criteria 

Positive test: Given a default Milestone 1 configuration, when a user starts a session, sensitive write operations are not executed without an explicit configuration and an explicit approval step.  

Positive test: Given a user requests a sensitive operation, has set the explicit configuration and confirms the prompt, then the server proceeds with execution and records the action. 

Negative test: Given a user declines approval for a sensitive operation, when the confirmation step is presented, then the operation is not executed. 

Negative test: Given no approval response is provided for a sensitive operation, when the request times out or is abandoned, then the server does not execute the operation. 

Requirement 4 

The system shall provide Audit-First / Traceability by recording human-attributable identity context for MCP-originated actions in Vault audit logs and structured MCP server logs. 

Acceptance Criteria 

Positive test: Given an authenticated MCP session, when the server makes a downstream Vault request, then the request includes audit context sufficient to attribute the action to the authenticated human user. 

Positive test: Given an incoming MCP JSON-RPC request, when the server processes it, then the MCP server emits a structured log containing the authenticated subject identity, requested action, result, and timestamp. 

Positive test: Given a blocked or denied action, when the request is evaluated, then the MCP server logs the attempted action and denial outcome even if the request never reaches Vault. 

Negative test: Given a request without verified user identity context, when the server would otherwise forward it downstream, then the request is rejected and not treated as an auditable authenticated action. 

Negative test: Given logging or audit enrichment is unavailable, when a request is processed, then the system must fail in a way that does not silently execute unaudited sensitive actions. 

Requirement 5 

The system shall provide operators with sufficient visibility to understand usage of Vault based on the current state of data.  

Note: Currently, the MCP server will be hosted stdio or http mode and operate on a per-user basis rather than a per-tenant model. Each user will host and manage their own MCP instance. The agent will impersonate the authenticated user while performing actions and accessing resources. We will focus on leveraging OIDC/JWT authentication with Vault as the primary authentication mechanism. The Vault token returned as part of the authentication flow will then be used to complete subsequent authentication and authorization operations.
