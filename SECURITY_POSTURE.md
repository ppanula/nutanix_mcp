# nutanix-mcp Security Posture

This document summarizes current security controls, intended operating model, and known boundaries.

## Security goals

- Keep Prism Element, Prism Central, and Move interactions read-only.
- Prevent accidental API surface expansion by future tool changes.
- Reduce abuse risk from high-rate or high-concurrency tool execution.
- Keep credentials in OS keyring storage only.

## Implemented controls

### 1. Central policy engine for API access

The client layer enforces centralized request policy for:

- Allowed endpoint families for Prism Element, Prism Central, and Move APIs.
- Allowed query parameter keys by API family.
- Rejection of malformed paths with query fragments embedded in path strings.

Any request outside policy is rejected before network I/O.

### 2. Read-only GET request model

All client helpers issue GET requests only and policy is built for read-only query patterns.

Why this matters:
- Prevents broadening into action-style endpoints through generic HTTP helpers.

### 3. Sanitized upstream error propagation

Client errors expose only high-level HTTP status details and avoid returning raw response bodies.

Why this matters:
- Reduces leakage of internal infrastructure details into MCP tool output.

### 4. Keyring-only credential ingestion

Credential lookup now uses OS keyring data only.

- Removed environment variable credential fallback.
- Added basic validation for stored values.

Why this matters:
- Reduces accidental credential injection/exposure through process environment.

### 5. Per-tool concurrency caps

Every MCP tool is wrapped with a guard that enforces a maximum number of concurrent executions.

Why this matters:
- Limits accidental overload and reduces abuse potential.

### 6. Per-tool rate limiting

Every MCP tool is rate-limited using a one-minute window.

Why this matters:
- Limits rapid prompt-loop enumeration and excessive API pressure.

### 7. Per-tool request timeout control

HTTP timeout is bound by active tool policy and cannot exceed configured limits.

Why this matters:
- Prevents long-running requests from monopolizing runtime capacity.

### 8. Validated config loaded once at startup

A validated security config object is loaded once during startup.

Supported environment controls:

- NUTANIX_MCP_REQUEST_TIMEOUT_SECONDS
- NUTANIX_MCP_TOOL_CONCURRENCY_LIMIT
- NUTANIX_MCP_RATE_LIMIT_PER_MINUTE
- NUTANIX_MCP_TOOL_POLICY_OVERRIDES (JSON object keyed by tool name)

Why this matters:
- Misconfiguration fails fast at startup.
- Runtime behavior remains centralized and deterministic.

## TLS rationale and caution

verify_ssl remains configurable per credential entry because many enterprise Nutanix environments use private CA or self-signed certificates.

- verify_ssl=true gives strongest MITM protection and server identity verification.
- verify_ssl=false improves compatibility in environments that are not PKI-ready.

Security caution:

- Using verify_ssl=false reduces transport authenticity guarantees and should be treated as explicit risk acceptance.
- Prefer trusted internal CA deployment whenever feasible.

## Keyring access boundary disclaimer

The MCP server process must read keyring credentials to authenticate to Nutanix endpoints. During execution, credentials exist in process memory.

Important boundary:

- Preventing all host-level secret access is outside application scope.
- Any principal able to run arbitrary local commands as the same OS user may still access local secrets.

Operational recommendation:

- Run nutanix-mcp under a least-privilege user context on a trusted workstation or jump host.

## Remaining cautions

- Rate limits and concurrency caps reduce risk but are not a complete anti-abuse system.
- This hardening step does not add SIEM/audit logging pipelines.
- Endpoint allowlists are intentionally strict and may require updates when adding new tools.

## Production usage guidance

- Use read-only service accounts with minimum required Nutanix RBAC.
- Limit network reachability from MCP host to approved Prism/Move endpoints only.
- Tune tool policy overrides conservatively in shared environments.
- Periodically review inventory entries and remove stale endpoints.

## Disclaimer

This is a community-maintained project and not an official Nutanix product. Operators remain responsible for validating controls against internal policy and compliance requirements.
