# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a security issue, email the maintainer directly or open a [GitHub Security Advisory](https://github.com/malrobust/KIMONO/security/advisories/new).

Include:
- A clear description of the vulnerability
- Steps to reproduce or a minimal proof of concept
- The version(s) affected
- Any suggested mitigations

You will receive an acknowledgement within **48 hours** and a resolution timeline within **7 days**.

## Security Design

Kimono is itself a security library. Its threat model and design guarantees are:

- **Zero LLM calls in the enforcement path.** Trust decisions are deterministic Python code — no model can be socially-engineered into bypassing them.
- **Fail-secure by default.** Content not registered in the taint registry is treated as trust score `0`.
- **Minimum-trust propagation.** One untrusted ingredient taints an entire action, regardless of the number of trusted sources also present.
- **No external network calls.** Kimono makes no outbound requests at runtime.

## Known Non-Goals

Kimono is **not** a replacement for:
- Transport-layer security (TLS, encryption at rest)
- Authentication / authorization systems
- Input sanitization for HTML/SQL injection

It operates strictly at the **agentic action-gating layer**.
