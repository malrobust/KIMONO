# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-06-19

First public release on PyPI as **`toride`** (`pip install toride`, import `toride`).

### Added
- **`toride.provenance`** — `Source` enum (`USER`, `SYSTEM`, `TOOL_OUTPUT`, `WEB_FETCH`, `FILE_READ`, `EMAIL`) and `TaggedContent` dataclass with deterministic trust scores.
- **`toride.taint`** — `TaintRegistry` for tracking content lineage and computing minimum-trust taint scores recursively across derivation chains.
- **`toride.policy`** — `PolicyEngine` with pluggable `Rule` objects; default hard-block for tainted `credential_use` and `REQUIRE_APPROVAL` for risky actions (`shell_exec`, `code_exec`, `file_write`, `network_call`, `email_send`).
- **`toride.guard`** — `AgentGuard` central integration point providing `.ingest()` and `.check_action()` with full audit logging.
- **`toride.fuzzer`** — `run_fuzz_test()` with 6 real-world prompt injection payloads (direct override, fake system tags, HTML comments, base64 encoding, zero-width unicode, social engineering).
- **`toride.report`** — JSON, Markdown, and PDF (optional `reportlab`) report generation.
- **`toride.cli`** — `toride-fuzz` command-line tool to stress-test agent decision functions.
- **`toride.integrations.langgraph_adapter`** — `LangGraphAgentGuardAdapter`, `guard_tool` decorator, and `RequireApprovalError` for LangGraph/LangChain pipelines.
- 10 unit tests covering provenance defaults, taint propagation, policy evaluation, guard gating, and fuzzer classification.
- CI matrix across Python 3.9–3.12 with ruff linting and mypy strict type checking.
- Automated PyPI publishing on version tags via OIDC trusted publishing.

[0.1.0]: https://github.com/malrobust/TORIDE/releases/tag/v0.1.0
