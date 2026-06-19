"""
Extended tests for AgentGuard: audit log, custom policy engine,
edge cases (empty source_ids, unknown ids), and export API.
"""

import pytest

from toride import AgentGuard, BlockedActionError, Decision, Source
from toride.policy import PolicyEngine
from toride.provenance import TaggedContent


def test_agent_guard_ingest_and_check():
    guard = AgentGuard()

    # Ingest clean user input
    t1 = guard.ingest(content="safe instruction", source=Source.USER)
    assert t1.trust_score == 100

    # Check safe action (fully trusted context)
    dec = guard.check_action("shell_exec", "echo 1", [t1.id])
    assert dec == Decision.ALLOW

    # Ingest untrusted content (web fetch)
    t2 = guard.ingest(content="untrusted instructions", source=Source.WEB_FETCH)
    assert t2.trust_score == 0

    # Credential use must be blocked when taint score < 100
    with pytest.raises(BlockedActionError) as exc_info:
        guard.check_action("credential_use", "AWS_KEY", [t1.id, t2.id])
    assert "strictly prohibited" in str(exc_info.value)

    # Risky action with untrusted content requires approval
    dec2 = guard.check_action("shell_exec", "cat /etc/passwd", [t1.id, t2.id])
    assert dec2 == Decision.REQUIRE_APPROVAL

    # Check audit log
    assert len(guard.audit_log) == 3
    assert guard.audit_log[0]["decision"] == "ALLOW"
    assert guard.audit_log[1]["decision"] == "BLOCK"
    assert guard.audit_log[2]["decision"] == "REQUIRE_APPROVAL"


def test_guard_raises_on_block():
    """AgentGuard.check_action raises BlockedActionError for BLOCK decisions."""
    guard = AgentGuard()
    t = guard.ingest("web stuff", source=guard.Source.WEB_FETCH)
    try:
        guard.check_action("credential_use", "SECRET", [t.id])
        raise AssertionError("Expected BlockedActionError")
    except BlockedActionError as e:
        assert "credential_use" in str(e)


def test_audit_log_records_taint_score():
    guard = AgentGuard()
    t = guard.ingest(content="web data", source=Source.WEB_FETCH)
    guard.check_action("shell_exec", "ls", [t.id])

    entry = guard.audit_log[0]
    assert "taint_score" in entry
    assert entry["taint_score"] == 0
    assert entry["action_type"] == "shell_exec"


def test_empty_source_ids_is_fully_trusted():
    """No source IDs → taint score 100 → clean action passes."""
    guard = AgentGuard()
    dec = guard.check_action("shell_exec", "echo hi", [])
    assert dec == Decision.ALLOW


def test_unknown_source_id_fails_secure():
    """An unregistered ID should be treated as trust 0."""
    guard = AgentGuard()
    dec = guard.check_action("shell_exec", "whoami", ["ghost-id"])
    # Trust 0 → risky action requires approval
    assert dec == Decision.REQUIRE_APPROVAL


def test_ingest_with_explicit_trust_score():
    guard = AgentGuard()
    t = guard.ingest(content="partial", source=Source.WEB_FETCH, trust_score=60)
    assert t.trust_score == 60


def test_ingest_with_parent_ids_inherits_taint():
    guard = AgentGuard()
    bad = guard.ingest(content="evil web page", source=Source.WEB_FETCH)
    good = guard.ingest(content="ai summary", source=Source.SYSTEM, parent_ids=[bad.id])

    # The good message's taint should be pulled down to 0 by its parent
    dec = guard.check_action("shell_exec", "id", [good.id])
    assert dec == Decision.REQUIRE_APPROVAL


def test_custom_policy_engine_threshold():
    """A lower threshold means more actions pass without approval."""
    engine = PolicyEngine(taint_threshold=0, default_decision=Decision.ALLOW)
    guard = AgentGuard(policy_engine=engine)

    t = guard.ingest(content="web page", source=Source.WEB_FETCH)
    # With threshold=0, taint_score(0) is NOT below 0, so risky rule doesn't fire
    dec = guard.check_action("shell_exec", "ls", [t.id])
    assert dec == Decision.ALLOW


def test_credential_use_always_blocked_regardless_of_threshold():
    """Hard-block for credential_use must hold even at threshold=0."""
    engine = PolicyEngine(taint_threshold=0, default_decision=Decision.ALLOW)
    guard = AgentGuard(policy_engine=engine)

    t = guard.ingest(content="web page", source=Source.WEB_FETCH)
    with pytest.raises(BlockedActionError):
        guard.check_action("credential_use", "TOKEN", [t.id])


def test_multiple_ingests_accumulate_in_registry():
    guard = AgentGuard()
    ids = [guard.ingest(f"msg {i}", source=Source.USER).id for i in range(10)]
    assert len(ids) == len(set(ids))  # all IDs are unique


def test_ingest_tagged_content_directly():
    """AgentGuard.ingest should accept a pre-built TaggedContent."""
    guard = AgentGuard()
    tc = TaggedContent(content="raw obj", source=Source.FILE_READ)
    result = guard.ingest_tagged(tc)
    assert result.id == tc.id
    assert result.trust_score == 10  # FILE_READ default
