import pytest
from kimono import AgentGuard, Source, BlockedActionError, Decision

def test_agent_guard_ingest_and_check():
    guard = AgentGuard()
    
    # Ingest clean user input
    t1 = guard.ingest(content="safe instruction", source=Source.USER)
    assert t1.trust_score == 100
    
    # Check safe action
    dec = guard.check_action("shell_exec", "echo 1", [t1.id])
    assert dec == Decision.ALLOW
    
    # Ingest untrusted content (web fetch)
    t2 = guard.ingest(content="untrusted instructions", source=Source.WEB_FETCH)
    assert t2.trust_score == 0
    
    # Credential use must be blocked when taint score < 100 (which is 0 because of t2)
    with pytest.raises(BlockedActionError) as exc_info:
        guard.check_action("credential_use", "AWS_KEY", [t1.id, t2.id])
    assert "strictly prohibited" in str(exc_info.value)
    
    # Risky action with untrusted content requires approval
    dec2 = guard.check_action("shell_exec", "cat /etc/passwd", [t1.id, t2.id])
    assert dec2 == Decision.REQUIRE_APPROVAL
    
    # Check audit log length
    assert len(guard.audit_log) == 3
    assert guard.audit_log[0]["decision"] == "ALLOW"
    assert guard.audit_log[1]["decision"] == "BLOCK"
    assert guard.audit_log[2]["decision"] == "REQUIRE_APPROVAL"
