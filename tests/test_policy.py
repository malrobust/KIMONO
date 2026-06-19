"""
Extended tests for PolicyEngine: default rules, custom rules, rule ordering,
default_decision, and ALLOW path.
"""

from toride.guard import AgentGuard, BlockedActionError
from toride.policy import Action, Decision, PolicyEngine, Rule


def test_credential_use_blocked_when_tainted():
    engine = PolicyEngine()

    # Credential use hard-block rule: blocked if taint_score < 100
    action_cred_tainted = Action(
        type="credential_use", payload="API_KEY", taint_score=99
    )
    decision, reason = engine.evaluate(action_cred_tainted)
    assert decision == Decision.BLOCK
    assert "strictly prohibited" in reason

    action_cred_clean = Action(
        type="credential_use", payload="API_KEY", taint_score=100
    )
    decision, reason = engine.evaluate(action_cred_clean)
    assert decision == Decision.ALLOW


def test_risky_actions_require_approval_when_tainted():
    engine = PolicyEngine(taint_threshold=50)
    risky = ["shell_exec", "code_exec", "file_write", "network_call", "email_send"]

    for action_type in risky:
        action = Action(type=action_type, payload="...", taint_score=49)
        decision, _ = engine.evaluate(action)
        assert decision == Decision.REQUIRE_APPROVAL, (
            f"Expected REQUIRE_APPROVAL for {action_type}"
        )

    # At threshold, action should not trigger require_approval
    action_at_threshold = Action(type="shell_exec", payload="...", taint_score=50)
    decision, _ = engine.evaluate(action_at_threshold)
    assert decision == Decision.ALLOW


def test_unknown_action_uses_default_decision():
    engine = PolicyEngine(default_decision=Decision.ALLOW)
    action = Action(type="totally_custom_action", payload="x", taint_score=0)
    decision, _ = engine.evaluate(action)
    assert decision == Decision.ALLOW


def test_default_decision_block():
    """PolicyEngine with default_decision=BLOCK blocks unknown actions."""
    engine = PolicyEngine(default_decision=Decision.BLOCK)
    action = Action(type="unknown_action", payload="x", taint_score=100)
    decision, _ = engine.evaluate(action)
    assert decision == Decision.BLOCK


def test_custom_rule_prepended():
    """Custom rules added via add_rule run before default rules."""
    custom_rule = Rule(
        name="Block all",
        condition=lambda act: True,
        decision=Decision.BLOCK,
        reason="Custom block",
    )
    engine = PolicyEngine()
    engine.add_rule(custom_rule, prepend=True)

    # Even a clean credential_use (taint 100) should be caught by our rule first
    action = Action(type="credential_use", payload="x", taint_score=100)
    decision, reason = engine.evaluate(action)
    assert decision == Decision.BLOCK
    assert reason == "Matched rule 'Block all': Custom block"


def test_custom_rule_appended():
    """Custom rules appended run after default rules."""
    catch_all = Rule(
        name="Catch all remaining",
        condition=lambda act: act.type == "my_custom_tool",
        decision=Decision.REQUIRE_APPROVAL,
        reason="my_custom_tool always needs approval",
    )
    engine = PolicyEngine()
    engine.add_rule(catch_all)

    action = Action(type="my_custom_tool", payload="args", taint_score=100)
    decision, _ = engine.evaluate(action)
    assert decision == Decision.REQUIRE_APPROVAL


def test_clean_safe_action_is_allowed():
    engine = PolicyEngine()
    action = Action(type="read_config", payload="config.yaml", taint_score=100)
    decision, _ = engine.evaluate(action)
    assert decision == Decision.ALLOW


def test_guard_raises_on_block():
    """AgentGuard.check_action raises BlockedActionError for BLOCK decisions."""
    guard = AgentGuard()
    t = guard.ingest("web stuff", source=guard.Source.WEB_FETCH)
    try:
        guard.check_action("credential_use", "SECRET", [t.id])
        raise AssertionError("Expected BlockedActionError")
    except BlockedActionError as e:
        assert "credential_use" in str(e)
