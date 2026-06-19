from kimono.policy import Action, Decision, Rule, PolicyEngine

def test_policy_engine_evaluation():
    engine = PolicyEngine(default_decision=Decision.ALLOW, taint_threshold=50)
    
    # Credential use hard-block rule: blocked if taint_score < 100
    action_cred_tainted = Action(type="credential_use", payload="API_KEY", taint_score=99)
    decision, reason = engine.evaluate(action_cred_tainted)
    assert decision == Decision.BLOCK
    assert "strictly prohibited" in reason

    action_cred_clean = Action(type="credential_use", payload="API_KEY", taint_score=100)
    decision, reason = engine.evaluate(action_cred_clean)
    assert decision == Decision.ALLOW

    # Risky action with high trust (>= threshold 50)
    action_shell_safe = Action(type="shell_exec", payload="echo 1", taint_score=100)
    decision, reason = engine.evaluate(action_shell_safe)
    assert decision == Decision.ALLOW
    
    # Risky action with low trust (< threshold 50)
    action_shell_unsafe = Action(type="shell_exec", payload="rm -rf /", taint_score=20)
    decision, reason = engine.evaluate(action_shell_unsafe)
    assert decision == Decision.REQUIRE_APPROVAL
    assert "Risky action requires human approval" in reason

def test_custom_rule():
    engine = PolicyEngine(default_decision=Decision.ALLOW)
    custom_rule = Rule(
        name="Block Specific Payload",
        condition=lambda act: act.payload == "blocked_val",
        decision=Decision.BLOCK,
        reason="Blocked specific value"
    )
    engine.add_rule(custom_rule)
    
    action1 = Action(type="some_action", payload="blocked_val", taint_score=100)
    decision, reason = engine.evaluate(action1)
    assert decision == Decision.BLOCK
    
    action2 = Action(type="some_action", payload="other_val", taint_score=100)
    decision, reason = engine.evaluate(action2)
    assert decision == Decision.ALLOW
