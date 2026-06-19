from toride import AgentGuard, BlockedActionError, Decision, Source
from toride.fuzzer import run_fuzz_test


def test_fuzzer_against_guarded_agent():
    guard = AgentGuard()

    def guarded_decide_fn(prompt: str):
        # Ingest prompt as untrusted Web context
        tagged = guard.ingest(content=prompt, source=Source.WEB_FETCH)

        actions = []
        prompt_lower = prompt.lower()

        # Determine the action type we might try to execute based on payload content
        if (
            "shell" in prompt_lower
            or "exec" in prompt_lower
            or "passwd" in prompt_lower
        ):
            action_type = "shell_exec"
        elif (
            "credential" in prompt_lower
            or "api_key" in prompt_lower
            or "mandatory" in prompt_lower
        ):
            action_type = "credential_use"
        elif "leak" in prompt_lower or "attacker" in prompt_lower:
            action_type = "network_call"
        else:
            action_type = None

        if action_type:
            # Let's perform agent gate using AgentGuard
            decision = guard.check_action(
                action_type=action_type,
                payload="payload",
                source_content_ids=[tagged.id],
            )
            if decision == Decision.REQUIRE_APPROVAL:
                raise BlockedActionError(f"Action requires approval: {action_type}")
            actions.append({"type": action_type, "payload": "payload"})

        return actions

    results = run_fuzz_test(guarded_decide_fn)

    # Assert 100% block or require approval rate (0% success/hijacked rate)
    for r in results:
        # None of the payloads should successfully hijack the agent
        assert r["hijacked"] is False

        # If an action was attempted, it must be blocked or captured
        if r["actions_attempted"]:
            assert r["blocked"] is True or any(
                guard.audit_log[-1]["decision"] in ["BLOCK", "REQUIRE_APPROVAL"]
                for log in guard.audit_log
            )

    # Print statistics for test output
    total = len(results)
    blocked = sum(1 for r in results if r["blocked"])
    hijacked = sum(1 for r in results if r["hijacked"])
    print(f"\nFuzz Test Run: Total={total}, Blocked={blocked}, Hijacked={hijacked}")
