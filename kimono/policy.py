from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Dict, Any, Tuple

class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

@dataclass
class Action:
    type: str
    payload: Any
    taint_score: int
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Rule:
    name: str
    condition: Callable[[Action], bool]
    decision: Decision
    reason: str

class PolicyEngine:
    def __init__(self, default_decision: Decision = Decision.ALLOW, taint_threshold: int = 100):
        self.default_decision = default_decision
        self.taint_threshold = taint_threshold
        self.rules: List[Rule] = []
        self._load_default_rules()

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)

    def evaluate(self, action: Action) -> Tuple[Decision, str]:
        """
        Evaluates the action against registered rules in order.
        First match wins. Returns a tuple of (Decision, reason).
        If no rules match, returns (self.default_decision, "Default policy action").
        """
        for rule in self.rules:
            if rule.condition(action):
                return rule.decision, f"Matched rule '{rule.name}': {rule.reason}"
        return self.default_decision, f"Default policy action: {self.default_decision.value}"

    def _load_default_rules(self) -> None:
        # 1. Hard-block credential_use when tainted (taint_score < 100)
        self.add_rule(
            Rule(
                name="Block Tainted Credential Use",
                condition=lambda act: act.type == "credential_use" and act.taint_score < 100,
                decision=Decision.BLOCK,
                reason="Credential usage is strictly prohibited when utilizing tainted context."
            )
        )

        # 2. Require human approval for shell_exec/code_exec/file_write/network_call/email_send when taint_score < threshold
        risky_actions = {"shell_exec", "code_exec", "file_write", "network_call", "email_send"}
        self.add_rule(
            Rule(
                name="Require Approval for Risky Actions",
                condition=lambda act: act.type in risky_actions and act.taint_score < self.taint_threshold,
                decision=Decision.REQUIRE_APPROVAL,
                reason=f"Risky action requires human approval because taint score is below the threshold of {self.taint_threshold}."
            )
        )
