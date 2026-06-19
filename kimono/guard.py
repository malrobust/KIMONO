import threading
import time
from typing import Any, ClassVar, Dict, List, Optional, Type

from kimono.policy import Action, Decision, PolicyEngine
from kimono.provenance import Source as SourceEnum
from kimono.provenance import TaggedContent
from kimono.taint import TaintRegistry


class BlockedActionError(Exception):
    """Raised when an action is blocked by the policy engine."""

    pass


class AgentGuard:
    # Expose Source enum directly on AgentGuard for ergonomic access
    Source: ClassVar[Type[SourceEnum]] = SourceEnum

    def __init__(self, policy_engine: Optional[PolicyEngine] = None):
        self.taint_registry = TaintRegistry()
        self.policy_engine = policy_engine or PolicyEngine()
        self.audit_log: List[Dict[str, Any]] = []
        self._lock = threading.RLock()

    def ingest(
        self,
        content: str,
        source: SourceEnum,
        parent_ids: Optional[List[str]] = None,
        trust_score: Optional[int] = None,
    ) -> TaggedContent:
        """
        Tags and registers incoming content.

        Optionally override the default trust score for the source.
        Returns the generated TaggedContent object.
        """
        with self._lock:
            kwargs: Dict[str, Any] = {
                "content": content,
                "source": source,
                "parent_ids": parent_ids or [],
            }
            if trust_score is not None:
                kwargs["trust_score"] = trust_score
            tagged = TaggedContent(**kwargs)
            self.taint_registry.register(tagged)
            return tagged

    def ingest_tagged(self, tagged: TaggedContent) -> TaggedContent:
        """
        Registers a pre-built TaggedContent object directly.

        Useful when content has already been constructed with custom
        metadata outside of AgentGuard.
        """
        with self._lock:
            self.taint_registry.register(tagged)
            return tagged

    def check_action(
        self,
        action_type: str,
        payload: Any,
        source_content_ids: List[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Decision:
        """
        Gates outgoing actions through the policy engine before execution.
        Computes the taint score for the action and logs details.

        Raises BlockedActionError if the decision is BLOCK.
        """
        with self._lock:
            taint_score = self.taint_registry.compute_taint(source_content_ids)
            action = Action(
                type=action_type,
                payload=payload,
                taint_score=taint_score,
                metadata=metadata or {},
            )

            decision, reason = self.policy_engine.evaluate(action)

            log_entry = {
                "timestamp": time.time(),
                "action_type": action_type,
                "payload": payload,
                "source_content_ids": source_content_ids,
                "taint_score": taint_score,
                "decision": decision.value,
                "reason": reason,
            }
            self.audit_log.append(log_entry)

            if decision == Decision.BLOCK:
                raise BlockedActionError(
                    f"Action '{action_type}' was BLOCKED. Reason: {reason}"
                )

            return decision
