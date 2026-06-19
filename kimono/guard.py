import time
import threading
from typing import Any, List, Dict, Optional
from kimono.provenance import TaggedContent, Source
from kimono.taint import TaintRegistry
from kimono.policy import Action, Decision, PolicyEngine

class BlockedActionError(Exception):
    """Raised when an action is blocked by the policy engine."""
    pass

class AgentGuard:
    def __init__(self, policy_engine: Optional[PolicyEngine] = None):
        self.taint_registry = TaintRegistry()
        self.policy_engine = policy_engine or PolicyEngine()
        self.audit_log: List[Dict[str, Any]] = []
        self._lock = threading.RLock()

    def ingest(self, content: str, source: Source, parent_ids: Optional[List[str]] = None) -> TaggedContent:
        """
        Tags and registers incoming content.
        
        Returns the generated TaggedContent object.
        """
        with self._lock:
            tagged = TaggedContent(
                content=content,
                source=source,
                parent_ids=parent_ids or []
            )
            self.taint_registry.register(tagged)
            return tagged

    def check_action(
        self,
        action_type: str,
        payload: Any,
        source_content_ids: List[str],
        metadata: Optional[Dict[str, Any]] = None
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
                metadata=metadata or {}
            )
            
            decision, reason = self.policy_engine.evaluate(action)
            
            log_entry = {
                "timestamp": time.time(),
                "action_type": action_type,
                "payload": payload,
                "source_content_ids": source_content_ids,
                "taint_score": taint_score,
                "decision": decision.value,
                "reason": reason
            }
            self.audit_log.append(log_entry)
            
            if decision == Decision.BLOCK:
                raise BlockedActionError(f"Action '{action_type}' was BLOCKED. Reason: {reason}")
                
            return decision
