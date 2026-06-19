from typing import Dict, List, Set
from kimono.provenance import TaggedContent

class TaintRegistry:
    def __init__(self):
        self._registry: Dict[str, TaggedContent] = {}

    def register(self, content: TaggedContent) -> None:
        """Registers a TaggedContent object by its ID."""
        self._registry[content.id] = content

    def get(self, content_id: str) -> TaggedContent:
        """Retrieves a TaggedContent object by its ID, or None if not found."""
        return self._registry.get(content_id)

    def compute_taint(self, content_ids: List[str]) -> int:
        """
        Computes the taint score for an action based on a list of contributing content IDs.
        Taint score is the MINIMUM trust score of everything that contributed to it.
        This recursively traces any parent_ids of the contributing contents.
        
        If no content_ids are provided, returns 100 (fully trusted/untainted).
        If content IDs are provided but not found in the registry, their trust is assumed to be 0
        (fail-secure principle).
        """
        if not content_ids:
            return 100

        resolved_ids: Set[str] = set()
        queue = list(content_ids)

        while queue:
            current_id = queue.pop(0)
            if current_id in resolved_ids:
                continue
            resolved_ids.add(current_id)
            
            content = self._registry.get(current_id)
            if content and content.parent_ids:
                queue.extend(content.parent_ids)

        min_trust = 100
        for cid in resolved_ids:
            content = self._registry.get(cid)
            if content is None:
                # Unregistered/unknown source is assumed to be untrusted
                current_trust = 0
            else:
                current_trust = content.trust_score
            
            if current_trust < min_trust:
                min_trust = current_trust

        return min_trust
