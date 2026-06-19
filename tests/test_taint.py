"""
Extended tests for TaintRegistry: chains, unknown IDs, empty inputs,
thread safety, and override trust scores.
"""

import threading

from toride.provenance import TRUST_LEVELS, Source, TaggedContent
from toride.taint import TaintRegistry


def test_taint_registry_computation():
    registry = TaintRegistry()

    # Register a WEB_FETCH content (trust = 0)
    tc_web = TaggedContent(content="Fetched content", source=Source.WEB_FETCH)
    registry.register(tc_web)
    assert tc_web.trust_score == 0

    # Register a USER content (trust = 100)
    tc_user = TaggedContent(content="User input", source=Source.USER)
    registry.register(tc_user)
    assert tc_user.trust_score == 100

    # Taint of only the user content is 100
    assert registry.compute_taint([tc_user.id]) == 100

    # Taint of only the web content is 0
    assert registry.compute_taint([tc_web.id]) == 0

    # Mixed: minimum wins → 0
    assert registry.compute_taint([tc_user.id, tc_web.id]) == 0


def test_taint_derivation_chain():
    registry = TaintRegistry()

    tc_web = TaggedContent(content="Fetched", source=Source.WEB_FETCH)
    registry.register(tc_web)

    # A SYSTEM message derived from the web fetch inherits its parent's taint
    tc_derived = TaggedContent(
        content="Derived content",
        source=Source.SYSTEM,
        parent_ids=[tc_web.id],
    )
    registry.register(tc_derived)

    # Even though tc_derived.source == SYSTEM (trust 100), its parent is WEB_FETCH (0)
    # compute_taint should recursively find the minimum across the whole chain
    score = registry.compute_taint([tc_derived.id])
    assert score == 0


def test_empty_content_ids_returns_100():
    """No contributing inputs → fully trusted (no taint)."""
    registry = TaintRegistry()
    assert registry.compute_taint([]) == 100


def test_unknown_content_id_fails_secure():
    """An ID not in the registry is treated as trust 0 (fail-secure)."""
    registry = TaintRegistry()
    score = registry.compute_taint(["nonexistent-id"])
    assert score == 0


def test_get_returns_none_for_missing():
    registry = TaintRegistry()
    assert registry.get("not-there") is None


def test_custom_trust_score_override():
    """Explicitly provided trust_score beats the source default."""
    tc = TaggedContent(content="partial trust", source=Source.WEB_FETCH, trust_score=50)
    assert tc.trust_score == 50


def test_all_source_trust_levels():
    """Every Source has a defined trust level and TaggedContent picks it up."""
    for source, expected in TRUST_LEVELS.items():
        tc = TaggedContent(content="test", source=source)
        assert tc.trust_score == expected, f"Failed for {source}"


def test_thread_safety():
    """Concurrent registrations must not corrupt the registry."""
    registry = TaintRegistry()
    items = [TaggedContent(content=f"msg {i}", source=Source.USER) for i in range(100)]
    threads = [
        threading.Thread(target=registry.register, args=(item,)) for item in items
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(registry._registry) == 100
