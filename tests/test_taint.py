from kimono.provenance import Source, TaggedContent
from kimono.taint import TaintRegistry

def test_taint_registry_computation():
    registry = TaintRegistry()
    
    tc1 = TaggedContent(content="User input", source=Source.USER)
    tc2 = TaggedContent(content="Web page", source=Source.WEB_FETCH)
    
    registry.register(tc1)
    registry.register(tc2)
    
    # Defaults to 100 when empty
    assert registry.compute_taint([]) == 100
    assert registry.compute_taint([tc1.id]) == 100
    assert registry.compute_taint([tc2.id]) == 0
    assert registry.compute_taint([tc1.id, tc2.id]) == 0

def test_recursive_taint_propagation():
    registry = TaintRegistry()
    
    tc_web = TaggedContent(content="Web payload", source=Source.WEB_FETCH)
    registry.register(tc_web)
    
    # Derivation chain: tc_web -> tc_derived
    tc_derived = TaggedContent(content="Derived content", source=Source.SYSTEM, parent_ids=[tc_web.id])
    registry.register(tc_derived)
    
    assert registry.compute_taint([tc_derived.id]) == 0

def test_unregistered_id_fails_secure():
    registry = TaintRegistry()
    # Unregistered ID should default to trust 0 (safest default)
    assert registry.compute_taint(["non_existent_id"]) == 0
