from toride.provenance import TRUST_LEVELS, Source, TaggedContent


def test_tagged_content_defaults():
    tc = TaggedContent(content="Hello", source=Source.USER)
    assert tc.trust_score == 100
    assert tc.id is not None
    assert tc.timestamp is not None
    assert tc.parent_ids == []


def test_tagged_content_custom_trust():
    tc = TaggedContent(content="Hello", source=Source.WEB_FETCH, trust_score=50)
    assert tc.trust_score == 50


def test_trust_levels_mapping():
    assert TRUST_LEVELS[Source.USER] == 100
    assert TRUST_LEVELS[Source.SYSTEM] == 100
    assert TRUST_LEVELS[Source.TOOL_OUTPUT] == 20
    assert TRUST_LEVELS[Source.FILE_READ] == 10
    assert TRUST_LEVELS[Source.WEB_FETCH] == 0
    assert TRUST_LEVELS[Source.EMAIL] == 0
