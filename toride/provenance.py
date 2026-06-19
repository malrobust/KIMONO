import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Source(str, Enum):
    USER = "USER"
    SYSTEM = "SYSTEM"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    WEB_FETCH = "WEB_FETCH"
    FILE_READ = "FILE_READ"
    EMAIL = "EMAIL"


TRUST_LEVELS = {
    Source.USER: 100,
    Source.SYSTEM: 100,
    Source.TOOL_OUTPUT: 20,
    Source.FILE_READ: 10,
    Source.WEB_FETCH: 0,
    Source.EMAIL: 0,
}


@dataclass
class TaggedContent:
    content: str
    source: Source
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    trust_score: int = field(default=-1)
    timestamp: float = field(default_factory=time.time)
    parent_ids: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.trust_score == -1:
            self.trust_score = TRUST_LEVELS.get(self.source, 0)
