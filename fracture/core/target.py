from dataclasses import dataclass, field
from typing import Optional

@dataclass
class AITarget:
    url: str
    name: Optional[str] = None
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    timeout: int = 30

    def __post_init__(self):
        if not self.name:
            self.name = self.url.split("//")[-1].split("/")[0]

    def __repr__(self):
        return f"AITarget(url={self.url}, name={self.name})"
