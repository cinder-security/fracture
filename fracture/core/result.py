from dataclasses import dataclass, field
from typing import Optional, Any
from datetime import UTC, datetime

@dataclass
class AttackResult:
    module: str
    target_url: str
    success: bool
    confidence: float = 0.0
    evidence: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    notes: Optional[str] = None

    def summary(self) -> str:
        status = "✅ SUCCESS" if self.success else "❌ FAILED"
        return f"[{self.module}] {status} | confidence={self.confidence:.0%} | {self.target_url}"
