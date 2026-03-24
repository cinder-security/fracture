from dataclasses import dataclass, field
from typing import Optional


def _normalize_cookie_mapping(cookies) -> dict[str, str]:
    normalized: dict[str, str] = {}

    if isinstance(cookies, dict):
        for key, value in cookies.items():
            name = str(key or "").strip()
            if name:
                normalized[name] = str(value or "")
        return normalized

    if isinstance(cookies, list):
        for item in cookies:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "") or "").strip()
            if name:
                normalized[name] = str(item.get("value", "") or "")

    return normalized


@dataclass
class AITarget:
    url: str
    name: Optional[str] = None
    model: Optional[str] = None
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    session_cookies: list[dict] = field(default_factory=list)
    timeout: int = 30

    def __post_init__(self):
        if not self.name:
            self.name = self.url.split("//")[-1].split("/")[0]

        handoff_cookies = _normalize_cookie_mapping(self.session_cookies)
        explicit_cookies = _normalize_cookie_mapping(self.cookies)
        self.cookies = {**handoff_cookies, **explicit_cookies}
        self.session_cookies = [
            {
                "name": str(item.get("name", "") or "").strip(),
                "value": str(item.get("value", "") or ""),
                "domain": str(item.get("domain", "") or ""),
                "path": str(item.get("path", "/") or "/"),
            }
            for item in (self.session_cookies or [])
            if isinstance(item, dict) and str(item.get("name", "") or "").strip()
        ]

    def __repr__(self):
        return (
            f"AITarget(url={self.url}, name={self.name}, model={self.model})"
        )
