from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


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


def _normalize_session_cookie_records(session_cookies, target_url: str) -> tuple[list[dict], dict]:
    parsed_target = urlparse(str(target_url or ""))
    target_host = str(parsed_target.hostname or "").strip().lower()
    target_path = str(parsed_target.path or "/").strip() or "/"
    if not target_path.startswith("/"):
        target_path = "/" + target_path

    normalized_records = []
    filtered_for_scope = 0

    for item in session_cookies or []:
        if not isinstance(item, dict):
            continue

        name = str(item.get("name", "") or "").strip()
        value = str(item.get("value", "") or "")
        domain = str(item.get("domain", "") or "").strip().lower()
        path = str(item.get("path", "/") or "/").strip() or "/"
        if not name or value == "":
            continue

        domain_match = True
        if domain and target_host:
            normalized_domain = domain.lstrip(".")
            domain_match = (
                target_host == normalized_domain
                or target_host.endswith("." + normalized_domain)
            )

        path_match = True
        if path not in {"", "/"}:
            normalized_path = path if path.startswith("/") else "/" + path
            path_match = target_path.startswith(normalized_path.rstrip("/") or "/")

        if not (domain_match and path_match):
            filtered_for_scope += 1
            continue

        normalized_records.append(
            {
                "name": name,
                "value": value,
                "domain": domain,
                "path": path if path.startswith("/") else "/" + path,
            }
        )

    session_cookie_names = []
    session_cookie_domains = []
    for item in normalized_records:
        if item["name"] not in session_cookie_names:
            session_cookie_names.append(item["name"])
        if item["domain"] and item["domain"] not in session_cookie_domains:
            session_cookie_domains.append(item["domain"])

    return normalized_records, {
        "session_material_present": bool(normalized_records),
        "session_cookie_count": len(normalized_records),
        "session_cookie_names": session_cookie_names,
        "session_cookie_domains": session_cookie_domains,
        "session_scope_applied": bool(filtered_for_scope > 0),
        "session_scope_filtered_count": filtered_for_scope,
    }


@dataclass
class AITarget:
    url: str
    name: Optional[str] = None
    model: Optional[str] = None
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    session_cookies: list[dict] = field(default_factory=list)
    session_context: dict = field(default_factory=dict)
    timeout: int = 30

    def __post_init__(self):
        if not self.name:
            self.name = self.url.split("//")[-1].split("/")[0]

        self.session_cookies, session_context = _normalize_session_cookie_records(self.session_cookies, self.url)
        handoff_cookies = _normalize_cookie_mapping(self.session_cookies)
        explicit_cookies = _normalize_cookie_mapping(self.cookies)
        self.cookies = {**handoff_cookies, **explicit_cookies}
        has_manual = bool(explicit_cookies)
        has_handoff = bool(handoff_cookies)
        if has_manual and has_handoff:
            session_cookie_source = "merged"
            session_cookie_merge_strategy = "manual_overrides_captured"
        elif has_manual:
            session_cookie_source = "manual"
            session_cookie_merge_strategy = "manual_only"
        elif has_handoff:
            session_cookie_source = "handoff"
            session_cookie_merge_strategy = "captured_only"
        else:
            session_cookie_source = "none"
            session_cookie_merge_strategy = "no_session_material"

        merged_cookie_names = []
        for name in list(handoff_cookies.keys()) + list(explicit_cookies.keys()):
            if name not in merged_cookie_names:
                merged_cookie_names.append(name)

        propagation_note = "No session cookies applied."
        if session_cookie_source == "handoff":
            propagation_note = "Captured handoff session cookies were applied to the target."
        elif session_cookie_source == "manual":
            propagation_note = "Manual operator cookies were applied to the target."
        elif session_cookie_source == "merged":
            propagation_note = "Manual operator cookies overrode colliding captured handoff cookies."

        self.session_context = {
            **session_context,
            "session_cookie_source": session_cookie_source,
            "session_cookie_merge_strategy": session_cookie_merge_strategy,
            "session_cookie_header_redacted": bool(has_handoff),
            "session_cookie_names": merged_cookie_names,
            "session_cookie_count": len(merged_cookie_names),
            "manual_cookie_names": list(explicit_cookies.keys()),
            "captured_cookie_names": list(handoff_cookies.keys()),
            "session_propagation_note": propagation_note,
        }

    def __repr__(self):
        return (
            f"AITarget(url={self.url}, name={self.name}, model={self.model})"
        )
