import json
import re
import sys
from urllib.parse import parse_qsl, urljoin, urlparse

import httpx


_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
_ABSOLUTE_URL_RE = re.compile(r"""https?://[^\s"'<>]+|wss?://[^\s"'<>]+""", re.IGNORECASE)
_PATH_CANDIDATE_RE = re.compile(
    r"""(?:"|')((?:/|\.?/)[^"'<> ]*(?:api|graphql|chat|conversation|message|messages|socket|stream|ws)[^"'<> ]*)(?:"|')""",
    re.IGNORECASE,
)

_API_HINT_TERMS = [
    "/api/",
    "/graphql",
    "/chat",
    "/conversation",
    "/message",
    "/messages",
    "/socket",
    "/stream",
    "graphql",
    "conversation",
    "message",
    "messages",
]

_SESSION_HINT_TERMS = [
    "login",
    "signin",
    "auth",
    "session",
    "cookie",
    "csrf",
    "bearer",
    "authorization",
    "localstorage",
    "sessionstorage",
]

_STREAM_HINT_TERMS = [
    "websocket",
    "wss://",
    "ws://",
    "socket.io",
    "eventsource",
    "text/event-stream",
    "sse",
    "stream",
]

_AUTH_SIGNAL_TERMS = [
    "authorization",
    "bearer",
    "cookie",
    "csrf",
    "session",
]

_AI_USEFUL_HINTS = [
    "chat",
    "message",
    "messages",
    "conversation",
    "completion",
    "prompt",
    "query",
    "search",
    "retrieve",
    "retrieval",
    "memory",
    "tool",
    "agent",
    "assist",
]

_LOW_VALUE_HINTS = [
    "analytics",
    "telemetry",
    "tracking",
    "pixel",
    "metrics",
    "metric",
    "health",
    "status",
    "heartbeat",
    "logout",
    "signin",
    "login",
]

_STATIC_EXTENSIONS = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
)


def _lower(value) -> str:
    return str(value or "").lower()


def _same_origin(url_a: str, url_b: str) -> bool:
    parsed_a = urlparse(str(url_a or ""))
    parsed_b = urlparse(str(url_b or ""))
    return (
        parsed_a.scheme,
        parsed_a.netloc,
    ) == (
        parsed_b.scheme,
        parsed_b.netloc,
    )


def _normalize_candidate_url(url: str) -> str:
    parsed = urlparse(str(url or ""))
    if not parsed.scheme and not parsed.netloc:
        return str(url or "")
    return parsed._replace(query="", fragment="").geturl()


def _extract_script_urls(html: str, base_url: str) -> list[str]:
    urls = []
    for src in _SCRIPT_SRC_RE.findall(html or ""):
        urls.append(urljoin(base_url, src))
    return urls[:8]


def _merge_candidate_entry(container: dict[str, dict], candidate_url: str, source: str, matched_term: str) -> None:
    url = str(candidate_url or "").strip()
    if not url:
        return
    entry = container.setdefault(
        url,
        {
            "url": url,
            "sources": set(),
            "matched_terms": set(),
        },
    )
    if source:
        entry["sources"].add(source)
    if matched_term:
        entry["matched_terms"].add(matched_term)


def _extract_candidate_entries(html: str, asset_bodies: list[tuple[str, str]], base_url: str) -> list[dict]:
    candidates: dict[str, dict] = {}

    def _register(candidate_url: str, source: str, matched_term: str) -> None:
        _merge_candidate_entry(candidates, candidate_url, source, matched_term)

    def _scan_blob(text: str, source: str) -> None:
        blob = text or ""
        for match in _ABSOLUTE_URL_RE.findall(blob):
            lowered = match.lower()
            matched = next((term for term in _API_HINT_TERMS if term in lowered), "")
            if matched:
                _register(match, source, matched)

        for match in _PATH_CANDIDATE_RE.findall(blob):
            normalized = urljoin(base_url, match)
            lowered = normalized.lower()
            matched = next((term for term in _API_HINT_TERMS if term in lowered), "")
            if matched:
                _register(normalized, source, matched)

        lowered_blob = _lower(blob)
        if "socket.io" in lowered_blob:
            _register(urljoin(base_url, "/socket.io/"), source, "socket.io")

    _scan_blob(html, "html")
    for asset_url, asset_text in asset_bodies:
        _scan_blob(asset_text, f"script:{asset_url}")

    normalized_entries = []
    for entry in candidates.values():
        normalized_entries.append(
            {
                "url": entry["url"],
                "sources": sorted(entry["sources"]),
                "matched_terms": sorted(entry["matched_terms"]),
            }
        )

    return sorted(normalized_entries, key=lambda item: item["url"])[:12]


def _extract_browser_candidate_entries(browser_requests: list[dict], base_url: str) -> list[dict]:
    candidates: dict[str, dict] = {}

    for request in browser_requests or []:
        url = str(request.get("url", "") or "")
        resource_type = str(request.get("resource_type", "") or "").lower()
        method = str(request.get("method", "") or "GET").upper()
        lowered_url = url.lower()

        matched = next((term for term in _API_HINT_TERMS if term in lowered_url), "")
        is_relevant = (
            matched
            or resource_type in {"fetch", "xhr", "websocket"}
            or any(term in lowered_url for term in _STREAM_HINT_TERMS)
        )
        if not is_relevant:
            continue

        _merge_candidate_entry(
            candidates,
            _normalize_candidate_url(urljoin(base_url, url)),
            f"browser:{resource_type or 'request'}:{method}",
            matched or resource_type or method.lower(),
        )

    normalized_entries = []
    for entry in candidates.values():
        normalized_entries.append(
            {
                "url": entry["url"],
                "sources": sorted(entry["sources"]),
                "matched_terms": sorted(entry["matched_terms"]),
            }
        )
    return sorted(normalized_entries, key=lambda item: item["url"])[:12]


def _extract_auth_metadata(
    combined_text: str,
    target_headers: dict,
    target_cookies: dict,
    browser_requests: list[dict],
) -> dict:
    auth_signals = set()
    observed_header_names = set(str(key).strip() for key in (target_headers or {}).keys() if str(key).strip())
    observed_cookie_names = set(str(key).strip() for key in (target_cookies or {}).keys() if str(key).strip())

    lowered = _lower(combined_text)
    for term in _AUTH_SIGNAL_TERMS:
        if term in lowered:
            auth_signals.add(term)

    for request in browser_requests or []:
        for header_name in request.get("header_names", []) or []:
            normalized = str(header_name or "").strip()
            if not normalized:
                continue
            observed_header_names.add(normalized)
            lower_name = normalized.lower()
            if lower_name in {"authorization", "cookie", "x-csrf-token", "x-xsrf-token"}:
                auth_signals.add(lower_name)

        for cookie_name in request.get("cookie_names", []) or []:
            normalized = str(cookie_name or "").strip()
            if normalized:
                observed_cookie_names.add(normalized)
                auth_signals.add("cookie")

    return {
        "auth_signals": sorted(auth_signals)[:6],
        "observed_header_names": sorted(observed_header_names)[:12],
        "observed_cookie_names": sorted(observed_cookie_names)[:12],
    }


def _extract_query_param_names(url: str) -> list[str]:
    try:
        parsed = urlparse(str(url or ""))
        return sorted({str(key).strip() for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if str(key).strip()})[:12]
    except Exception:
        return []


def _extract_body_field_hints(post_data: str, content_type: str) -> list[str]:
    raw = str(post_data or "")
    lowered_type = _lower(content_type)
    if not raw:
        return []

    if "json" in lowered_type or raw.lstrip().startswith(("{", "[")):
        try:
            payload = json.loads(raw)
        except Exception:
            payload = None
        hints = set()
        if isinstance(payload, dict):
            hints.update(str(key).strip() for key in payload.keys() if str(key).strip())
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    hints.update(str(key).strip() for key in item.keys() if str(key).strip())
        return sorted(hints)[:10]

    if "x-www-form-urlencoded" in lowered_type:
        return sorted({str(key).strip() for key, _ in parse_qsl(raw, keep_blank_values=True) if str(key).strip()})[:10]

    return []


def _build_invocation_profile(best_candidate: dict | None, browser_requests: list[dict], probe: dict | None = None) -> dict | None:
    if not isinstance(best_candidate, dict) or not best_candidate.get("url"):
        return None

    candidate_url = str(best_candidate.get("url", "") or "")
    normalized_candidate_url = _normalize_candidate_url(candidate_url)
    relevant_requests = [
        request for request in (browser_requests or [])
        if _normalize_candidate_url(str(request.get("url", "") or "")) == normalized_candidate_url
    ]
    observed = relevant_requests[0] if relevant_requests else {}
    probe = probe or {}

    method_hint = str(observed.get("method", "") or "").upper() or None
    content_type_hint = str(observed.get("content_type_hint", "") or "").strip() or None
    if not content_type_hint:
        content_type_hint = str(probe.get("content_type", "") or "").strip() or None

    accepts_json = bool(observed.get("accepts_json"))
    if not accepts_json and content_type_hint:
        accepts_json = "json" in _lower(content_type_hint) or "graphql" in _lower(content_type_hint)

    websocket_likely = (
        str(observed.get("resource_type", "") or "").lower() == "websocket"
        or str(best_candidate.get("intent", "") or "") == "tool_or_agent_surface" and "websocket" in _lower(candidate_url)
        or candidate_url.lower().startswith(("ws://", "wss://"))
    )
    streaming_likely = bool(
        websocket_likely
        or observed.get("streaming_likely")
        or "event-stream" in _lower(content_type_hint)
        or any(token in candidate_url.lower() for token in ["/stream", "sse", "eventsource"])
    )

    observed_body_keys = list(observed.get("body_field_hints", []) or [])[:10]
    observed_query_param_names = list(observed.get("query_param_names", []) or [])[:10]
    observed_header_names = list(observed.get("header_names", []) or [])[:16]
    observed_cookie_names = list(observed.get("cookie_names", []) or [])[:12]

    request_shape_hints = []
    if str(observed.get("resource_type", "") or "").lower() in {"fetch", "xhr"}:
        request_shape_hints.append("frontend fetch/xhr observed")
    if method_hint == "POST":
        request_shape_hints.append("interactive POST observed")
    if accepts_json:
        request_shape_hints.append("json response/accept hint")
    if content_type_hint and "json" in _lower(content_type_hint):
        request_shape_hints.append("json request content type")
    if observed_body_keys:
        request_shape_hints.append("body field names observed")
    if observed_query_param_names:
        request_shape_hints.append("query param names observed")
    if streaming_likely:
        request_shape_hints.append("streaming or realtime hints observed")

    invocation_notes = []
    if method_hint:
        invocation_notes.append(f"Observed {method_hint} request shape for the candidate endpoint.")
    if observed_body_keys:
        invocation_notes.append("Only body field names were retained; no body values or prompts were persisted.")
    if observed_query_param_names:
        invocation_notes.append("Only query parameter names were retained; no parameter values were persisted.")

    return {
        "method_hint": method_hint or ("POST" if best_candidate.get("intent") in {"chat_surface", "tool_or_agent_surface"} else "GET"),
        "content_type_hint": content_type_hint or ("application/json" if accepts_json else None),
        "accepts_json": accepts_json,
        "streaming_likely": bool(streaming_likely),
        "websocket_likely": bool(websocket_likely),
        "request_shape_hints": request_shape_hints[:6],
        "observed_body_keys": observed_body_keys,
        "observed_query_param_names": observed_query_param_names,
        "observed_header_names": observed_header_names,
        "observed_cookie_names": observed_cookie_names,
        "invocation_notes": invocation_notes[:4],
    }


def _build_handoff(
    *,
    best_candidate: dict | None,
    discovery_mode: str,
    likely_browser_session_required: bool,
    likely_websocket_or_streaming_surface: bool,
    auth_metadata: dict,
    invocation_profile: dict | None,
) -> dict | None:
    if not isinstance(best_candidate, dict) or not best_candidate.get("url"):
        return None

    url = str(best_candidate.get("url", "") or "")
    lowered = url.lower()
    intent = str(best_candidate.get("intent", "unknown_surface") or "unknown_surface")
    reasons = list(best_candidate.get("reasons", []) or [])
    probe = best_candidate.get("probe", {}) if isinstance(best_candidate.get("probe", {}), dict) else {}
    matched_terms = [str(term).lower() for term in (best_candidate.get("matched_terms", []) or [])]
    auth_signals = list(auth_metadata.get("auth_signals", []) or [])

    if isinstance(invocation_profile, dict) and invocation_profile.get("websocket_likely"):
        transport_hint = "websocket"
    elif lowered.startswith(("ws://", "wss://")) or any(token in lowered for token in ["/ws", "/socket", "socket.io"]):
        transport_hint = "websocket"
    elif "graphql" in lowered or "graphql" in matched_terms:
        transport_hint = "graphql-http"
    elif isinstance(invocation_profile, dict) and invocation_profile.get("streaming_likely"):
        transport_hint = "streaming-http"
    elif any(token in lowered for token in ["/stream", "eventsource", "sse"]):
        transport_hint = "streaming-http"
    else:
        transport_hint = "http"

    method_hint = (
        str(invocation_profile.get("method_hint", "") or "").upper()
        if isinstance(invocation_profile, dict) else ""
    ) or ("POST" if intent in {"chat_surface", "tool_or_agent_surface"} or transport_hint in {"graphql-http", "websocket"} else "GET")
    session_required = bool(
        likely_browser_session_required
        or auth_signals
        or probe.get("status_code") in {401, 403}
    )

    notes = [f"Use {method_hint} against the recommended endpoint."]
    if session_required:
        notes.append("Session or auth material is likely required; pass headers/cookies explicitly if available.")
    if transport_hint == "websocket":
        notes.append("Treat this as a realtime/browser-driven surface rather than a plain request-response API.")
    elif transport_hint == "graphql-http":
        notes.append("GraphQL naming detected; inspect operation shape before module execution.")

    return {
        "recommended_target_url": url,
        "intent": intent,
        "score": int(best_candidate.get("score", 0) or 0),
        "source_mode": discovery_mode,
        "transport_hint": transport_hint,
        "method_hint": method_hint,
        "session_required": session_required,
        "browser_session_likely": bool(likely_browser_session_required),
        "auth_signals": auth_signals,
        "observed_header_names": list(auth_metadata.get("observed_header_names", []) or []),
        "observed_cookie_names": list(auth_metadata.get("observed_cookie_names", []) or []),
        "invocation_profile": invocation_profile,
        "notes": notes[:4],
    }


def _candidate_penalties(url: str, sources: list[str], intent: str) -> list[tuple[str, int]]:
    lowered = _lower(url)
    penalties: list[tuple[str, int]] = []

    if any(lowered.endswith(ext) for ext in _STATIC_EXTENSIONS):
        penalties.append(("static asset path", -6))

    if any(hint in lowered for hint in ["analytics", "telemetry", "tracking", "pixel"]):
        penalties.append(("analytics/telemetry path", -5))

    if any(hint in lowered for hint in ["health", "metrics", "metric", "status", "heartbeat"]):
        penalties.append(("health/metrics endpoint", -4))

    if any(hint in lowered for hint in ["login", "logout", "signin"]) and intent == "unknown_surface":
        penalties.append(("auth-only endpoint", -4))

    if not any(source.startswith("browser:fetch:") or source.startswith("browser:xhr:") or source.startswith("browser:websocket:") for source in sources):
        if not any(hint in lowered for hint in _AI_USEFUL_HINTS):
            penalties.append(("weak AI-surface semantics", -2))

    return penalties


def _infer_intent(url: str, sources: list[str], matched_terms: list[str]) -> str:
    text = " ".join([str(url or "")] + list(sources or []) + list(matched_terms or [])).lower()
    if any(term in text for term in ["chat", "conversation", "message", "messages", "completion"]):
        return "chat_surface"
    if any(term in text for term in ["retrieval", "search", "rag", "document", "knowledge", "vector", "graphql"]):
        return "retrieval_surface"
    if any(term in text for term in ["memory", "history", "thread", "session", "store"]):
        return "memory_surface"
    if any(term in text for term in ["tool", "plugin", "function", "agent", "action", "invoke", "websocket", "socket"]):
        return "tool_or_agent_surface"
    return "unknown_surface"


def get_phantomtwin_runtime_status() -> dict:
    try:
        from playwright.async_api import async_playwright  # noqa: F401
    except Exception:
        return {
            "ready": False,
            "reason": (
                f"Playwright is not installed in the current Python runtime ({sys.executable}). "
                "PhantomTwin will fall back to passive discovery."
            ),
            "hint": "Install it in the active environment and run `python -m playwright install chromium`.",
        }

    return {
        "ready": True,
        "reason": "Playwright Python package detected in the current runtime.",
        "hint": "",
    }


async def _run_phantomtwin_browser_recon(target) -> dict:
    runtime_status = get_phantomtwin_runtime_status()
    if not runtime_status.get("ready"):
        return {
            "available": False,
            "requests": [],
            "note": f"{runtime_status.get('reason', '')} {runtime_status.get('hint', '')}".strip(),
            "rendered_html": "",
        }

    from playwright.async_api import async_playwright

    requests = []
    rendered_html = ""

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context(extra_http_headers=getattr(target, "headers", {}) or {})

            if getattr(target, "cookies", None):
                cookies = []
                for key, value in (getattr(target, "cookies", {}) or {}).items():
                    cookies.append({"name": key, "value": value, "url": target.url})
                if cookies:
                    await context.add_cookies(cookies)

            page = await context.new_page()

            def _on_request(request):
                header_names = []
                cookie_names = []
                try:
                    headers = dict(getattr(request, "headers", {}) or {})
                except Exception:
                    headers = {}
                for header_name in headers.keys():
                    normalized = str(header_name or "").strip()
                    if normalized:
                        header_names.append(normalized)
                cookie_header = str(headers.get("cookie", "") or "")
                if cookie_header:
                    for item in cookie_header.split(";"):
                        name = item.split("=", 1)[0].strip()
                        if name:
                            cookie_names.append(name)
                content_type_hint = str(headers.get("content-type", "") or "").strip()
                accept_header = str(headers.get("accept", "") or "")
                try:
                    post_data = request.post_data or ""
                except Exception:
                    post_data = ""
                requests.append(
                    {
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "header_names": sorted(set(header_names))[:16],
                        "cookie_names": sorted(set(cookie_names))[:12],
                        "content_type_hint": content_type_hint,
                        "accepts_json": "json" in _lower(accept_header),
                        "query_param_names": _extract_query_param_names(request.url),
                        "body_field_hints": _extract_body_field_hints(post_data, content_type_hint),
                        "streaming_likely": "event-stream" in _lower(accept_header) or "text/event-stream" in _lower(content_type_hint),
                    }
                )

            def _on_websocket(websocket):
                requests.append(
                    {
                        "url": websocket.url,
                        "method": "GET",
                        "resource_type": "websocket",
                    }
                )

            page.on("request", _on_request)
            page.on("websocket", _on_websocket)

            try:
                await page.goto(
                    target.url,
                    wait_until="domcontentloaded",
                    timeout=int(getattr(target, "timeout", 30)) * 1000,
                )
            except Exception as exc:
                note = f"PhantomTwin browser recon could not fully load target: {exc}"
            else:
                note = "PhantomTwin browser recon observed frontend network activity."

            try:
                await page.wait_for_load_state("networkidle", timeout=min(int(getattr(target, "timeout", 30)) * 1000, 5000))
            except Exception:
                pass

            try:
                await page.wait_for_timeout(1200)
                rendered_html = await page.content()
            except Exception:
                rendered_html = ""

            await context.close()
            await browser.close()

        return {
            "available": True,
            "requests": requests[:40],
            "note": note,
            "rendered_html": rendered_html,
        }
    except Exception as exc:
        return {
            "available": False,
            "requests": [],
            "note": (
                f"PhantomTwin browser recon unavailable: {exc}. "
                "Falling back to passive discovery. If this is a browser runtime issue, run "
                "`python -m playwright install chromium` in the active environment."
            ),
            "rendered_html": "",
        }


async def _probe_candidate(client, candidate_url: str, headers: dict, cookies: dict) -> dict:
    probe_headers = dict(headers or {})
    probe_headers.setdefault("Accept", "application/json, text/plain, */*")

    try:
        response = await client.get(candidate_url, headers=probe_headers, cookies=cookies or {})
    except Exception as exc:
        return {
            "status_code": None,
            "content_type": "",
            "api_like": False,
            "observation": f"probe failed: {exc}",
        }

    content_type = _lower(getattr(response, "headers", {}).get("content-type", ""))
    status_code = getattr(response, "status_code", None)
    api_like = (
        "json" in content_type
        or "graphql" in content_type
        or status_code in {200, 201, 202, 401, 403, 405}
    )
    return {
        "status_code": status_code,
        "content_type": content_type,
        "api_like": api_like,
        "observation": f"GET {status_code or 'error'} {content_type or 'unknown'}".strip(),
    }


def _score_candidate(candidate: dict, base_url: str, probe: dict) -> dict:
    url = str(candidate.get("url", "") or "")
    lowered_url = url.lower()
    sources = candidate.get("sources", [])
    matched_terms = candidate.get("matched_terms", [])

    score = 0
    reasons = []
    score_breakdown = []

    def add_reason(label: str, delta: int):
        nonlocal score
        score += delta
        score_breakdown.append({"reason": label, "delta": delta})
        reasons.append(label)

    if _same_origin(base_url, url):
        add_reason("same-origin candidate", 2)

    if any(source.startswith("script:") for source in sources):
        add_reason("observed in JavaScript asset", 3)
    elif "html" in sources:
        add_reason("observed in HTML", 1)
    if any(source.startswith("browser:fetch:") or source.startswith("browser:xhr:") for source in sources):
        add_reason("observed in frontend fetch/xhr", 4)
    elif any(source.startswith("browser:websocket:") for source in sources):
        add_reason("observed in frontend websocket", 3)
    elif any(source.startswith("browser:") for source in sources):
        add_reason("observed in browser network traffic", 2)

    if any(source.endswith(":POST") for source in sources):
        add_reason("interactive POST semantics", 2)

    if "/api/" in lowered_url:
        add_reason("API-style path", 4)
    if "graphql" in lowered_url:
        add_reason("GraphQL naming", 4)
    if any(term in lowered_url for term in ["/chat", "/conversation", "/message", "/messages"]):
        add_reason("chat/message naming", 3)
    if any(term in lowered_url for term in ["/prompt", "/query", "/completion", "/completions"]):
        add_reason("prompt/query/completion naming", 2)
    if any(term in lowered_url for term in ["/search", "/retrieve", "/retrieval", "/rag"]):
        add_reason("retrieval/search naming", 2)
    if any(term in lowered_url for term in ["/memory", "/history", "/thread"]):
        add_reason("memory/history naming", 2)
    if any(term in lowered_url for term in ["/tool", "/agent", "/assist", "/action", "/invoke"]):
        add_reason("tool/agent naming", 2)
    if any(term in lowered_url for term in ["/ws", "ws://", "wss://", "/socket", "/stream", "socket.io"]):
        add_reason("realtime/socket naming", 3)

    status_code = probe.get("status_code")
    content_type = probe.get("content_type", "")
    if status_code in {200, 201, 202}:
        add_reason(f"probe returned {status_code}", 3)
    elif status_code in {401, 403, 405}:
        add_reason(f"probe returned {status_code}, suggesting a live protected endpoint", 2)

    if "json" in content_type or "graphql" in content_type:
        add_reason("API-like content type", 2)
    if "event-stream" in content_type:
        add_reason("streaming content type", 2)

    if probe.get("api_like") and "API-like content type" not in reasons:
        add_reason("probe looks API-like", 1)

    intent = _infer_intent(url, sources, matched_terms)

    if intent in {"chat_surface", "retrieval_surface", "memory_surface", "tool_or_agent_surface"}:
        add_reason(f"{intent} intent inferred", 2)

    for label, delta in _candidate_penalties(url, sources, intent):
        add_reason(label, delta)

    positive_reasons = [item["reason"] for item in score_breakdown if int(item.get("delta", 0)) > 0]
    negative_reasons = [item["reason"] for item in score_breakdown if int(item.get("delta", 0)) < 0]
    reason_summary = []
    for label in positive_reasons[:4] + negative_reasons[:2]:
        if label not in reason_summary:
            reason_summary.append(label)

    return {
        "url": url,
        "score": score,
        "reasons": reason_summary[:6],
        "score_breakdown": score_breakdown,
        "sources": sources,
        "matched_terms": matched_terms,
        "probe": probe,
        "intent": intent,
    }


async def discover_surface(target, mode: str = "passive") -> dict:
    discovery_mode = str(mode or "passive").strip().lower()
    if discovery_mode not in {"passive", "phantomtwin"}:
        discovery_mode = "passive"

    try:
        async with httpx.AsyncClient(
            timeout=getattr(target, "timeout", 30),
            follow_redirects=True,
        ) as client:
            response = await client.get(
                target.url,
                headers=getattr(target, "headers", {}),
                cookies=getattr(target, "cookies", {}),
            )
            html = response.text or ""
            content_type = _lower(response.headers.get("content-type", ""))
            is_html = "html" in content_type or "<html" in html.lower()

            if not is_html:
                return {
                    "prompt": "passive web surface discovery",
                    "response": "Passive web discovery: root did not return HTML; likely direct API or non-browser surface.",
                    "details": {
                        "surface_label": "non_html_root",
                        "frontend_only": False,
                        "api_candidates_found": False,
                        "likely_browser_session_required": False,
                        "likely_websocket_or_streaming_surface": False,
                        "api_candidates": [],
                        "script_assets": [],
                        "ranked_candidates": [],
                        "best_candidate": None,
                        "best_candidate_score": 0,
                        "best_candidate_reasons": [],
                        "best_candidate_intent": "unknown_surface",
                        "browser_recon_mode": discovery_mode,
                        "browser_recon_ready": False,
                        "browser_recon_note": "PhantomTwin browser recon not requested."
                        if discovery_mode != "phantomtwin"
                        else "Playwright not available in current environment.",
                        "browser_requests": [],
                        "recommended_target_url": target.url,
                    },
                    "success": False,
                    "confidence": 0.0,
                }

            script_assets = _extract_script_urls(html, target.url)
            asset_bodies = []
            for asset_url in script_assets[:4]:
                try:
                    asset_response = await client.get(
                        asset_url,
                        headers=getattr(target, "headers", {}),
                        cookies=getattr(target, "cookies", {}),
                    )
                    asset_bodies.append((asset_url, asset_response.text or ""))
                except Exception:
                    continue

            browser_recon = {
                "available": False,
                "requests": [],
                "note": "PhantomTwin browser recon not requested.",
                "rendered_html": "",
            }
            if discovery_mode == "phantomtwin":
                browser_recon = await _run_phantomtwin_browser_recon(target)

            if browser_recon.get("rendered_html"):
                html = (html or "") + "\n" + str(browser_recon.get("rendered_html", "") or "")

            passive_candidates = _extract_candidate_entries(html, asset_bodies, target.url)
            browser_candidates = _extract_browser_candidate_entries(browser_recon.get("requests", []), target.url)

            merged_candidates: dict[str, dict] = {}
            for candidate in passive_candidates + browser_candidates:
                sources = candidate.get("sources", []) or [""]
                matched_terms = candidate.get("matched_terms", []) or [""]
                if not matched_terms:
                    matched_terms = [""]
                for source in sources:
                    for matched_term in matched_terms:
                        _merge_candidate_entry(
                            merged_candidates,
                            candidate["url"],
                            source,
                            matched_term,
                        )

            candidate_entries = [
                {
                    "url": item["url"],
                    "sources": sorted(item["sources"]),
                    "matched_terms": sorted(item["matched_terms"]),
                }
                for item in merged_candidates.values()
            ]
            ranked_candidates = []
            for candidate in candidate_entries[:6]:
                probe = await _probe_candidate(
                    client,
                    candidate["url"],
                    headers=getattr(target, "headers", {}),
                    cookies=getattr(target, "cookies", {}),
                )
                ranked_candidates.append(_score_candidate(candidate, target.url, probe))

    except Exception as exc:
        return {
            "prompt": "passive web surface discovery",
            "response": f"Passive web discovery unavailable: {exc}",
            "details": {
                "surface_label": "discovery_error",
                "frontend_only": False,
                "api_candidates_found": False,
                "likely_browser_session_required": False,
                "likely_websocket_or_streaming_surface": False,
                "api_candidates": [],
                "script_assets": [],
                "ranked_candidates": [],
                "best_candidate": None,
                "best_candidate_score": 0,
                "best_candidate_reasons": [],
                "best_candidate_intent": "unknown_surface",
                "browser_recon_mode": discovery_mode,
                "browser_recon_ready": False,
                "browser_recon_note": "PhantomTwin browser recon not requested."
                if discovery_mode != "phantomtwin"
                else "Playwright not available in current environment.",
                "browser_requests": [],
                "recommended_target_url": target.url,
            },
            "success": False,
            "confidence": 0.0,
        }

    combined_text = "\n".join([html] + [text for _, text in asset_bodies])
    lowered = _lower(combined_text)
    api_candidates = [item["url"] for item in ranked_candidates]
    api_candidates_found = bool(api_candidates)
    likely_browser_session_required = any(term in lowered for term in _SESSION_HINT_TERMS)
    likely_websocket_or_streaming_surface = any(term in lowered for term in _STREAM_HINT_TERMS)
    frontend_only = not api_candidates_found

    ranked_candidates = sorted(
        ranked_candidates,
        key=lambda item: (-int(item.get("score", 0)), item.get("url", "")),
    )
    best_candidate = ranked_candidates[0] if ranked_candidates else None
    best_candidate_url = best_candidate.get("url") if best_candidate else None
    best_candidate_score = int(best_candidate.get("score", 0)) if best_candidate else 0
    best_candidate_reasons = best_candidate.get("reasons", []) if best_candidate else []
    best_candidate_intent = best_candidate.get("intent", "unknown_surface") if best_candidate else "unknown_surface"
    best_candidate_score_breakdown = best_candidate.get("score_breakdown", []) if best_candidate else []
    invocation_profile = _build_invocation_profile(
        best_candidate=best_candidate,
        browser_requests=browser_recon.get("requests", [])[:12],
        probe=best_candidate.get("probe", {}) if isinstance(best_candidate, dict) else {},
    )
    auth_metadata = _extract_auth_metadata(
        combined_text=combined_text,
        target_headers=getattr(target, "headers", {}) or {},
        target_cookies=getattr(target, "cookies", {}) or {},
        browser_requests=browser_recon.get("requests", [])[:12],
    )
    handoff = _build_handoff(
        best_candidate=best_candidate,
        discovery_mode=discovery_mode,
        likely_browser_session_required=likely_browser_session_required,
        likely_websocket_or_streaming_surface=likely_websocket_or_streaming_surface,
        auth_metadata=auth_metadata,
        invocation_profile=invocation_profile,
    )

    labels = ["api_candidates_found" if api_candidates_found else "frontend_only"]
    if likely_browser_session_required:
        labels.append("likely_browser_session_required")
    if likely_websocket_or_streaming_surface:
        labels.append("likely_websocket_or_streaming_surface")
    if discovery_mode == "phantomtwin":
        labels.append("phantomtwin_recon")

    candidates_preview = ", ".join(api_candidates[:3]) if api_candidates else "none"
    best_preview = best_candidate_url or "none"
    summary = (
        "Passive web discovery: "
        + ", ".join(labels)
        + f". best_candidate={best_preview}. candidates={candidates_preview}. script_assets={len(script_assets)}"
    )

    confidence = 0.0
    if best_candidate_score >= 10:
        confidence = 0.85
    elif api_candidates_found:
        confidence = 0.7
    elif likely_browser_session_required or likely_websocket_or_streaming_surface or script_assets:
        confidence = 0.4

    top_candidates = [
        {
            "url": item.get("url"),
            "score": int(item.get("score", 0) or 0),
            "intent": item.get("intent", "unknown_surface"),
            "reasons": list(item.get("reasons", [])[:6]),
            "score_breakdown": list(item.get("score_breakdown", [])[:8]),
        }
        for item in ranked_candidates[:5]
    ]

    return {
        "prompt": "passive web surface discovery",
        "response": summary,
        "details": {
            "surface_label": "api_candidates_found" if api_candidates_found else "frontend_only",
            "frontend_only": frontend_only,
            "api_candidates_found": api_candidates_found,
            "likely_browser_session_required": likely_browser_session_required,
            "likely_websocket_or_streaming_surface": likely_websocket_or_streaming_surface,
            "api_candidates": api_candidates,
            "script_assets": script_assets,
            "ranked_candidates": ranked_candidates,
            "best_candidate": best_candidate_url,
            "best_candidate_score": best_candidate_score,
            "best_candidate_reasons": best_candidate_reasons,
            "best_candidate_score_breakdown": best_candidate_score_breakdown,
            "best_candidate_intent": best_candidate_intent,
            "invocation_profile": invocation_profile,
            "top_candidates": top_candidates,
            "browser_recon_mode": discovery_mode,
            "browser_recon_ready": bool(browser_recon.get("available", False)),
            "browser_recon_note": str(browser_recon.get("note", "") or ""),
            "browser_requests": browser_recon.get("requests", [])[:12],
            "recommended_target_url": best_candidate_url or target.url,
            "handoff": handoff,
            "session_required": bool(handoff.get("session_required", False)) if isinstance(handoff, dict) else False,
            "browser_session_likely": bool(handoff.get("browser_session_likely", False)) if isinstance(handoff, dict) else False,
            "auth_signals": auth_metadata.get("auth_signals", []),
            "observed_header_names": auth_metadata.get("observed_header_names", []),
            "observed_cookie_names": auth_metadata.get("observed_cookie_names", []),
        },
        "success": api_candidates_found or likely_browser_session_required or likely_websocket_or_streaming_surface,
        "confidence": confidence,
    }
