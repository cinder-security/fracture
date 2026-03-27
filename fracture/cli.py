import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(
    name="fracture",
    help="Autonomous AI Red Team Engine",
    add_completion=False,
)
console = Console()

BANNER = """[bold red]
  ███████╗██████╗  █████╗  ██████╗████████╗██╗   ██╗██████╗ ███████╗
  ██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝
  █████╗  ██████╔╝███████║██║        ██║   ██║   ██║██████╔╝█████╗
  ██╔══╝  ██╔══██╗██╔══██║██║        ██║   ██║   ██║██╔══██╗██╔══╝
  ██║     ██║  ██║██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║███████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝[/bold red]
[dim]  Autonomous AI Red Team Engine — v0.1.0[/dim]
[italic red]  "Find the fracture before someone else does."[/italic red]
[dim]  cindersecurity.io · github.com/cinder-security/fracture[/dim]
"""


def _save_result_json(result, output_path: str):
    payload = {
        "module": getattr(result, "module", "unknown"),
        "target_url": getattr(result, "target_url", "unknown"),
        "success": getattr(result, "success", False),
        "confidence": getattr(result, "confidence", 0.0),
        "notes": getattr(result, "notes", ""),
        "timestamp": getattr(result, "timestamp", ""),
        "evidence": getattr(result, "evidence", {}),
    }

    with open(output_path, "w") as f:
        json.dump(payload, f, indent=2)

    _print_output_saved("Result JSON", output_path)


def _parse_key_value_pairs(items: Optional[list[str]], label: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise typer.BadParameter(f"Invalid {label} '{item}'. Use KEY=VALUE.")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise typer.BadParameter(f"Invalid {label} '{item}'. Key must not be empty.")
        parsed[key] = value
    return parsed


def _build_target(
    *,
    target_url: str,
    model: Optional[str] = None,
    headers: Optional[list[str]] = None,
    cookies: Optional[list[str]] = None,
    session_cookies: Optional[list[dict]] = None,
    timeout: int = 30,
    body_key: Optional[str] = None,
    body_fields: Optional[list[str]] = None,
):
    from fracture.core.target import AITarget

    return AITarget(
        url=target_url,
        model=model,
        headers=_parse_key_value_pairs(headers, "header"),
        cookies=_parse_key_value_pairs(cookies, "cookie"),
        session_cookies=list(session_cookies or []),
        timeout=timeout,
        body_key=body_key or None,
        body_fields=_parse_key_value_pairs(body_fields, "body-field"),
    )


def _sanitize_scan_header_names(headers: dict) -> list[str]:
    return sorted(str(key).strip() for key in (headers or {}).keys() if str(key).strip())


def _sanitize_scan_cookie_names(cookies: dict) -> list[str]:
    return sorted(str(key).strip() for key in (cookies or {}).keys() if str(key).strip())


def _dedupe_text(items) -> list[str]:
    ordered = []
    for item in items or []:
        value = str(item or "").strip()
        if value and value not in ordered:
            ordered.append(value)
    return ordered


def _auth_material_types(headers: dict, cookies: dict) -> list[str]:
    material_types = []
    if headers:
        material_types.append("headers")
    if cookies:
        material_types.append("cookies")
    return material_types


def _print_output_saved(label: str, output_path: str):
    console.print(f"\n[dim]{label} saved to {output_path}[/dim]")


def _extract_handoff_session_cookies(handoff: dict | None) -> list[dict]:
    if not isinstance(handoff, dict):
        return []

    cookies = handoff.get("session_cookies", [])
    if not isinstance(cookies, list):
        return []

    normalized = []
    for item in cookies:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "").strip()
        if not name:
            continue
        normalized.append(
            {
                "name": name,
                "value": str(item.get("value", "") or ""),
                "domain": str(item.get("domain", "") or ""),
                "path": str(item.get("path", "/") or "/"),
            }
        )
    return normalized


def _build_session_context(target, handoff: dict | None = None) -> dict:
    target_context = getattr(target, "session_context", {}) if target is not None else {}
    if isinstance(target_context, dict) and target_context:
        return dict(target_context)

    handoff = handoff if isinstance(handoff, dict) else {}
    return {
        "session_material_present": bool(handoff.get("session_material_present")),
        "session_cookie_count": int(handoff.get("session_cookie_count", 0) or 0),
        "session_cookie_names": list(handoff.get("session_cookie_names", []) or []),
        "session_cookie_domains": list(handoff.get("session_cookie_domains", []) or []),
        "session_cookie_source": str(handoff.get("session_cookie_source", "none") or "none"),
        "session_cookie_merge_strategy": str(handoff.get("session_cookie_merge_strategy", "no_session_material") or "no_session_material"),
        "session_cookie_header_redacted": bool(handoff.get("session_cookie_header_redacted", False)),
        "session_scope_applied": bool(handoff.get("session_scope_applied", False)),
        "session_propagation_note": str(handoff.get("session_propagation_note", "") or ""),
    }


def _build_auth_wall_context(handoff: dict | None = None, surface_details: dict | None = None) -> dict:
    handoff = handoff if isinstance(handoff, dict) else {}
    surface_details = surface_details if isinstance(surface_details, dict) else {}

    def pick(key: str, default=None):
        if key in handoff:
            return handoff.get(key)
        return surface_details.get(key, default)

    return {
        "auth_wall_detected": bool(pick("auth_wall_detected", False)),
        "auth_wall_type": str(pick("auth_wall_type", "no_auth_wall") or "no_auth_wall"),
        "auth_wall_confidence": float(pick("auth_wall_confidence", 0.0) or 0.0),
        "auth_success_markers": list(pick("auth_success_markers", []) or []),
        "already_authenticated_signals": list(pick("already_authenticated_signals", []) or []),
        "manual_login_recommended": bool(pick("manual_login_recommended", False)),
        "session_capture_readiness": str(pick("session_capture_readiness", "low") or "low"),
        "post_login_surface_score": int(pick("post_login_surface_score", 0) or 0),
        "auth_opportunity_score": int(pick("auth_opportunity_score", 0) or 0),
        "auth_opportunity_level": str(pick("auth_opportunity_level", "low") or "low"),
        "post_login_surface_label": str(pick("post_login_surface_label", "unknown_surface") or "unknown_surface"),
        "auth_wall_rationale": str(pick("auth_wall_rationale", "") or ""),
    }


def _sanitize_cookie_mapping_for_output(cookies: dict | None) -> dict:
    sanitized = {}
    for key in sorted((cookies or {}).keys()):
        name = str(key or "").strip()
        if name:
            sanitized[name] = "<redacted>"
    return sanitized


def _sanitize_header_mapping_for_output(headers: dict | None) -> dict:
    sanitized = {}
    sensitive_tokens = ("authorization", "cookie", "token", "secret", "key", "csrf", "xsrf")
    for key, value in (headers or {}).items():
        name = str(key or "").strip()
        if not name:
            continue
        if any(token in name.lower() for token in sensitive_tokens):
            sanitized[name] = "<redacted>"
        else:
            sanitized[name] = value
    return sanitized


def _sanitize_handoff_for_output(handoff: dict | None) -> dict | None:
    if not isinstance(handoff, dict) or not handoff:
        return handoff

    sanitized = dict(handoff)
    if isinstance(sanitized.get("session_cookies"), list):
        sanitized["session_cookies"] = [
            {
                "name": str(item.get("name", "") or "").strip(),
                "value": "<redacted>",
                "domain": str(item.get("domain", "") or ""),
                "path": str(item.get("path", "/") or "/"),
            }
            for item in sanitized.get("session_cookies", [])
            if isinstance(item, dict) and str(item.get("name", "") or "").strip()
        ]
    if "session_cookie_header" in sanitized:
        sanitized["session_cookie_header"] = str(sanitized.get("session_cookie_header", "") or "")
    return sanitized


def _print_operator_cue(title: str, lines: list[str]):
    useful_lines = [str(line).strip() for line in lines if str(line or "").strip()]
    if not useful_lines:
        return
    console.print(Panel(
        "\n".join(f"[dim]{line}[/dim]" for line in useful_lines[:4]),
        title=f"[bold yellow]{title}[/bold yellow]",
        border_style="yellow",
    ))


def _build_auth_context(
    *,
    handoff: dict | None = None,
    surface_details: dict | None = None,
    target_headers: dict | None = None,
    target_cookies: dict | None = None,
) -> dict:
    handoff = handoff if isinstance(handoff, dict) else {}
    surface_details = surface_details if isinstance(surface_details, dict) else {}
    target_headers = target_headers or {}
    target_cookies = target_cookies or {}

    observed_header_names = list(
        handoff.get("observed_header_names")
        or surface_details.get("observed_header_names")
        or []
    )
    observed_cookie_names = list(
        handoff.get("observed_cookie_names")
        or surface_details.get("observed_cookie_names")
        or []
    )
    auth_signals = list(
        handoff.get("auth_signals")
        or surface_details.get("auth_signals")
        or []
    )
    observed_auth_names = _dedupe_text(
        auth_signals + observed_header_names + observed_cookie_names
    )[:8]

    auth_material_types = _auth_material_types(target_headers, target_cookies)
    auth_material_provided = bool(auth_material_types)
    session_required = bool(
        handoff.get("session_required", surface_details.get("session_required", False))
    )
    browser_session_likely = bool(
        handoff.get("browser_session_likely", surface_details.get("browser_session_likely", False))
    )
    auth_friction_present = bool(
        session_required or browser_session_likely or observed_auth_names
    )

    best_candidate_score = int(surface_details.get("best_candidate_score", handoff.get("score", 0)) or 0)
    surface_label = str(surface_details.get("surface_label", "") or "").strip().lower()
    status = "generic_surface"
    if surface_label == "discovery_error":
        status = "transport_or_discovery_error"
    elif best_candidate_score >= 8 and auth_friction_present:
        status = "useful_surface_with_auth_friction"
    elif best_candidate_score >= 8:
        status = "useful_surface"
    elif surface_label in {"frontend_only", "non_html_root"}:
        status = "weak_or_indirect_surface"

    auth_friction_rationale = ""
    if status == "transport_or_discovery_error":
        auth_friction_rationale = "Surface discovery hit a transport or discovery failure; do not treat this as an auth-gated negative result."
    elif auth_friction_present:
        auth_friction_rationale = (
            "Useful surface detected, but interaction likely requires session/auth context."
            if best_candidate_score >= 8
            else "Session/auth context may be required before surface coverage is representative."
        )

    suggested_material = []
    if observed_cookie_names or "cookie" in observed_auth_names or session_required:
        suggested_material.append("session cookies")
    if any("authorization" in name.lower() for name in observed_header_names + observed_auth_names):
        suggested_material.append("Authorization header")
    csrf_names = [
        name for name in observed_header_names + observed_auth_names
        if "csrf" in name.lower() or "xsrf" in name.lower()
    ]
    if csrf_names:
        suggested_material.append("CSRF/app-specific headers")
    if not suggested_material and auth_friction_present:
        suggested_material = ["session cookies", "Authorization header"]

    operational_limitations = []
    if auth_friction_present and not auth_material_provided:
        operational_limitations.append(
            "results may underrepresent reachable attack surface without valid session/auth context"
        )
    elif auth_friction_present and auth_material_provided:
        operational_limitations.append(
            "manual auth context is being applied, but coverage still depends on token/session validity"
        )

    manual_auth_rationale = ""
    if auth_material_provided:
        manual_auth_rationale = (
            "Manual auth context provided via " + ", ".join(auth_material_types) + "."
        )

    return {
        "auth_friction_present": auth_friction_present,
        "auth_friction_rationale": auth_friction_rationale,
        "auth_material_provided": auth_material_provided,
        "auth_material_types": auth_material_types,
        "manual_auth_rationale": manual_auth_rationale,
        "observed_auth_signal_names": observed_auth_names,
        "suggested_auth_material": _dedupe_text(suggested_material),
        "operational_limitations": _dedupe_text(operational_limitations),
        "coverage_constraints": _dedupe_text(operational_limitations),
        "status": status,
    }


def _load_scan_payload(scan_path: str) -> dict:
    try:
        with open(scan_path, "r") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        console.print(f"[red]Scan file '{scan_path}' not found.[/red]")
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[red]Could not read scan file '{scan_path}': {exc}[/red]")
        raise typer.Exit(code=1)

    if not isinstance(payload, dict):
        console.print(f"[red]Scan file '{scan_path}' does not contain a valid JSON object.[/red]")
        raise typer.Exit(code=1)

    return payload


def _resolve_attack_handoff(scan_path: Optional[str]) -> dict | None:
    if not scan_path:
        return None

    payload = _load_scan_payload(scan_path)
    handoff = payload.get("handoff", {})
    if isinstance(handoff, dict) and handoff.get("recommended_target_url"):
        return handoff

    details = (
        payload.get("fingerprint", {})
        .get("evidence", {})
        .get("surface_discovery", {})
        .get("details", {})
    )
    if isinstance(details, dict):
        handoff = details.get("handoff", {})
        if isinstance(handoff, dict) and handoff.get("recommended_target_url"):
            return handoff

    console.print(f"[red]Scan file '{scan_path}' does not contain a usable handoff.[/red]")
    console.print("[dim]Run `fracture scan --output scan.json` on a target with a discovered endpoint first.[/dim]")
    raise typer.Exit(code=1)


def _print_attack_handoff_summary(
    handoff: dict,
    explicit_target: Optional[str],
    target_headers: dict,
    target_cookies: dict,
    session_context: dict | None = None,
):
    if not isinstance(handoff, dict) or not handoff:
        return

    invocation_profile = handoff.get("invocation_profile", {}) if isinstance(handoff, dict) else {}
    auth_context = _build_auth_context(
        handoff=handoff,
        target_headers=target_headers,
        target_cookies=target_cookies,
    )
    session_context = session_context if isinstance(session_context, dict) else {}
    auth_wall_context = _build_auth_wall_context(handoff, None)
    invocation_summary = "none"
    if isinstance(invocation_profile, dict) and invocation_profile:
        invocation_summary = (
            f"{invocation_profile.get('method_hint', 'unknown')} "
            f"{invocation_profile.get('content_type_hint') or 'unknown'} "
            f"body={','.join(invocation_profile.get('observed_body_keys', [])[:3]) or 'none'} "
            f"query={','.join(invocation_profile.get('observed_query_param_names', [])[:3]) or 'none'} "
            f"stream={'yes' if invocation_profile.get('streaming_likely') else 'no'} "
            f"ws={'yes' if invocation_profile.get('websocket_likely') else 'no'}"
        )

    console.print(Panel(
        f"[bold]Used Target:[/bold]    [cyan]{explicit_target or handoff.get('recommended_target_url', 'unknown')}[/cyan]\n"
        f"[bold]Handoff URL:[/bold]  [dim]{handoff.get('recommended_target_url', 'unknown')}[/dim]\n"
        f"[bold]Intent:[/bold]       [dim]{handoff.get('intent', 'unknown_surface')}[/dim]\n"
        f"[bold]Score:[/bold]        [dim]{handoff.get('score', 0)}[/dim]\n"
        f"[bold]Source Mode:[/bold]  [dim]{handoff.get('source_mode', 'unknown')}[/dim]\n"
        f"[bold]Transport:[/bold]    [dim]{handoff.get('transport_hint', 'unknown')}[/dim]\n"
        f"[bold]Method Hint:[/bold]  [dim]{handoff.get('method_hint', 'unknown')}[/dim]\n"
        f"[bold]Invocation:[/bold]   [dim]{invocation_summary}[/dim]\n"
        f"[bold]Session Req:[/bold]  [dim]{'yes' if handoff.get('session_required') else 'no'}[/dim]\n"
        f"[bold]Auth Signals:[/bold] [dim]{', '.join(handoff.get('auth_signals', []) or []) or 'none'}[/dim]\n"
        f"[bold]Observed Auth:[/bold] [dim]{', '.join(auth_context.get('observed_auth_signal_names', [])[:5]) or 'none'}[/dim]\n"
        f"[bold]Manual Auth:[/bold] [dim]{auth_context.get('manual_auth_rationale') or 'none provided'}[/dim]\n"
        f"[bold]Auth Wall:[/bold] [dim]{auth_wall_context.get('auth_wall_type', 'no_auth_wall')} / "
        f"{auth_wall_context.get('auth_opportunity_level', 'low')}[/dim]\n"
        f"[bold]Session Material:[/bold] [dim]{'present' if session_context.get('session_material_present') else 'none'}[/dim]\n"
        f"[bold]Session Cookies:[/bold] [dim]{session_context.get('session_cookie_count', 0)}; "
        f"{', '.join(session_context.get('session_cookie_names', [])[:4]) or 'none'}[/dim]\n"
        f"[bold]Session Domains:[/bold] [dim]{', '.join(session_context.get('session_cookie_domains', [])[:3]) or 'none'}[/dim]\n"
        f"[bold]Session Source:[/bold] [dim]{session_context.get('session_cookie_source', 'none')} / "
        f"{session_context.get('session_cookie_merge_strategy', 'unknown')}[/dim]",
        title="[bold yellow]Attack Handoff[/bold yellow]",
        border_style="yellow",
    ))

    if explicit_target:
        console.print("[yellow]Explicit --target provided; overriding handoff recommended_target_url.[/yellow]")

    if auth_context.get("auth_friction_present") and auth_context.get("auth_material_provided"):
        console.print(
            "[yellow]Manual auth context will be applied during execution. "
            f"Types: {', '.join(auth_context.get('auth_material_types', []))}.[/yellow]"
        )

    if auth_context.get("auth_friction_present") and not auth_context.get("auth_material_provided"):
        console.print(
            "[yellow]Useful surface detected, but session/auth friction is likely and no manual auth context was provided. "
            f"Helpful material if available: {', '.join(auth_context.get('suggested_auth_material', [])[:3]) or 'session cookies, Authorization header'}. "
            "Continuing without auth material; weak/negative results may underrepresent reachable surface.[/yellow]"
        )

    for limitation in auth_context.get("operational_limitations", [])[:2]:
        console.print(f"[dim]Coverage limitation: {limitation}[/dim]")
    if session_context.get("session_cookie_header_redacted"):
        console.print("[dim]Session cookie header is redacted in operator-facing output.[/dim]")
    if session_context.get("session_propagation_note"):
        console.print(f"[dim]{session_context.get('session_propagation_note')}[/dim]")


def _build_execution_hints(handoff: dict | None) -> dict | None:
    if not isinstance(handoff, dict) or not handoff:
        return None

    invocation_profile = handoff.get("invocation_profile", {})
    if not isinstance(invocation_profile, dict):
        invocation_profile = {}

    hints = {
        "method_hint": invocation_profile.get("method_hint") or handoff.get("method_hint"),
        "content_type_hint": invocation_profile.get("content_type_hint"),
        "accepts_json": bool(invocation_profile.get("accepts_json")),
        "observed_body_keys": list(invocation_profile.get("observed_body_keys", []) or []),
        "observed_query_param_names": list(invocation_profile.get("observed_query_param_names", []) or []),
        "session_required": bool(handoff.get("session_required")),
        "auth_signals": list(handoff.get("auth_signals", []) or []),
        "streaming_likely": bool(invocation_profile.get("streaming_likely")),
        "websocket_likely": bool(invocation_profile.get("websocket_likely")),
    }
    normalized = {
        key: value
        for key, value in hints.items()
        if value not in (None, False, [], "")
    }
    return normalized or None


def _print_execution_hints_summary(execution_hints: dict | None):
    if not isinstance(execution_hints, dict) or not execution_hints:
        return

    console.print(Panel(
        f"[bold]Method:[/bold]      [dim]{execution_hints.get('method_hint', 'unknown')}[/dim]\n"
        f"[bold]Content-Type:[/bold] [dim]{execution_hints.get('content_type_hint', 'unknown')}[/dim]\n"
        f"[bold]Accepts JSON:[/bold] [dim]{'yes' if execution_hints.get('accepts_json') else 'no'}[/dim]\n"
        f"[bold]Body Keys:[/bold]   [dim]{', '.join(execution_hints.get('observed_body_keys', [])[:4]) or 'none'}[/dim]\n"
        f"[bold]Query Keys:[/bold]  [dim]{', '.join(execution_hints.get('observed_query_param_names', [])[:4]) or 'none'}[/dim]\n"
        f"[bold]Session/Auth:[/bold] [dim]{'required' if execution_hints.get('session_required') else 'not indicated'}; "
        f"{', '.join(execution_hints.get('auth_signals', [])[:3]) or 'none'}[/dim]\n"
        f"[bold]Transport:[/bold]   [dim]stream={'yes' if execution_hints.get('streaming_likely') else 'no'} "
        f"ws={'yes' if execution_hints.get('websocket_likely') else 'no'}[/dim]",
        title="[bold yellow]Execution Hints[/bold yellow]",
        border_style="yellow",
    ))    


def _print_attack_graph_summary(attack_graph: dict | None):
    if not isinstance(attack_graph, dict) or not attack_graph:
        return
    summary = attack_graph.get("summary", {}) if isinstance(attack_graph.get("summary", {}), dict) else {}
    primary_path = " -> ".join(summary.get("primary_path", [])[:6]) or "none"
    blockers = "; ".join(summary.get("blockers", [])[:2]) or "none"
    dependency = summary.get("auth_or_session_dependency", "none") or "none"
    console.print(Panel(
        f"[bold]Attack Graph:[/bold] [dim]{summary.get('node_count', 0)} nodes / {summary.get('edge_count', 0)} edges[/dim]\n"
        f"[bold]Primary Path:[/bold] [dim]{primary_path}[/dim]\n"
        f"[bold]Blockers:[/bold] [dim]{blockers}[/dim]\n"
        f"[bold]Dependency:[/bold] [dim]{dependency}[/dim]",
        title="[bold yellow]Attack Graph[/bold yellow]",
        border_style="yellow",
    ))


def _print_adversarial_twin_summary(adversarial_twin: dict | None):
    if not isinstance(adversarial_twin, dict) or not adversarial_twin:
        return
    summary = adversarial_twin.get("summary", {}) if isinstance(adversarial_twin.get("summary", {}), dict) else {}
    surface_model = adversarial_twin.get("surface_model", {}) if isinstance(adversarial_twin.get("surface_model", {}), dict) else {}
    console.print(Panel(
        f"[bold]Twin:[/bold] [dim]{summary.get('overall_posture', 'unknown')} / attackability={summary.get('attackability', 'unknown')} / auth={summary.get('auth_dependency', 'unknown')}[/dim]\n"
        f"[bold]Surface:[/bold] [dim]{surface_model.get('primary_surface_type', 'unknown_surface')}[/dim]\n"
        f"[bold]Next Step:[/bold] [dim]{summary.get('recommended_next_step', 'none')}[/dim]\n"
        f"[bold]Rationale:[/bold] [dim]{summary.get('twin_rationale', 'none')}[/dim]",
        title="[bold yellow]Adversarial Twin[/bold yellow]",
        border_style="yellow",
    ))


def _print_phantomtwin_runtime_guard(mode: str):
    if str(mode or "passive").strip().lower() != "phantomtwin":
        return

    from fracture.core.surface_discovery import get_phantomtwin_runtime_status

    status = get_phantomtwin_runtime_status()
    if status.get("ready"):
        return

    console.print(Panel(
        f"[bold yellow]PhantomTwin runtime guard[/bold yellow]\n"
        f"[dim]{status.get('reason', '')}[/dim]\n"
        f"[dim]{status.get('hint', '')}[/dim]",
        border_style="yellow",
    ))


def _save_report_output(report, output_path: str, output_format: str):
    report_format = str(output_format or "json").strip().lower()

    if report_format == "docx":
        from fracture.reporting.docx_export import export_report_docx

        export_report_docx(report, output_path)
        _print_output_saved("DOCX report", output_path)
        return

    if report_format == "pdf":
        from fracture.reporting.pdf_export import export_report_pdf

        export_report_pdf(report, output_path)
        _print_output_saved("PDF report", output_path)
        return

    report.save(output_path)
    _print_output_saved("JSON report", output_path)


def _detect_transport_error(evidence: dict) -> bool:
    """Return True if any probe response in evidence signals a transport failure."""
    if not isinstance(evidence, dict):
        return False
    for value in evidence.values():
        if isinstance(value, dict):
            meta_response = str(value.get("best_response", "") or "")
            if meta_response.startswith("[error]"):
                return True
            for assessment_key in ("extract_assessment", "assessment", "classification"):
                if value.get(assessment_key) == "target_transport_error":
                    return True
            probes = value.get("probes", [])
            if isinstance(probes, list):
                for probe in probes:
                    if isinstance(probe, dict):
                        r = str(probe.get("response", "") or "")
                        if r.startswith("[error]"):
                            return True
                        if probe.get("extract_assessment") == "target_transport_error":
                            return True
                        if probe.get("classification") == "target_transport_error":
                            return True
    return False


def _print_transport_error_hint():
    console.print(Panel(
        "[yellow]All or most probes returned transport-level errors.[/yellow]\n"
        "The target may have rejected requests due to a mismatched JSON schema.\n\n"
        "[bold]Possible causes:[/bold]\n"
        "  • Target expects a specific field name (e.g. [cyan]message[/cyan], [cyan]input[/cyan], [cyan]query[/cyan])\n"
        "  • Target requires a static field not included in the probe body\n"
        "    (e.g. [cyan]session_id[/cyan], [cyan]tenant[/cyan], [cyan]api_version[/cyan])\n\n"
        "[bold]Suggested fixes:[/bold]\n"
        "  [dim]fracture attack --body-key message --body-field session_id=default ...[/dim]\n"
        "  [dim]fracture start  --body-key input   --body-field tenant=myorg ...[/dim]",
        title="[bold yellow]Transport Error — Body Schema Mismatch?[/bold yellow]",
        border_style="yellow",
    ))


def _print_generic_result(result):
    module_name = getattr(result, "module", "unknown")
    success = getattr(result, "success", False)
    confidence = getattr(result, "confidence", 0.0)
    notes = getattr(result, "notes", "")
    timestamp = getattr(result, "timestamp", "")
    evidence = getattr(result, "evidence", {}) or {}

    status = "[green]✅ SUCCESS[/green]" if success else "[red]❌ FAILED[/red]"
    conf_color = "green" if confidence > 0.5 else "yellow" if confidence > 0.2 else "red"

    console.print(Panel(
        f"[bold]Module:[/bold]    [cyan]{module_name}[/cyan]\n"
        f"[bold]Status:[/bold]    {status}\n"
        f"[bold]Confidence:[/bold] [{conf_color}]{confidence:.0%}[/{conf_color}]\n"
        f"[bold]Notes:[/bold]     [dim]{notes}[/dim]\n"
        f"[bold]Timestamp:[/bold] [dim]{timestamp}[/dim]",
        title=f"[bold red]{module_name.upper()} Summary[/bold red]",
        border_style="red",
    ))

    if evidence:
        table = Table(
            title=f"[bold red]{module_name.upper()} Evidence[/bold red]",
            show_lines=True,
            border_style="red",
            header_style="bold white on red",
        )
        table.add_column("Key", style="cyan", max_width=24)
        table.add_column("Value", style="white", max_width=100)

        for key, value in evidence.items():
            rendered = str(value)
            if len(rendered) > 500:
                rendered = rendered[:500] + "..."
            table.add_row(str(key), rendered)

        console.print(table)

    if not success and _detect_transport_error(evidence):
        _print_transport_error_hint()


def _print_scan_result(target, fingerprint, plan: dict, discovery_mode: str = "passive"):
    attack_plan = plan.get("attack_plan", []) if isinstance(plan, dict) else []
    attack_plan_str = ", ".join(attack_plan) if attack_plan else "none"
    fingerprint_meta = {}
    if getattr(fingerprint, "evidence", None) and isinstance(fingerprint.evidence, dict):
        fingerprint_meta = fingerprint.evidence.get("_meta", {}) or {}
    surface_details = {}
    if getattr(fingerprint, "evidence", None) and isinstance(fingerprint.evidence, dict):
        raw_surface = fingerprint.evidence.get("surface_discovery", {}) or {}
        if isinstance(raw_surface, dict):
            surface_details = raw_surface.get("details", {}) or {}

    risk_level = str(plan.get("risk_level", "unknown")) if isinstance(plan, dict) else "unknown"
    risk_color = "red" if risk_level in {"high", "critical"} else "yellow"
    surface_label = surface_details.get("surface_label", "unknown")
    browser_hint = "yes" if surface_details.get("likely_browser_session_required") else "no"
    realtime_hint = "yes" if surface_details.get("likely_websocket_or_streaming_surface") else "no"
    candidates = surface_details.get("api_candidates", []) if isinstance(surface_details, dict) else []
    candidates_text = ", ".join(candidates[:3]) if candidates else "none"
    best_candidate = surface_details.get("best_candidate", "none")
    best_candidate_score = surface_details.get("best_candidate_score", 0)
    best_candidate_reasons = surface_details.get("best_candidate_reasons", []) or []
    best_candidate_reason_text = ", ".join(best_candidate_reasons[:3]) if best_candidate_reasons else "none"
    best_candidate_intent = surface_details.get("best_candidate_intent", "unknown_surface")
    best_candidate_breakdown = surface_details.get("best_candidate_score_breakdown", []) or []
    browser_recon_note = surface_details.get("browser_recon_note", "")
    handoff = surface_details.get("handoff", {}) if isinstance(surface_details, dict) else {}
    auth_context = _build_auth_context(
        handoff=handoff,
        surface_details=surface_details,
        target_headers=getattr(target, "headers", {}),
        target_cookies=getattr(target, "cookies", {}),
    )
    handoff_method = handoff.get("method_hint", "unknown") if isinstance(handoff, dict) else "unknown"
    handoff_session = "yes" if isinstance(handoff, dict) and handoff.get("session_required") else "no"
    invocation_profile = surface_details.get("invocation_profile", {}) if isinstance(surface_details, dict) else {}
    top_candidates = surface_details.get("top_candidates", []) if isinstance(surface_details, dict) else []
    planning_rationale = plan.get("planning_rationale", []) if isinstance(plan, dict) else []
    planning_signals = plan.get("planning_signals_used", []) if isinstance(plan, dict) else []
    surface_constraints = plan.get("surface_constraints", []) if isinstance(plan, dict) else []
    top_candidates_text = " | ".join(
        f"{item.get('url')} ({item.get('score', 0)}, {item.get('intent', 'unknown_surface')})"
        for item in top_candidates[:3]
    ) if top_candidates else "none"
    best_breakdown_text = ", ".join(
        f"{item.get('reason')} ({item.get('delta', 0):+d})"
        for item in best_candidate_breakdown[:4]
    ) if best_candidate_breakdown else "none"
    invocation_summary = "none"
    if isinstance(invocation_profile, dict) and invocation_profile:
        invocation_summary = (
            f"{invocation_profile.get('method_hint', 'unknown')} "
            f"{invocation_profile.get('content_type_hint') or 'unknown'} "
            f"body={','.join(invocation_profile.get('observed_body_keys', [])[:3]) or 'none'} "
            f"query={','.join(invocation_profile.get('observed_query_param_names', [])[:3]) or 'none'} "
            f"stream={'yes' if invocation_profile.get('streaming_likely') else 'no'} "
            f"ws={'yes' if invocation_profile.get('websocket_likely') else 'no'}"
        )
    planning_signals_text = ", ".join(planning_signals[:4]) if planning_signals else "none"
    planning_rationale_text = " ; ".join(planning_rationale[:2]) if planning_rationale else str(plan.get("rationale", "") or "none")
    surface_constraints_text = " ; ".join(surface_constraints[:2]) if surface_constraints else "none"
    observed_auth_text = ", ".join(auth_context.get("observed_auth_signal_names", [])[:5]) or "none"
    manual_auth_text = auth_context.get("manual_auth_rationale") or "none provided"
    coverage_text = " ; ".join(auth_context.get("operational_limitations", [])[:2]) or "none"
    auth_friction_text = auth_context.get("auth_friction_rationale") or "none"
    surface_status = auth_context.get("status", "generic_surface")
    session_capture_note = surface_details.get("session_capture_note", "") if isinstance(surface_details, dict) else ""
    session_context = _build_session_context(None, handoff if isinstance(handoff, dict) else {})
    auth_wall_context = _build_auth_wall_context(handoff if isinstance(handoff, dict) else {}, surface_details)
    auth_wall_confidence_pct = int(round(auth_wall_context.get("auth_wall_confidence", 0.0) * 100))

    console.print(Panel(
        f"[bold]Target:[/bold]      [cyan]{getattr(target, 'url', 'unknown')}[/cyan]\n"
        f"[bold]Model Hint:[/bold]  [cyan]{getattr(target, 'model', None) or 'auto'}[/cyan]\n"
        f"[bold]Detected:[/bold]    [cyan]{plan.get('detected_model', 'unknown')}[/cyan]\n"
        f"[bold]Risk:[/bold]        [{risk_color}]{risk_level}[/{risk_color}]\n"
        f"[bold]Recon Mode:[/bold]  [cyan]{discovery_mode}[/cyan]\n"
        f"[bold]Surfaces:[/bold]    [green]{attack_plan_str}[/green]\n"
        f"[bold]Web Surface:[/bold] [cyan]{surface_label}[/cyan]\n"
        f"[bold]Browser/Auth:[/bold] [dim]{browser_hint}[/dim]\n"
        f"[bold]Realtime:[/bold]    [dim]{realtime_hint}[/dim]\n"
        f"[bold]Best Endpoint:[/bold] [cyan]{best_candidate}[/cyan]\n"
        f"[bold]Endpoint Score:[/bold] [dim]{best_candidate_score}[/dim]\n"
        f"[bold]Endpoint Intent:[/bold] [dim]{best_candidate_intent}[/dim]\n"
        f"[bold]Endpoint Why:[/bold] [dim]{best_candidate_reason_text}[/dim]\n"
        f"[bold]Score Detail:[/bold] [dim]{best_breakdown_text}[/dim]\n"
        f"[bold]Surface Status:[/bold] [dim]{surface_status}[/dim]\n"
        f"[bold]Invocation:[/bold]  [dim]{invocation_summary}[/dim]\n"
        f"[bold]Planning Signals:[/bold] [dim]{planning_signals_text}[/dim]\n"
        f"[bold]Constraints:[/bold] [dim]{surface_constraints_text}[/dim]\n"
        f"[bold]Session/Auth Constraint:[/bold] [dim]{auth_friction_text}[/dim]\n"
        f"[bold]Observed Auth Signals:[/bold] [dim]{observed_auth_text}[/dim]\n"
        f"[bold]Manual Auth Context:[/bold] [dim]{manual_auth_text}[/dim]\n"
        f"[bold]Coverage Limitation:[/bold] [dim]{coverage_text}[/dim]\n"
        f"[bold]Auth Wall:[/bold]   [dim]{auth_wall_context.get('auth_wall_type', 'no_auth_wall')} "
        f"({auth_wall_confidence_pct}% confidence)[/dim]\n"
        f"[bold]Opportunity:[/bold] [dim]{auth_wall_context.get('auth_opportunity_level', 'low')} "
        f"(score={auth_wall_context.get('auth_opportunity_score', 0)}/10)[/dim]\n"
        f"[bold]Manual Login:[/bold] [dim]{'recommended' if auth_wall_context.get('manual_login_recommended') else 'not recommended'}[/dim]\n"
        f"[bold]Capture Ready:[/bold] [dim]{auth_wall_context.get('session_capture_readiness', 'low')}[/dim]\n"
        f"[bold]Post-Login Surface:[/bold] [dim]{auth_wall_context.get('post_login_surface_label', 'unknown_surface')} "
        f"(score={auth_wall_context.get('post_login_surface_score', 0)}/10)[/dim]\n"
        f"[bold]Auth Rationale:[/bold] [dim]{auth_wall_context.get('auth_wall_rationale', '') or 'none'}[/dim]\n"
        f"[bold]Session Material:[/bold] [dim]{'present' if session_context.get('session_material_present') else 'none'}[/dim]\n"
        f"[bold]Session Cookies:[/bold] [dim]{session_context.get('session_cookie_count', 0)}; "
        f"{', '.join(session_context.get('session_cookie_names', [])[:4]) or 'none'}[/dim]\n"
        f"[bold]Session Domains:[/bold] [dim]{', '.join(session_context.get('session_cookie_domains', [])[:3]) or 'none'}[/dim]\n"
        f"[bold]Session Source:[/bold] [dim]{session_context.get('session_cookie_source', 'none')} / "
        f"{session_context.get('session_cookie_merge_strategy', 'unknown')}[/dim]\n"
        f"[bold]Handoff Method:[/bold] [dim]{handoff_method}[/dim]\n"
        f"[bold]Handoff Session:[/bold] [dim]{handoff_session}[/dim]\n"
        f"[bold]Candidates:[/bold]  [dim]{candidates_text}[/dim]\n"
        f"[bold]Top Candidates:[/bold] [dim]{top_candidates_text}[/dim]\n"
        f"[bold]Browser Recon:[/bold] [dim]{browser_recon_note}[/dim]\n"
        f"[bold]Probes Sent:[/bold] [dim]{fingerprint_meta.get('prompts_sent', 'unknown')}[/dim]\n"
        f"[bold]Analysis:[/bold]    [dim]{plan.get('analysis', '')}[/dim]\n"
        f"[bold]Why:[/bold]         [dim]{plan.get('rationale', '')}[/dim]\n"
        f"[bold]Priority Why:[/bold] [dim]{planning_rationale_text}[/dim]",
        title="[bold red]FRACTURE Scan Triage[/bold red]",
        border_style="red",
    ))

    if surface_details.get("login_form_detected"):
        console.print("[yellow]Login form detected during PhantomTwin recon.[/yellow]")
    if session_capture_note:
        console.print(f"[yellow]{session_capture_note}[/yellow]")
    if session_context.get("session_cookie_header_redacted"):
        console.print("[dim]Session cookie header is redacted in operator-facing output.[/dim]")

    evidence = getattr(fingerprint, "evidence", {}) or {}
    table = Table(
        title="[bold red]Fingerprint Signals[/bold red]",
        show_lines=True,
        border_style="red",
        header_style="bold white on red",
    )
    table.add_column("Probe", style="cyan", max_width=24)
    table.add_column("Signal", style="white", max_width=100)

    for key, value in evidence.items():
        if key == "_meta":
            continue
        response = value.get("response", "") if isinstance(value, dict) else str(value)
        response = str(response).strip()
        if len(response) > 160:
            response = response[:160] + "..."
        table.add_row(str(key), response or "no response")

    console.print(table)


def _serialize_attack_result(result) -> dict:
    return {
        "module": getattr(result, "module", "unknown"),
        "target_url": getattr(result, "target_url", "unknown"),
        "success": getattr(result, "success", False),
        "confidence": getattr(result, "confidence", 0.0),
        "notes": getattr(result, "notes", ""),
        "timestamp": getattr(result, "timestamp", ""),
        "evidence": getattr(result, "evidence", {}),
    }


def _print_attack_summary(target, modules: list[str], results: dict):
    total = len(results)
    succeeded = sum(1 for result in results.values() if getattr(result, "success", False))
    avg_confidence = (
        sum(float(getattr(result, "confidence", 0.0) or 0.0) for result in results.values()) / total
        if total else 0.0
    )
    avg_color = "green" if avg_confidence > 0.5 else "yellow" if avg_confidence > 0.2 else "red"

    console.print(Panel(
        f"[bold]Target:[/bold]    [cyan]{getattr(target, 'url', 'unknown')}[/cyan]\n"
        f"[bold]Modules:[/bold]   [red]{', '.join(modules)}[/red]\n"
        f"[bold]Model:[/bold]     [dim]{getattr(target, 'model', None) or 'auto'}[/dim]\n"
        f"[bold]Timeout:[/bold]   [dim]{getattr(target, 'timeout', 'unknown')}s[/dim]\n"
        f"[bold]Succeeded:[/bold] {succeeded}/{total}\n"
        f"[bold]Avg ASR:[/bold]   [{avg_color}]{avg_confidence:.0%}[/{avg_color}]",
        title="[bold red]Attack Summary[/bold red]",
        border_style="red",
    ))


def _summarize_attack_findings(results: dict) -> list[str]:
    findings = []
    for module_name, result in results.items():
        evidence = getattr(result, "evidence", {}) or {}
        meta = evidence.get("_meta", {}) if isinstance(evidence, dict) else {}
        assessment = (
            meta.get("memory_assessment")
            or meta.get("extract_assessment")
            or meta.get("best_classification")
            or ("success" if getattr(result, "success", False) else "negative")
        )
        findings.append(f"{module_name}: {assessment}")
    return findings[:3]


def _print_scan_operator_cue(plan: dict, surface_details: dict, auth_context: dict):
    best_candidate = surface_details.get("best_candidate")
    best_intent = surface_details.get("best_candidate_intent", "unknown_surface")
    auth_wall_context = _build_auth_wall_context(surface_details.get("handoff", {}), surface_details)
    modules = ", ".join((plan.get("attack_plan", []) or [])[:4]) or "none"
    lines = []
    if best_candidate:
        lines.append(f"Best endpoint: {best_candidate} ({best_intent})")
    lines.append(f"Prioritized modules: {modules}")
    lines.append(
        "Auth wall: "
        f"{auth_wall_context.get('auth_wall_type', 'no_auth_wall')} / "
        f"opportunity={auth_wall_context.get('auth_opportunity_level', 'low')}"
    )
    if auth_context.get("status") == "transport_or_discovery_error":
        lines.append("Next step: treat this as discovery failure, not as a clean negative surface.")
    elif auth_wall_context.get("manual_login_recommended"):
        lines.append("Next step: manual login is worth the effort because the post-login surface looks actionable.")
    elif auth_context.get("auth_friction_present") and not auth_context.get("auth_material_provided"):
        lines.append("Next step: rerun attack/report with relevant --header/--cookie material if a valid session exists.")
    elif auth_context.get("auth_material_provided"):
        lines.append("Next step: use --from-scan so attack can reuse the discovered handoff with your manual auth context.")
    else:
        lines.append("Next step: use fracture attack --from-scan to keep the discovered handoff and execution hints.")
    _print_operator_cue("Operator Cue", lines)


def _print_attack_operator_cue(results: dict, auth_context: dict):
    findings = "; ".join(_summarize_attack_findings(results)) or "none"
    lines = [f"Key signals: {findings}"]
    if auth_context.get("auth_friction_present") and not auth_context.get("auth_material_provided"):
        lines.append("Coverage may be limited by session/auth friction; prudent negatives may still be partial coverage.")
    elif auth_context.get("auth_material_provided"):
        lines.append("Manual auth context was applied; keep session validity in mind when interpreting weak results.")
    lines.append("Next step: use fracture report when you need a consolidated rationale and exportable artifact.")
    _print_operator_cue("Operator Cue", lines)


def _print_report_operator_cue(report_obj, output: Optional[str], report_format: str):
    if report_obj is None:
        return
    findings = getattr(report_obj, "findings_summary", {}) or {}
    executive = "; ".join((findings.get("executive_summary", []) or [])[:2]) or "none"
    top_signals = ", ".join((findings.get("top_signals", []) or [])[:4]) or "none"
    limitations = "; ".join((findings.get("operational_limitations", []) or [])[:2]) or "none"
    lines = [
        f"Executive summary: {executive}",
        f"Top signals: {top_signals}",
        f"Operational limitations: {limitations}",
    ]
    if output:
        lines.append(f"Exported {report_format} artifact: {output}")
    _print_operator_cue("Report Cue", lines)


def _print_autopilot_operator_cue(results: dict, output: Optional[str]):
    if not isinstance(results, dict):
        return
    plan = results.get("plan", {}) or {}
    report_obj = results.get("report")
    findings = getattr(report_obj, "findings_summary", {}) if report_obj is not None else {}
    lines = [
        f"Plan executed: {', '.join(plan.get('attack_plan', [])[:5]) or 'none'}",
        f"Constraints: {'; '.join(plan.get('surface_constraints', [])[:2]) or 'none'}",
        f"Findings: confirmed={findings.get('confirmed', 0)} probable={findings.get('probable', 0)} possible={findings.get('possible', 0)} negative={findings.get('negative', 0)}",
    ]
    if output:
        lines.append(f"Output path: {output}")
    _print_operator_cue("Autopilot Cue", lines)


async def _run_auto(target, output: Optional[str] = None, planner: str = "local"):
    from fracture.core.orchestrator import Orchestrator

    orch = Orchestrator(target, console=console, planner=planner)
    results = await orch.run(output_path=output)
    return results


async def _run_scan(target, planner: str = "local", discovery_mode: str = "passive"):
    from fracture.core.orchestrator import Orchestrator

    orch = Orchestrator(target, console=console, planner=planner)
    return await orch.scan(discovery_mode=discovery_mode)


async def _run_attack(
    target,
    modules: list[str],
    objective: Optional[str] = None,
    execution_hints: Optional[dict] = None,
):
    from fracture.core.orchestrator import Orchestrator

    orch = Orchestrator(target, console=console)
    return await orch.attack(modules, objective=objective, execution_hints=execution_hints)


@app.command()
def start(
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
    module: str = typer.Option(
        "fingerprint",
        "--module",
        "-m",
        help="Legacy single-module mode: fingerprint, hpm, memory, privesc, extract, auto",
    ),
    objective: Optional[str] = typer.Option(
        None,
        "--objective",
        help="Optional HPM attack objective",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save result to JSON",
    ),
    planner: str = typer.Option(
        "local",
        "--planner",
        help="Planner mode for autonomous flow: local or claude",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="Optional model hint for target adapters and module heuristics",
    ),
    header: Optional[list[str]] = typer.Option(
        None,
        "--header",
        help="HTTP header in KEY=VALUE format; repeatable",
    ),
    cookie: Optional[list[str]] = typer.Option(
        None,
        "--cookie",
        help="HTTP cookie in KEY=VALUE format; repeatable",
    ),
    timeout: int = typer.Option(
        30,
        "--timeout",
        help="HTTP timeout in seconds for target requests",
    ),
    body_key: Optional[str] = typer.Option(
        None,
        "--body-key",
        help="Override primary JSON body field name (e.g. 'message', 'input')",
    ),
    body_field: Optional[list[str]] = typer.Option(
        None,
        "--body-field",
        help="Static JSON body field in KEY=VALUE format; repeatable (e.g. session_id=default)",
    ),
):
    """Legacy compatibility command for single-module or auto engagements."""
    console.print(BANNER)
    console.print(Panel(
        f"[bold]Target:[/bold]    [cyan]{target}[/cyan]\n"
        f"[bold]Module:[/bold]    [red]{module}[/red]\n"
        f"[bold]Planner:[/bold]   [yellow]{planner}[/yellow]\n"
        f"[bold]Objective:[/bold] [dim]{objective or 'default'}[/dim]\n"
        f"[bold]Model:[/bold]     [dim]{model or 'auto'}[/dim]\n"
        f"[bold]Timeout:[/bold]   [dim]{timeout}s[/dim]",
        title="[bold red]Engagement Config[/bold red]",
        border_style="red",
    ))

    ai_target = _build_target(
        target_url=target,
        model=model,
        headers=header,
        cookies=cookie,
        timeout=timeout,
        body_key=body_key,
        body_fields=body_field,
    )

    if module == "auto":
        results = asyncio.run(_run_auto(ai_target, output=output, planner=planner))
        _print_autopilot_operator_cue(results, output)
        return

    result = None

    if module == "fingerprint":
        from fracture.modules.fingerprint.engine import FingerprintEngine
        result = asyncio.run(FingerprintEngine(ai_target).run())

    elif module == "privesc":
        from fracture.modules.privesc.engine import PrivescEngine
        result = asyncio.run(PrivescEngine(ai_target).run())

    elif module == "memory":
        from fracture.modules.memory.engine import MemoryEngine
        result = asyncio.run(MemoryEngine(ai_target).run())

    elif module == "extract":
        from fracture.modules.extract.engine import ExtractEngine
        result = asyncio.run(ExtractEngine(ai_target).run())

    elif module == "hpm":
        from fracture.modules.hpm.engine import HPMEngine
        result = asyncio.run(HPMEngine(ai_target, objective=objective).run())

    else:
        console.print(f"[red]Module '{module}' not available.[/red]")
        console.print("[dim]Available: fingerprint, hpm, memory, privesc, extract, auto[/dim]")
        raise typer.Exit(code=1)

    _print_generic_result(result)

    if output and result is not None:
        _save_result_json(result, output)


@app.command()
def autopilot(
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save autonomous results to JSON",
    ),
    planner: str = typer.Option(
        "local",
        "--planner",
        help="Planner mode: local or claude",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="Optional model hint for target adapters and module heuristics",
    ),
    header: Optional[list[str]] = typer.Option(
        None,
        "--header",
        help="HTTP header in KEY=VALUE format; repeatable",
    ),
    cookie: Optional[list[str]] = typer.Option(
        None,
        "--cookie",
        help="HTTP cookie in KEY=VALUE format; repeatable",
    ),
    timeout: int = typer.Option(
        30,
        "--timeout",
        help="HTTP timeout in seconds for target requests",
    ),
):
    """Run the full autonomous multi-agent workflow."""
    console.print(BANNER)

    ai_target = _build_target(
        target_url=target,
        model=model,
        headers=header,
        cookies=cookie,
        timeout=timeout,
    )

    results = asyncio.run(_run_auto(ai_target, output=output, planner=planner))
    _print_autopilot_operator_cue(results, output)


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save triage output to JSON",
    ),
    planner: str = typer.Option(
        "local",
        "--planner",
        help="Planner mode: local or claude",
    ),
    mode: str = typer.Option(
        "passive",
        "--mode",
        help="Recon mode: passive or phantomtwin",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="Optional model hint for target adapters and module heuristics",
    ),
    header: Optional[list[str]] = typer.Option(
        None,
        "--header",
        help="HTTP header in KEY=VALUE format; repeatable",
    ),
    cookie: Optional[list[str]] = typer.Option(
        None,
        "--cookie",
        help="HTTP cookie in KEY=VALUE format; repeatable",
    ),
    timeout: int = typer.Option(
        30,
        "--timeout",
        help="HTTP timeout in seconds for target requests",
    ),
):
    """Fingerprint the target and return triage-ready attack surfaces."""
    console.print(BANNER)

    ai_target = _build_target(
        target_url=target,
        model=model,
        headers=header,
        cookies=cookie,
        timeout=timeout,
    )

    _print_phantomtwin_runtime_guard(mode)

    results = asyncio.run(_run_scan(ai_target, planner=planner, discovery_mode=mode))
    fingerprint = results.get("fingerprint")
    plan = results.get("plan", {})

    _print_scan_result(ai_target, fingerprint, plan, discovery_mode=mode)
    surface_details = (
        getattr(fingerprint, "evidence", {}) or {}
    ).get("surface_discovery", {}).get("details", {})
    handoff = surface_details.get("handoff") if isinstance(surface_details, dict) else None
    auth_context = _build_auth_context(
        handoff=handoff,
        surface_details=surface_details,
        target_headers=ai_target.headers,
        target_cookies=ai_target.cookies,
    )
    scan_session_context = _build_session_context(None, handoff if isinstance(handoff, dict) else {})
    auth_wall_context = _build_auth_wall_context(handoff if isinstance(handoff, dict) else {}, surface_details)
    _print_scan_operator_cue(plan, surface_details, auth_context)

    if output:
        payload = {
            "target_url": ai_target.url,
            "model_hint": ai_target.model,
            "header_names": _sanitize_scan_header_names(ai_target.headers),
            "cookie_names": _sanitize_scan_cookie_names(ai_target.cookies),
            "timeout": ai_target.timeout,
            "fingerprint": {
                "module": getattr(fingerprint, "module", "fingerprint"),
                "success": getattr(fingerprint, "success", False),
                "confidence": getattr(fingerprint, "confidence", 0.0),
                "notes": getattr(fingerprint, "notes", ""),
                "timestamp": getattr(fingerprint, "timestamp", ""),
                "evidence": getattr(fingerprint, "evidence", {}),
            },
            "triage": {
                "recon_mode": mode,
                "detected_model": plan.get("detected_model", "unknown"),
                "risk_level": plan.get("risk_level", "unknown"),
                "analysis": plan.get("analysis", ""),
                "rationale": plan.get("rationale", ""),
                "planning_rationale": plan.get("planning_rationale", []),
                "module_priority_reasons": plan.get("module_priority_reasons", {}),
                "surface_constraints": plan.get("surface_constraints", []),
                "planning_signals_used": plan.get("planning_signals_used", []),
                "auth_friction_present": auth_context.get("auth_friction_present", False),
                "auth_friction_rationale": auth_context.get("auth_friction_rationale", ""),
                "auth_material_provided": auth_context.get("auth_material_provided", False),
                "auth_material_types": auth_context.get("auth_material_types", []),
                "operational_limitations": auth_context.get("operational_limitations", []),
                "coverage_constraints": auth_context.get("coverage_constraints", []),
                "observed_auth_signal_names": auth_context.get("observed_auth_signal_names", []),
                "auth_wall_detected": auth_wall_context.get("auth_wall_detected", False),
                "auth_wall_type": auth_wall_context.get("auth_wall_type", "no_auth_wall"),
                "auth_wall_confidence": auth_wall_context.get("auth_wall_confidence", 0.0),
                "auth_success_markers": auth_wall_context.get("auth_success_markers", []),
                "already_authenticated_signals": auth_wall_context.get("already_authenticated_signals", []),
                "manual_login_recommended": auth_wall_context.get("manual_login_recommended", False),
                "session_capture_readiness": auth_wall_context.get("session_capture_readiness", "low"),
                "post_login_surface_score": auth_wall_context.get("post_login_surface_score", 0),
                "auth_opportunity_score": auth_wall_context.get("auth_opportunity_score", 0),
                "auth_opportunity_level": auth_wall_context.get("auth_opportunity_level", "low"),
                "post_login_surface_label": auth_wall_context.get("post_login_surface_label", "unknown_surface"),
                "auth_wall_rationale": auth_wall_context.get("auth_wall_rationale", ""),
                "session_material_present": scan_session_context.get("session_material_present", False),
                "session_cookie_count": scan_session_context.get("session_cookie_count", 0),
                "session_cookie_names": scan_session_context.get("session_cookie_names", []),
                "session_cookie_domains": scan_session_context.get("session_cookie_domains", []),
                "session_cookie_source": scan_session_context.get("session_cookie_source", "none"),
                "session_cookie_merge_strategy": scan_session_context.get("session_cookie_merge_strategy", "unknown"),
                "session_cookie_header_redacted": scan_session_context.get("session_cookie_header_redacted", False),
                "session_scope_applied": scan_session_context.get("session_scope_applied", False),
                "session_propagation_note": scan_session_context.get("session_propagation_note", ""),
                "suggested_modules": plan.get("attack_plan", []),
                "top_candidates": surface_details.get("top_candidates", []) if isinstance(surface_details, dict) else [],
            },
            "handoff": handoff,
        }

        with open(output, "w") as f:
            json.dump(payload, f, indent=2)

        _print_output_saved("Scan triage", output)


@app.command()
def attack(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target URL"),
    from_scan: Optional[str] = typer.Option(
        None,
        "--from-scan",
        help="Use structured handoff from a prior scan JSON export",
    ),
    module: list[str] = typer.Option(
        ...,
        "--module",
        "-m",
        help="Attack module to execute; repeatable",
    ),
    objective: Optional[str] = typer.Option(
        None,
        "--objective",
        help="Optional HPM attack objective",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save attack results to JSON",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="Optional model hint for target adapters and module heuristics",
    ),
    header: Optional[list[str]] = typer.Option(
        None,
        "--header",
        help="HTTP header in KEY=VALUE format; repeatable",
    ),
    cookie: Optional[list[str]] = typer.Option(
        None,
        "--cookie",
        help="HTTP cookie in KEY=VALUE format; repeatable",
    ),
    timeout: int = typer.Option(
        30,
        "--timeout",
        help="HTTP timeout in seconds for target requests",
    ),
    body_key: Optional[str] = typer.Option(
        None,
        "--body-key",
        help="Override primary JSON body field name (e.g. 'message', 'input')",
    ),
    body_field: Optional[list[str]] = typer.Option(
        None,
        "--body-field",
        help="Static JSON body field in KEY=VALUE format; repeatable (e.g. session_id=default)",
    ),
):
    """Execute one or more attack modules explicitly against a target."""
    from fracture.agents.execution import MODULE_MAP

    console.print(BANNER)
    handoff = _resolve_attack_handoff(from_scan) if from_scan else None
    resolved_target = target or (handoff.get("recommended_target_url") if isinstance(handoff, dict) else None)
    if not resolved_target:
        console.print("[red]Attack requires --target or --from-scan with a usable handoff.[/red]")
        raise typer.Exit(code=1)

    requested_modules: list[str] = []
    for item in module:
        normalized = str(item).strip().lower()
        if not normalized:
            continue
        if normalized not in MODULE_MAP:
            console.print(f"[red]Module '{normalized}' not available.[/red]")
            console.print(f"[dim]Available: {', '.join(MODULE_MAP)}[/dim]")
            raise typer.Exit(code=1)
        if normalized not in requested_modules:
            requested_modules.append(normalized)

    ai_target = _build_target(
        target_url=resolved_target,
        model=model,
        headers=header,
        cookies=cookie,
        session_cookies=_extract_handoff_session_cookies(handoff),
        timeout=timeout,
        body_key=body_key,
        body_fields=body_field,
    )
    session_context = _build_session_context(ai_target, handoff)
    if session_context.get("session_material_present"):
        console.print(
            "[yellow]"
            f"Applied session context: source={session_context.get('session_cookie_source', 'none')} "
            f"strategy={session_context.get('session_cookie_merge_strategy', 'unknown')} "
            f"cookies={session_context.get('session_cookie_count', 0)} "
            f"names={', '.join(session_context.get('session_cookie_names', [])[:4]) or 'none'}."
            "[/yellow]"
        )

    _print_attack_handoff_summary(
        handoff=handoff or {},
        explicit_target=target,
        target_headers=ai_target.headers,
        target_cookies=ai_target.cookies,
        session_context=session_context,
    )
    execution_hints = None if target else _build_execution_hints(handoff)
    _print_execution_hints_summary(execution_hints)
    attack_auth_context = _build_auth_context(
        handoff=handoff or {},
        target_headers=ai_target.headers,
        target_cookies=ai_target.cookies,
    )

    results = asyncio.run(
        _run_attack(
            ai_target,
            requested_modules,
            objective=objective,
            execution_hints=execution_hints,
        )
    )
    attack_results = results.get("attacks", {})
    from fracture.agents.report import ReportAgent

    attack_graph = ReportAgent(ai_target, console=console).build_attack_graph(
        plan={},
        attack_results=attack_results,
        handoff=handoff or {},
        session_context=session_context,
        execution_hints=execution_hints,
    )
    adversarial_twin = ReportAgent(ai_target, console=console).build_adversarial_twin(
        plan={},
        attack_results=attack_results,
        attack_graph=attack_graph,
        handoff=handoff or {},
        session_context=session_context,
        execution_hints=execution_hints,
    )

    _print_attack_summary(ai_target, requested_modules, attack_results)

    for result in attack_results.values():
        _print_generic_result(result)
    _print_attack_graph_summary(attack_graph)
    _print_adversarial_twin_summary(adversarial_twin)
    _print_attack_operator_cue(attack_results, attack_auth_context)

    if output:
        payload = {
            "target_url": ai_target.url,
            "model_hint": ai_target.model,
            "headers": _sanitize_header_mapping_for_output(ai_target.headers),
            "cookies": _sanitize_cookie_mapping_for_output(ai_target.cookies),
            "cookie_names": sorted((ai_target.cookies or {}).keys()),
            "timeout": ai_target.timeout,
            "handoff_used": _sanitize_handoff_for_output(handoff or None),
            "session_context": session_context,
            "execution_hints": execution_hints,
            "auth_friction_present": attack_auth_context.get("auth_friction_present", False),
            "auth_friction_rationale": attack_auth_context.get("auth_friction_rationale", ""),
            "auth_material_provided": attack_auth_context.get("auth_material_provided", False),
            "auth_material_types": attack_auth_context.get("auth_material_types", []),
            "operational_limitations": attack_auth_context.get("operational_limitations", []),
            "coverage_constraints": attack_auth_context.get("coverage_constraints", []),
            "observed_auth_signal_names": attack_auth_context.get("observed_auth_signal_names", []),
            "modules": requested_modules,
            "results": {
                name: _serialize_attack_result(result)
                for name, result in attack_results.items()
            },
            "attack_graph": attack_graph,
            "adversarial_twin": adversarial_twin,
        }

        with open(output, "w") as f:
            json.dump(payload, f, indent=2)

        _print_output_saved("Attack results", output)


@app.command()
def report(
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save consolidated report",
    ),
    format: str = typer.Option(
        "json",
        "--format",
        help="Report export format: json, docx, or pdf",
    ),
    planner: str = typer.Option(
        "local",
        "--planner",
        help="Planner mode: local or claude",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="Optional model hint for target adapters and module heuristics",
    ),
    header: Optional[list[str]] = typer.Option(
        None,
        "--header",
        help="HTTP header in KEY=VALUE format; repeatable",
    ),
    cookie: Optional[list[str]] = typer.Option(
        None,
        "--cookie",
        help="HTTP cookie in KEY=VALUE format; repeatable",
    ),
    timeout: int = typer.Option(
        30,
        "--timeout",
        help="HTTP timeout in seconds for target requests",
    ),
):
    """Run autopilot and emit the consolidated final report."""
    console.print(BANNER)

    ai_target = _build_target(
        target_url=target,
        model=model,
        headers=header,
        cookies=cookie,
        timeout=timeout,
    )

    report_format = str(format or "json").strip().lower()
    if report_format not in {"json", "docx", "pdf"}:
        console.print(f"[red]Unsupported report format '{report_format}'.[/red]")
        console.print("[dim]Available formats: json, docx, pdf[/dim]")
        raise typer.Exit(code=1)

    if output:
        suffix = Path(output).suffix.lower()
        if suffix == ".docx":
            report_format = "docx"
        elif suffix == ".pdf":
            report_format = "pdf"
        elif suffix == ".json":
            report_format = "json"

    results = asyncio.run(_run_auto(ai_target, output=None, planner=planner))
    report_obj = results.get("report") if isinstance(results, dict) else None

    if output and report_obj is not None:
        _save_report_output(report_obj, output, report_format)
    _print_report_operator_cue(report_obj, output, report_format)


@app.command()
def ui(
    demo: bool = typer.Option(
        False,
        "--demo",
        help="Load the repo's golden demo workspace",
    ),
    workspace: Optional[str] = typer.Option(
        None,
        "--workspace",
        help="Workspace directory containing scan.json, attack.json or report.json artifacts",
    ),
    scan: Optional[str] = typer.Option(
        None,
        "--scan",
        help="Path to a scan JSON artifact",
    ),
    attack: Optional[str] = typer.Option(
        None,
        "--attack",
        help="Path to an attack JSON artifact",
    ),
    report: Optional[str] = typer.Option(
        None,
        "--report",
        help="Path to a report JSON artifact",
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Host interface for the local read-only UI server",
    ),
    port: int = typer.Option(
        8009,
        "--port",
        help="Port for the local read-only UI server; use 0 for an ephemeral port",
    ),
    max_requests: int = typer.Option(
        0,
        "--max-requests",
        help="Serve at most N HTTP requests before exiting; 0 keeps the server running",
    ),
    presentation: bool = typer.Option(
        False,
        "--presentation",
        help="Print the Control Center URL in presentation mode",
    ),
):
    """Launch a read-only local Control Center UI over FRACTURE artifacts."""
    from fracture.ui.control_center import get_demo_workspace_path, load_control_center_bundle, serve_control_center

    console.print(BANNER)
    if demo and any([workspace, scan, attack, report]):
        console.print("[red]Use either --demo or explicit workspace/artifact inputs, not both.[/red]")
        raise typer.Exit(code=1)

    workspace_path = str(get_demo_workspace_path()) if demo else workspace
    try:
        bundle = load_control_center_bundle(
            workspace=workspace_path,
            scan_path=scan,
            attack_path=attack,
            report_path=report,
        )
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    loaded = [
        artifact["label"]
        for artifact in bundle.get("artifacts", {}).values()
        if artifact.get("available")
    ]
    console.print(Panel(
        f"[bold]Workspace:[/bold] [dim]{bundle.get('workspace') or 'not provided'}[/dim]\n"
        f"[bold]Artifacts:[/bold] [dim]{', '.join(loaded) or 'none'}[/dim]\n"
        f"[bold]Target:[/bold] [cyan]{bundle.get('overview', {}).get('target', 'unknown')}[/cyan]\n"
        f"[bold]Best Candidate:[/bold] [dim]{bundle.get('overview', {}).get('best_candidate', 'unknown')}[/dim]\n"
        f"[bold]Demo Mode:[/bold] [dim]{'golden workspace' if bundle.get('demo_workspace') else 'custom workspace'}[/dim]\n"
        f"[bold]Read-only:[/bold] [dim]sanitized operator view; cookies, sensitive headers and secrets stay redacted[/dim]",
        title="[bold red]FRACTURE Control Center[/bold red]",
        border_style="red",
    ))

    serve_control_center(
        bundle,
        host=host,
        port=port,
        max_requests=max_requests,
        ready_callback=lambda url: console.print(
            f"[green]Control Center URL:[/green] [bold]{url}{'?presentation=1&view=executive' if presentation else '?view=executive'}[/bold]\n"
            "[dim]Artifacts are served read-only and sanitized. Press Ctrl+C to stop.[/dim]"
        ),
    )


if __name__ == "__main__":
    app()
