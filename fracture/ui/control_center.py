import json
from datetime import UTC, datetime
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Optional

DEMO_WORKSPACE_PATH = Path(__file__).resolve().parents[2] / "demo" / "golden-workspace"

SENSITIVE_KEY_TOKENS = (
    "authorization",
    "cookie",
    "token",
    "secret",
    "api_key",
    "apikey",
    "password",
    "session_cookie_header",
)

SAFE_SENSITIVE_KEYS = {
    "session_cookie_count",
    "session_cookie_names",
    "session_cookie_domains",
    "session_cookie_source",
    "session_cookie_merge_strategy",
    "session_cookie_header_redacted",
    "session_scope_applied",
}


def load_control_center_bundle(
    *,
    workspace: Optional[str] = None,
    scan_path: Optional[str] = None,
    attack_path: Optional[str] = None,
    report_path: Optional[str] = None,
) -> dict:
    artifact_paths = _resolve_artifact_paths(
        workspace=workspace,
        scan_path=scan_path,
        attack_path=attack_path,
        report_path=report_path,
    )
    artifacts = {name: _load_optional_json(path) for name, path in artifact_paths.items()}
    sanitized_artifacts = {
        name: _sanitize_value(payload)
        for name, payload in artifacts.items()
    }

    scan_payload = sanitized_artifacts.get("scan") or {}
    attack_payload = sanitized_artifacts.get("attack") or {}
    report_payload = sanitized_artifacts.get("report") or {}
    scan_surface = _extract_scan_surface_details(scan_payload)
    scan_handoff = _extract_scan_handoff(scan_payload)
    attack_graph = _first_dict(
        report_payload.get("attack_graph"),
        attack_payload.get("attack_graph"),
    )
    adversarial_twin = _first_dict(
        report_payload.get("adversarial_twin"),
        attack_payload.get("adversarial_twin"),
    )
    findings_summary = _first_dict(report_payload.get("findings_summary"))
    report_results = report_payload.get("results") if isinstance(report_payload.get("results"), dict) else {}
    boardroom = _first_dict(report_payload.get("boardroom"))
    toolforge = _first_dict(report_payload.get("toolforge"), attack_payload.get("toolforge"))
    governor = _first_dict(report_payload.get("governor"), attack_payload.get("governor"))
    reality = _first_dict(report_payload.get("reality"), attack_payload.get("reality"))
    shadow = _first_dict(report_payload.get("shadow"), attack_payload.get("shadow"))

    overview = {
        "target": _first_str(
            report_payload.get("target_url"),
            attack_payload.get("target_url"),
            scan_payload.get("target_url"),
        ) or "unknown",
        "best_candidate": _first_str(
            _nested(adversarial_twin, "identity", "best_candidate"),
            scan_handoff.get("recommended_target_url"),
            scan_surface.get("best_candidate"),
        ) or "unknown",
        "best_candidate_intent": _first_str(
            _nested(adversarial_twin, "identity", "best_candidate_intent"),
            scan_handoff.get("intent"),
            scan_surface.get("best_candidate_intent"),
        ) or "unknown_surface",
        "auth_wall_type": _first_str(
            _nested(adversarial_twin, "auth_profile", "auth_wall_type"),
            scan_handoff.get("auth_wall_type"),
            scan_surface.get("auth_wall_type"),
            _nested(scan_payload, "triage", "auth_wall_type"),
        ) or "no_auth_wall",
        "auth_wall_confidence": _first_float(
            _nested(adversarial_twin, "auth_profile", "auth_wall_confidence"),
            scan_handoff.get("auth_wall_confidence"),
            scan_surface.get("auth_wall_confidence"),
            _nested(scan_payload, "triage", "auth_wall_confidence"),
        ),
        "auth_opportunity_score": _first_int(
            _nested(adversarial_twin, "auth_profile", "auth_opportunity_score"),
            scan_handoff.get("auth_opportunity_score"),
            scan_surface.get("auth_opportunity_score"),
            _nested(scan_payload, "triage", "auth_opportunity_score"),
        ),
        "session_context": _first_dict(
            _nested(adversarial_twin, "session_profile"),
            attack_payload.get("session_context"),
            _build_scan_session_context(scan_payload, scan_handoff),
        ),
        "attackability": _first_str(_nested(adversarial_twin, "summary", "attackability")) or "unknown",
        "overall_posture": _first_str(_nested(adversarial_twin, "summary", "overall_posture")) or "unknown",
        "recommended_next_step": (
            _first_str(_nested(adversarial_twin, "summary", "recommended_next_step"))
            or "collect_more_artifacts"
        ),
    }

    findings = {
        "findings_summary": findings_summary,
        "executive_summary": _listify(findings_summary.get("executive_summary")),
        "highlights": _listify(findings_summary.get("highlights")),
        "module_assessment": [
            {
                "module": module_name,
                "assessment": str(entry.get("assessment", "unknown") or "unknown"),
                "module_assessment": str(entry.get("module_assessment", "unknown") or "unknown"),
            }
            for module_name, entry in report_results.items()
            if isinstance(entry, dict)
        ],
        "report_rationale": [
            str(entry.get("report_rationale", "") or "").strip()
            for entry in report_results.values()
            if isinstance(entry, dict) and str(entry.get("report_rationale", "") or "").strip()
        ],
        "key_signals": _dedupe(
            list(findings_summary.get("top_signals", []) or [])
            + [
                signal
                for entry in report_results.values()
                if isinstance(entry, dict)
                for signal in list(entry.get("key_signals", []) or [])
            ]
        ),
        "operational_limitations": _dedupe(
            list(findings_summary.get("operational_limitations", []) or [])
            + list(attack_payload.get("operational_limitations", []) or [])
            + list(_nested(scan_payload, "triage", "operational_limitations") or [])
        ),
    }
    executive = _build_executive_summary(
        overview=overview,
        attack_graph=attack_graph,
        adversarial_twin=adversarial_twin,
        findings=findings,
        boardroom=boardroom,
        toolforge=toolforge,
        governor=governor,
        reality=reality,
        shadow=shadow,
    )
    resolved_workspace = str(Path(workspace).resolve()) if workspace else None

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "workspace": resolved_workspace,
        "demo_workspace": bool(resolved_workspace and Path(resolved_workspace) == DEMO_WORKSPACE_PATH.resolve()),
        "artifacts": {
            name: {
                "available": artifact_paths.get(name) is not None,
                "path": str(artifact_paths[name].resolve()) if artifact_paths.get(name) else None,
                "label": f"{name}.json",
            }
            for name in ("scan", "attack", "report")
        },
        "overview": overview,
        "attack_graph": attack_graph or {"nodes": [], "edges": [], "summary": {}},
        "adversarial_twin": adversarial_twin or {},
        "boardroom": boardroom or {},
        "toolforge": toolforge or {},
        "governor": governor or {},
        "reality": reality or {},
        "shadow": shadow or {},
        "findings": findings,
        "executive": executive,
        "artifacts_payload": sanitized_artifacts,
    }


def get_demo_workspace_path() -> Path:
    return DEMO_WORKSPACE_PATH


def serve_control_center(
    bundle: dict,
    *,
    host: str = "127.0.0.1",
    port: int = 8009,
    max_requests: int = 0,
    ready_callback: Optional[Callable[[str], None]] = None,
) -> None:
    html = _render_html(bundle).encode("utf-8")
    artifact_payloads = {
        name: json.dumps(payload, indent=2).encode("utf-8")
        for name, payload in (bundle.get("artifacts_payload", {}) or {}).items()
        if payload is not None
    }
    handler = partial(
        _ControlCenterHandler,
        html=html,
        artifact_payloads=artifact_payloads,
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    server.timeout = 0.5
    try:
        actual_host, actual_port = server.server_address[:2]
        url = f"http://{actual_host}:{actual_port}/"
        if ready_callback:
            ready_callback(url)
        if max_requests and max_requests > 0:
            served = 0
            while served < max_requests:
                server.handle_request()
                served += 1
        else:
            server.serve_forever()
    finally:
        server.server_close()


class _ControlCenterHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, html: bytes, artifact_payloads: dict[str, bytes], **kwargs):
        self._html = html
        self._artifact_payloads = artifact_payloads
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path in {"/", "/index.html"}:
            self._send(200, self._html, "text/html; charset=utf-8")
            return

        if self.path.startswith("/artifacts/"):
            name = self.path.rsplit("/", 1)[-1].replace(".json", "")
            payload = self._artifact_payloads.get(name)
            if payload is None:
                self._send(404, b'{"error":"artifact_not_available"}', "application/json; charset=utf-8")
                return
            self._send(200, payload, "application/json; charset=utf-8")
            return

        self._send(404, b"not found", "text/plain; charset=utf-8")

    def log_message(self, fmt, *args):
        return

    def _send(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _render_html(bundle: dict) -> str:
    page_bundle = dict(bundle)
    page_bundle.pop("artifacts_payload", None)
    data_json = json.dumps(page_bundle, separators=(",", ":")).replace("</script>", "<\\/script>")
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>FRACTURE Control Center</title>
    <style>
      :root {{
        --bg: #0a0f16;
        --card: rgba(16, 24, 36, 0.88);
        --card-strong: rgba(11, 18, 29, 0.96);
        --line: rgba(125, 160, 200, 0.18);
        --line-strong: rgba(125, 160, 200, 0.32);
        --text: #edf4ff;
        --muted: #8ba0bb;
        --accent: #8ef7c8;
        --accent-2: #7ed8ff;
        --accent-3: #ffcf7d;
        --shadow: 0 20px 80px rgba(0, 0, 0, 0.45);
        --radius: 22px;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        font-family: "Segoe UI", "SF Pro Display", "Helvetica Neue", sans-serif;
        color: var(--text);
        background:
          radial-gradient(circle at top left, rgba(126, 216, 255, 0.13), transparent 32%),
          radial-gradient(circle at top right, rgba(142, 247, 200, 0.11), transparent 28%),
          linear-gradient(180deg, #08111c, #060a11 58%, #04070c);
      }}
      body::before {{
        content: "";
        position: fixed;
        inset: 0;
        background-image:
          linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px),
          linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px);
        background-size: 36px 36px;
        mask-image: linear-gradient(180deg, rgba(0,0,0,0.7), transparent);
        pointer-events: none;
      }}
      body.presentation .shell {{ max-width: 1600px; }}
      body.presentation .hero {{ padding: 36px; }}
      .shell {{ max-width: 1480px; margin: 0 auto; padding: 28px 22px 48px; position: relative; }}
      .hero {{
        padding: 28px;
        border: 1px solid var(--line);
        border-radius: calc(var(--radius) + 6px);
        background: linear-gradient(135deg, rgba(14, 22, 34, 0.96), rgba(10, 15, 22, 0.82));
        box-shadow: var(--shadow);
      }}
      .hero-top {{ display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; flex-wrap: wrap; }}
      .eyebrow {{
        display: inline-flex; gap: 10px; align-items: center; padding: 7px 12px; border: 1px solid var(--line);
        border-radius: 999px; color: var(--accent); font-size: 12px; letter-spacing: 0.16em; text-transform: uppercase;
      }}
      h1 {{ margin: 16px 0 8px; font-size: clamp(34px, 7vw, 64px); line-height: 0.95; letter-spacing: -0.04em; }}
      .lede {{ color: var(--muted); max-width: 820px; font-size: 16px; line-height: 1.7; }}
      .toolbar {{ display: flex; gap: 10px; flex-wrap: wrap; }}
      .tool {{
        padding: 12px 14px; border-radius: 999px; border: 1px solid var(--line); background: rgba(7, 12, 19, 0.78);
        color: var(--text); font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase;
      }}
      .tool a, .tool button {{ color: inherit; background: none; border: 0; padding: 0; cursor: pointer; font: inherit; text-transform: inherit; letter-spacing: inherit; }}
      .hero-grid, .card-grid, .mini-grid, .artifact-grid, .summary-grid {{ display: grid; gap: 16px; }}
      .hero-grid {{ grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); margin-top: 22px; }}
      .card-grid {{ grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }}
      .mini-grid {{ grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); }}
      .artifact-grid {{ grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }}
      .summary-grid {{ grid-template-columns: 1.2fr 0.8fr; align-items: stretch; }}
      .metric, .card, .artifact-card, .node-card, .edge-card, .hero-spotlight {{
        border: 1px solid var(--line); border-radius: var(--radius); background: var(--card); box-shadow: var(--shadow);
      }}
      .metric {{ padding: 18px; min-height: 128px; }}
      .metric .label, .label {{ color: var(--muted); text-transform: uppercase; letter-spacing: 0.12em; font-size: 11px; }}
      .metric .value {{ margin-top: 10px; font-size: 18px; line-height: 1.35; word-break: break-word; }}
      .value-strong {{ font-size: 28px; letter-spacing: -0.03em; }}
      .hero-spotlight {{ padding: 22px; background: linear-gradient(135deg, rgba(126,216,255,0.12), rgba(142,247,200,0.08) 48%, rgba(255,207,125,0.08)); }}
      .spotlight-title {{ margin: 8px 0 10px; font-size: clamp(26px, 4vw, 42px); line-height: 1.02; letter-spacing: -0.04em; }}
      .spotlight-subtitle {{ color: var(--muted); line-height: 1.7; }}
      .nav {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 22px 0 18px; }}
      .tab {{
        padding: 12px 16px; border-radius: 999px; border: 1px solid var(--line); background: rgba(9, 14, 22, 0.74);
        color: var(--muted); cursor: pointer; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase;
      }}
      .tab.active {{ color: #08111c; background: linear-gradient(135deg, var(--accent), var(--accent-2)); border-color: transparent; }}
      .panel {{ display: none; }}
      .panel.active {{ display: block; }}
      .card {{ padding: 22px; }}
      .card h2, .card h3 {{ margin: 0 0 12px; letter-spacing: -0.02em; }}
      .list {{ display: grid; gap: 10px; }}
      .item {{ padding: 12px 14px; border: 1px solid var(--line); border-radius: 16px; background: rgba(255, 255, 255, 0.02); }}
      .pill {{ display: inline-flex; align-items: center; gap: 8px; padding: 7px 10px; border-radius: 999px; border: 1px solid var(--line-strong); background: rgba(255, 255, 255, 0.03); font-size: 12px; }}
      .path {{ display: flex; flex-wrap: wrap; gap: 10px; }}
      .path-step {{ padding: 10px 12px; border-radius: 14px; background: linear-gradient(135deg, rgba(142,247,200,0.16), rgba(126,216,255,0.12)); border: 1px solid rgba(142, 247, 200, 0.32); font-size: 13px; }}
      .path-step.focus {{ background: linear-gradient(135deg, rgba(255,207,125,0.18), rgba(126,216,255,0.12)); border-color: rgba(255,207,125,0.34); }}
      .node-card.primary {{ border-color: rgba(142, 247, 200, 0.42); box-shadow: 0 0 0 1px rgba(142, 247, 200, 0.14) inset, var(--shadow); }}
      .node-card, .edge-card, .artifact-card {{ padding: 18px; }}
      .muted {{ color: var(--muted); }}
      .empty {{ padding: 18px; border: 1px dashed var(--line-strong); border-radius: 18px; color: var(--muted); }}
      pre {{ margin: 0; padding: 18px; border-radius: 18px; overflow: auto; background: rgba(3, 7, 11, 0.88); border: 1px solid var(--line); color: #d6e6ff; font-size: 12px; line-height: 1.6; }}
      a {{ color: var(--accent-2); text-decoration: none; }}
      .artifact-card a {{ display: inline-block; margin-top: 12px; }}
      .stack {{ display: grid; gap: 12px; }}
      .data-grid {{ display: grid; gap: 10px; }}
      .artifact-badge {{ display: inline-flex; padding: 6px 10px; border-radius: 999px; border: 1px solid var(--line-strong); color: var(--accent); font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; }}
      .artifact-status {{ margin-top: 8px; color: var(--muted); }}
      @media (max-width: 980px) {{ .summary-grid {{ grid-template-columns: 1fr; }} }}
      @media (max-width: 740px) {{ .shell {{ padding: 16px 14px 28px; }} .hero, .card, .hero-spotlight {{ padding: 18px; }} }}
    </style>
  </head>
  <body>
    <div id="app" class="shell"></div>
    <script>window.__FRACTURE_CONTROL_CENTER__ = {data_json};</script>
    <script>
      const data = window.__FRACTURE_CONTROL_CENTER__;
      const root = document.getElementById("app");
      const params = new URLSearchParams(window.location.search);
      const presentation = params.get("presentation") === "1";
      document.body.classList.toggle("presentation", presentation);
      const safe = (value) => {{
        if (value === null || value === undefined || value === "") return "unknown";
        if (typeof value === "number") return String(value);
        if (typeof value === "boolean") return value ? "true" : "false";
        return String(value);
      }};
      const percent = (value) => `${{Math.round(Number(value || 0) * 100)}}%`;
      const list = (items) => Array.isArray(items) ? items.filter(Boolean) : [];
      const pretty = (value) => JSON.stringify(value, null, 2);
      const humanize = (value) => {{
        if (Array.isArray(value)) return value.join(", ") || "none";
        if (value && typeof value === "object") return pretty(value);
        return safe(value);
      }};
      const renderPills = (items, focus = false) => list(items).length
        ? `<div class="path">${{list(items).map((item) => `<div class="${{focus ? "path-step focus" : "pill"}}">${{safe(item)}}</div>`).join("")}}</div>`
        : '<div class="empty">No signals available.</div>';
      const renderPairs = (payload) => {{
        const entries = Object.entries(payload || {{}}).filter(([, value]) => value !== null && value !== undefined && value !== "" && (!(Array.isArray(value)) || value.length));
        if (!entries.length) return '<div class="empty">No structured data was present in the loaded artifacts.</div>';
        return `<div class="data-grid">${{entries.map(([key, value]) => `<div class="item"><div class="label">${{safe(key).replaceAll("_", " ")}}</div><div>${{humanize(value)}}</div></div>`).join("")}}</div>`;
      }};
      const tabs = [["executive","Executive Summary"],["overview","Overview"],["graph","Attack Graph"],["twin","Adversarial Twin"],["findings","Findings"],["artifacts","Artifacts"]];
      const session = data.overview.session_context || {{}};
      const graph = data.attack_graph || {{}};
      const graphSummary = graph.summary || {{}};
      const twin = data.adversarial_twin || {{}};
      const toolforge = data.toolforge || {{}};
      const governor = data.governor || {{}};
      const reality = data.reality || {{}};
      const shadow = data.shadow || {{}};
      const findings = data.findings || {{}};
      const executive = data.executive || {{}};
      const initialView = params.get("view") || "executive";
      const toggleQuery = new URLSearchParams(params);
      toggleQuery.set("view", initialView);
      if (presentation) toggleQuery.delete("presentation"); else toggleQuery.set("presentation", "1");
      const toggleHref = `${{window.location.pathname}}?${{toggleQuery.toString()}}`;

      const renderExecutive = () => `<div class="stack">
        <div class="summary-grid">
          <section class="hero-spotlight">
            <div class="label">Top Finding</div>
            <div class="spotlight-title">${{safe(executive.top_finding)}}</div>
            <div class="spotlight-subtitle">Recommended next step: ${{safe(executive.recommended_next_step)}}. Primary path and signal posture are lifted directly from the loaded FRACTURE artifacts.</div>
            <div style="margin-top:18px">${{renderPills(executive.top_signals)}}</div>
          </section>
          <section class="card">
            <h2>Executive Summary</h2>
            <div class="mini-grid">
              <div class="item"><div class="label">Overall Posture</div><div>${{safe(executive.overall_posture)}}</div></div>
              <div class="item"><div class="label">Attackability</div><div>${{safe(executive.attackability)}}</div></div>
              <div class="item"><div class="label">Auth Wall</div><div>${{safe(executive.auth_wall)}}</div></div>
              <div class="item"><div class="label">Auth Dependency</div><div>${{safe(executive.auth_dependency)}}</div></div>
            </div>
            <div class="stack" style="margin-top:16px">
              <div class="item"><div class="label">Primary Path</div>${{renderPills(executive.primary_path, true)}}</div>
              <div class="item"><div class="label">Operational Limitations</div><div>${{list(executive.operational_limitations).join(" ; ") || "none"}}</div></div>
            </div>
          </section>
        </div>
        <div class="card-grid">
          <section class="card"><h2>ToolForge</h2>${{renderPairs(toolforge.summary || {{}})}}</section>
          <section class="card"><h2>Governor</h2>${{renderPairs(governor.summary || {{}})}}</section>
          <section class="card"><h2>Reality</h2>${{renderPairs(reality.summary || {{}})}}</section>
          <section class="card"><h2>Shadow</h2>${{renderPairs(shadow.summary || {{}})}}</section>
        </div>
      </div>`;

      const renderOverview = () => `<div class="card-grid">
        <section class="card"><h2>Overview</h2><div class="mini-grid">
          <div class="item"><div class="label">Target</div><div>${{safe(data.overview.target)}}</div></div>
          <div class="item"><div class="label">Best Candidate</div><div>${{safe(data.overview.best_candidate)}}</div></div>
          <div class="item"><div class="label">Intent</div><div>${{safe(data.overview.best_candidate_intent)}}</div></div>
          <div class="item"><div class="label">Auth Wall</div><div>${{safe(data.overview.auth_wall_type)}}</div></div>
          <div class="item"><div class="label">Confidence</div><div>${{percent(data.overview.auth_wall_confidence)}}</div></div>
          <div class="item"><div class="label">Opportunity</div><div>${{safe(data.overview.auth_opportunity_score)}} / 10</div></div>
          <div class="item"><div class="label">Attackability</div><div>${{safe(data.overview.attackability)}}</div></div>
          <div class="item"><div class="label">Overall Posture</div><div>${{safe(data.overview.overall_posture)}}</div></div>
          <div class="item"><div class="label">Recommended Next Step</div><div>${{safe(data.overview.recommended_next_step)}}</div></div>
        </div></section>
        <section class="card"><h2>Session Context</h2><div class="list">
          <div class="item"><div class="label">Session Material</div><div>${{session.session_material_present ? "present" : "none"}}</div></div>
          <div class="item"><div class="label">Cookie Count</div><div>${{safe(session.session_cookie_count || 0)}}</div></div>
          <div class="item"><div class="label">Cookie Names</div><div>${{list(session.session_cookie_names).join(", ") || "none"}}</div></div>
          <div class="item"><div class="label">Session Source</div><div>${{safe(session.session_cookie_source)}}</div></div>
          <div class="item"><div class="label">Session Reused / Constraints</div><div>${{list(session.operational_limitations).join(" ; ") || safe(session.auth_or_session_dependency)}}</div></div>
        </div></section>
      </div>`;

      const renderGraph = () => {{
        const nodes = list(graph.nodes);
        const edges = list(graph.edges);
        const primaryPath = list(graphSummary.primary_path);
        return `<div class="card-grid">
          <section class="card"><h2>Primary Path</h2>
            ${{
              primaryPath.length
                ? `<div class="path">${{primaryPath.map((step) => `<div class="path-step">${{safe(step)}}</div>`).join("")}}</div>`
                : '<div class="empty">No primary path available in the loaded artifacts.</div>'
            }}
            <div style="margin-top:16px" class="mini-grid">
              <div class="item"><div class="label">Nodes</div><div>${{safe(graphSummary.node_count || nodes.length)}}</div></div>
              <div class="item"><div class="label">Edges</div><div>${{safe(graphSummary.edge_count || edges.length)}}</div></div>
              <div class="item"><div class="label">Blockers</div><div>${{list(graphSummary.blockers).join(" ; ") || "none"}}</div></div>
              <div class="item"><div class="label">Dependency</div><div>${{safe(graphSummary.auth_or_session_dependency)}}</div></div>
            </div>
          </section>
          <section class="card"><h2>Nodes</h2>
            ${{
              nodes.length
                ? `<div class="card-grid">${{nodes.map((node) => `<div class="node-card ${{primaryPath.includes(node.id) ? "primary" : ""}}"><div class="label">${{safe(node.kind)}}</div><h3>${{safe(node.label)}}</h3><pre>${{pretty(node.attrs || {{}})}}</pre></div>`).join("")}}</div>`
                : '<div class="empty">attack_graph.nodes is not available.</div>'
            }}
          </section>
          <section class="card"><h2>Edges</h2>
            ${{
              edges.length
                ? `<div class="list">${{edges.map((edge) => `<div class="edge-card"><div class="label">${{safe(edge.type)}}</div><div>${{safe(edge.source)}} -> ${{safe(edge.target)}}</div><pre>${{pretty(edge.attrs || {{}})}}</pre></div>`).join("")}}</div>`
                : '<div class="empty">attack_graph.edges is not available.</div>'
            }}
          </section>
        </div>`;
      }};

      const renderTwin = () => {{
        const summary = twin.summary || {{}};
        const sections = [["Auth Profile", twin.auth_profile || {{}}],["Session Context", twin.session_profile || {{}}],["Invocation Profile", twin.invocation_profile || {{}}],["Surface Model", twin.surface_model || {{}}],["Offensive Signals", twin.offensive_signals || {{}}],["ToolForge", toolforge.summary || {{}}],["Governor", governor.summary || {{}}],["Reality", reality.summary || {{}}],["Shadow", shadow.summary || {{}}]];
        return `<div class="card-grid">
          <section class="card"><h2>Summary</h2>
            ${{
              Object.keys(summary).length
                ? `<div class="mini-grid">
                    <div class="item"><div class="label">Overall Posture</div><div>${{safe(summary.overall_posture)}}</div></div>
                    <div class="item"><div class="label">Attackability</div><div>${{safe(summary.attackability)}}</div></div>
                    <div class="item"><div class="label">Auth Dependency</div><div>${{safe(summary.auth_dependency)}}</div></div>
                    <div class="item"><div class="label">Next Step</div><div>${{safe(summary.recommended_next_step)}}</div></div>
                    <div class="item"><div class="label">Simulated Best Path</div><div>${{safe(summary.simulated_best_path)}}</div></div>
                    <div class="item"><div class="label">Scenario Count</div><div>${{safe(summary.scenario_count)}}</div></div>
                  </div>
                  <div class="item" style="margin-top:16px"><div class="label">Twin Rationale</div><div>${{safe(summary.twin_rationale)}}</div></div>`
                : '<div class="empty">adversarial_twin.summary is not available.</div>'
            }}
          </section>
          ${{sections.map(([title, payload]) => `<section class="card"><h2>${{title}}</h2>${{renderPairs(payload)}}</section>`).join("")}}
        </div>`;
      }};

      const renderFindings = () => `<div class="card-grid">
        <section class="card"><h2>Findings Summary</h2><div class="mini-grid">
          <div class="item"><div class="label">Confirmed</div><div>${{safe((findings.findings_summary || {{}}).confirmed || 0)}}</div></div>
          <div class="item"><div class="label">Probable</div><div>${{safe((findings.findings_summary || {{}}).probable || 0)}}</div></div>
          <div class="item"><div class="label">Possible</div><div>${{safe((findings.findings_summary || {{}}).possible || 0)}}</div></div>
          <div class="item"><div class="label">Negative</div><div>${{safe((findings.findings_summary || {{}}).negative || 0)}}</div></div>
        </div></section>
        <section class="card"><h2>Executive Summary</h2>${{list(findings.executive_summary).length ? `<div class="list">${{list(findings.executive_summary).map((item) => `<div class="item">${{safe(item)}}</div>`).join("")}}</div>` : '<div class="empty">No executive summary was present in the loaded report.</div>'}}</section>
        <section class="card"><h2>Module Assessment</h2>${{list(findings.module_assessment).length ? `<div class="list">${{list(findings.module_assessment).map((item) => `<div class="item"><div class="label">${{safe(item.module)}}</div><div>${{safe(item.assessment)}} / ${{safe(item.module_assessment)}}</div></div>`).join("")}}</div>` : '<div class="empty">No module assessment entries were present in the loaded report.</div>'}}</section>
        <section class="card"><h2>Report Rationale</h2>${{list(findings.report_rationale).length ? `<div class="list">${{list(findings.report_rationale).map((item) => `<div class="item">${{safe(item)}}</div>`).join("")}}</div>` : '<div class="empty">No report rationale entries were present in the loaded report.</div>'}}</section>
        <section class="card"><h2>Key Signals</h2>${{list(findings.key_signals).length ? `<div class="path">${{list(findings.key_signals).map((item) => `<div class="pill">${{safe(item)}}</div>`).join("")}}</div>` : '<div class="empty">No key signals were present in the loaded report.</div>'}}</section>
        <section class="card"><h2>Operational Limitations</h2>${{list(findings.operational_limitations).length ? `<div class="list">${{list(findings.operational_limitations).map((item) => `<div class="item">${{safe(item)}}</div>`).join("")}}</div>` : '<div class="empty">No operational limitations were present in the loaded artifacts.</div>'}}</section>
      </div>`;

      const renderArtifacts = () => `<div class="artifact-grid">${{Object.entries(data.artifacts || {{}}).map(([name, artifact]) => `
        <section class="artifact-card">
          <div class="artifact-badge">${{artifact.available ? "available" : "missing"}}</div>
          <div class="label" style="margin-top:12px">${{safe(name)}}</div>
          <h2 style="margin:6px 0 0">${{safe(artifact.label)}}</h2>
          <div class="artifact-status">${{artifact.available ? "Sanitized artifact ready for demo review." : "Artifact not loaded in this workspace."}}</div>
          <div class="muted" style="margin-top:8px">${{safe(artifact.path)}}</div>
          ${{artifact.available ? `<a href="/artifacts/${{name}}.json" target="_blank" rel="noreferrer">Open sanitized artifact</a>` : '<div class="muted" style="margin-top:12px">Degraded cleanly</div>'}}
        </section>`).join("")}}</div>`;

      const renderPanel = (key) => key === "executive" ? renderExecutive() : key === "overview" ? renderOverview() : key === "graph" ? renderGraph() : key === "twin" ? renderTwin() : key === "findings" ? renderFindings() : renderArtifacts();

      root.innerHTML = `
        <section class="hero">
          <div class="hero-top">
            <div>
              <div class="eyebrow">FRACTURE Control Center <span class="muted">read-only / sanitized</span></div>
              <h1>Executive Demo Workspace</h1>
              <p class="lede">A client-ready local control surface over real FRACTURE artifacts. The hierarchy is tuned for meetings first: posture, attackability, auth dependency, next step, top finding and primary path stay foregrounded.</p>
            </div>
            <div class="toolbar">
              <div class="tool">${{data.demo_workspace ? "golden demo workspace" : "custom workspace"}}</div>
              <div class="tool"><a href="${{toggleHref}}">${{presentation ? "exit presentation mode" : "presentation mode"}}</a></div>
            </div>
          </div>
          <div class="hero-grid">
            <div class="metric"><div class="label">Target</div><div class="value value-strong">${{safe(data.overview.target)}}</div></div>
            <div class="metric"><div class="label">Overall Posture</div><div class="value value-strong">${{safe(data.overview.overall_posture)}}</div></div>
            <div class="metric"><div class="label">Attackability</div><div class="value value-strong">${{safe(data.overview.attackability)}}</div></div>
            <div class="metric"><div class="label">Auth Dependency</div><div class="value">${{safe(executive.auth_dependency)}}</div></div>
            <div class="metric"><div class="label">Best Candidate</div><div class="value">${{safe(data.overview.best_candidate)}}</div></div>
            <div class="metric"><div class="label">Primary Path</div><div class="value">${{list(executive.primary_path).join(" -> ") || "none"}}</div></div>
            <div class="metric"><div class="label">Recommended Next Step</div><div class="value">${{safe(data.overview.recommended_next_step)}}</div></div>
          </div>
        </section>
        <nav class="nav">${{tabs.map(([key, label]) => `<button class="tab ${{key === initialView ? "active" : ""}}" data-tab="${{key}}">${{label}}</button>`).join("")}}</nav>
        ${{tabs.map(([key]) => `<section class="panel ${{key === initialView ? "active" : ""}}" data-panel="${{key}}">${{renderPanel(key)}}</section>`).join("")}}
      `;

      for (const button of root.querySelectorAll(".tab")) {{
        button.addEventListener("click", () => {{
          const key = button.dataset.tab;
          for (const tab of root.querySelectorAll(".tab")) tab.classList.toggle("active", tab === button);
          for (const panel of root.querySelectorAll(".panel")) panel.classList.toggle("active", panel.dataset.panel === key);
        }});
      }}
    </script>
  </body>
</html>"""


def _resolve_artifact_paths(
    *,
    workspace: Optional[str],
    scan_path: Optional[str],
    attack_path: Optional[str],
    report_path: Optional[str],
) -> dict[str, Optional[Path]]:
    if not workspace and not any([scan_path, attack_path, report_path]):
        raise ValueError("UI requires --workspace or at least one of --scan/--attack/--report.")

    resolved = {
        "scan": Path(scan_path).expanduser().resolve() if scan_path else None,
        "attack": Path(attack_path).expanduser().resolve() if attack_path else None,
        "report": Path(report_path).expanduser().resolve() if report_path else None,
    }
    if workspace:
        workspace_path = Path(workspace).expanduser().resolve()
        for name in ("scan", "attack", "report"):
            if resolved[name] is None:
                resolved[name] = _discover_workspace_artifact(workspace_path, name)

    if not any(resolved.values()):
        raise ValueError("No UI artifacts were found. Expected scan.json, attack.json or report.json.")
    return resolved


def _discover_workspace_artifact(workspace: Path, name: str) -> Optional[Path]:
    direct = workspace / f"{name}.json"
    if direct.exists():
        return direct
    exact_matches = sorted(workspace.rglob(f"{name}.json"))
    if exact_matches:
        return exact_matches[0]
    suffix_matches = sorted(workspace.rglob(f"*{name}.json"))
    if suffix_matches:
        return suffix_matches[0]
    return None


def _load_optional_json(path: Optional[Path]) -> Optional[dict]:
    if path is None:
        return None
    with open(path, "r") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Artifact '{path}' does not contain a JSON object.")
    return payload


def _extract_scan_surface_details(scan_payload: dict) -> dict:
    return _first_dict(_nested(scan_payload, "fingerprint", "evidence", "surface_discovery", "details"))


def _extract_scan_handoff(scan_payload: dict) -> dict:
    return _first_dict(scan_payload.get("handoff"), _extract_scan_surface_details(scan_payload).get("handoff"))


def _build_scan_session_context(scan_payload: dict, handoff: dict) -> dict:
    triage = _first_dict(scan_payload.get("triage"))
    return {
        "session_material_present": bool(handoff.get("session_material_present", triage.get("session_material_present", False))),
        "session_cookie_count": int(handoff.get("session_cookie_count", triage.get("session_cookie_count", 0)) or 0),
        "session_cookie_names": list(handoff.get("session_cookie_names", triage.get("session_cookie_names", [])) or []),
        "session_cookie_source": str(handoff.get("session_cookie_source", triage.get("session_cookie_source", "none")) or "none"),
        "session_cookie_merge_strategy": str(handoff.get("session_cookie_merge_strategy", triage.get("session_cookie_merge_strategy", "unknown")) or "unknown"),
        "operational_limitations": list(triage.get("operational_limitations", []) or []),
    }


def _build_executive_summary(
    *,
    overview: dict,
    attack_graph: dict,
    adversarial_twin: dict,
    findings: dict,
    boardroom: dict | None = None,
    toolforge: dict | None = None,
    governor: dict | None = None,
    reality: dict | None = None,
    shadow: dict | None = None,
) -> dict:
    graph_summary = _first_dict((attack_graph or {}).get("summary"))
    twin_summary = _first_dict((adversarial_twin or {}).get("summary"))
    boardroom_summary = _first_dict((boardroom or {}).get("summary"))
    boardroom_operator = _first_dict((boardroom or {}).get("operator_brief"))
    toolforge_summary = _first_dict((toolforge or {}).get("summary"))
    governor_summary = _first_dict((governor or {}).get("summary"))
    reality_summary = _first_dict((reality or {}).get("summary"))
    shadow_summary = _first_dict((shadow or {}).get("summary"))
    top_finding = _first_str(
        boardroom_summary.get("top_finding") if boardroom_summary else None,
        governor_summary.get("strongest_gap") if governor_summary else None,
        toolforge_summary.get("strongest_chain") if toolforge_summary else None,
        *(findings.get("executive_summary", []) or []),
        *(findings.get("highlights", []) or []),
    )
    if not top_finding:
        ranked = sorted(
            findings.get("module_assessment", []) or [],
            key=lambda item: _assessment_rank(str(item.get("assessment", "unknown") or "unknown")),
        )
        if ranked:
            best = ranked[0]
            top_finding = (
                f"{best.get('module', 'module')}: "
                f"{best.get('assessment', 'unknown')} ({best.get('module_assessment', 'unknown')})"
            )

    auth_dependency = _first_str(
        twin_summary.get("auth_dependency"),
        overview.get("session_context", {}).get("auth_or_session_dependency"),
    ) or "none"

    return {
        "top_finding": top_finding or "No decisive top finding was present in the loaded artifacts.",
        "top_signals": list((findings.get("key_signals", []) or [])[:5]),
        "overall_posture": _first_str(
            boardroom_summary.get("risk_posture") if boardroom_summary else None,
            overview.get("overall_posture", "unknown"),
        ) or "unknown",
        "attackability": overview.get("attackability", "unknown"),
        "auth_wall": overview.get("auth_wall_type", "no_auth_wall"),
        "auth_dependency": auth_dependency,
        "recommended_next_step": _first_str(
            boardroom_summary.get("recommended_action") if boardroom_summary else None,
            boardroom_operator.get("next_step") if boardroom_operator else None,
            shadow_summary.get("recommended_move") if shadow_summary else None,
            governor_summary.get("recommended_move") if governor_summary else None,
            toolforge_summary.get("recommended_move") if toolforge_summary else None,
            reality_summary.get("recommended_use") if reality_summary else None,
            overview.get("recommended_next_step", "collect_more_artifacts"),
        ) or "collect_more_artifacts",
        "operational_limitations": list((findings.get("operational_limitations", []) or [])[:4]),
        "primary_path": list(
            (boardroom_operator.get("primary_path") if boardroom_operator else None)
            or (graph_summary.get("primary_path", []) or [])
        )[:6],
    }


def _sanitize_value(value, key: str = ""):
    lowered_key = str(key or "").lower()
    if isinstance(value, dict):
        if lowered_key == "headers":
            return {
                str(header_name): "<redacted>" if _is_sensitive_key(str(header_name)) else header_value
                for header_name, header_value in value.items()
            }
        if lowered_key == "cookies":
            return {str(cookie_name): "<redacted>" for cookie_name in value.keys()}
        return {str(child_key): _sanitize_value(child_value, key=str(child_key)) for child_key, child_value in value.items()}
    if isinstance(value, list):
        if lowered_key == "session_cookies":
            sanitized = []
            for item in value:
                if isinstance(item, dict):
                    sanitized.append({
                        "name": str(item.get("name", "") or ""),
                        "value": "<redacted>",
                        "domain": str(item.get("domain", "") or ""),
                        "path": str(item.get("path", "/") or "/"),
                    })
                else:
                    sanitized.append(_sanitize_value(item, key=key))
            return sanitized
        return [_sanitize_value(item, key=key) for item in value]
    if lowered_key in SAFE_SENSITIVE_KEYS:
        return value
    if lowered_key and _is_sensitive_key(lowered_key):
        return "<redacted>"
    return value


def _is_sensitive_key(name: str) -> bool:
    lowered = str(name or "").lower()
    return any(token in lowered for token in SENSITIVE_KEY_TOKENS)


def _nested(payload, *keys):
    current = payload
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _first_dict(*values) -> dict:
    for value in values:
        if isinstance(value, dict):
            return value
    return {}


def _first_str(*values) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _first_int(*values) -> int:
    for value in values:
        try:
            if value not in (None, ""):
                return int(value)
        except Exception:
            continue
    return 0


def _first_float(*values) -> float:
    for value in values:
        try:
            if value not in (None, ""):
                return float(value)
        except Exception:
            continue
    return 0.0


def _listify(value) -> list:
    return list(value or []) if isinstance(value, list) else []


def _dedupe(items) -> list[str]:
    ordered = []
    for item in items or []:
        value = str(item or "").strip()
        if value and value not in ordered:
            ordered.append(value)
    return ordered


def _assessment_rank(value: str) -> int:
    order = {
        "confirmed": 0,
        "probable": 1,
        "possible": 2,
        "negative": 3,
        "unknown": 4,
    }
    return order.get(str(value or "unknown").strip().lower(), 5)
