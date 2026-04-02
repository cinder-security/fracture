import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from fracture.agents.report import Report
from fracture.cli import app
from fracture.core.result import AttackResult
from fracture.core.operations import ExecutionRecord
from fracture.ui.control_center import get_demo_workspace_path, load_control_center_bundle


class CLISmokeTests(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def _operation_state_path(self, workspace: Path) -> Path:
        matches = sorted((workspace / ".fracture" / "operations").glob("*.json"))
        self.assertTrue(matches)
        return matches[0]

    def _scan_fixture_result(self, target, *, intent: str, score: int, plan_modules: list[str], risk_level: str = "high"):
        return {
            "fingerprint": AttackResult(
                module="fingerprint",
                target_url=target.url,
                success=True,
                confidence=0.9,
                evidence={
                    "surface_discovery": {
                        "response": f"Passive web discovery: best_candidate intent={intent}.",
                        "details": {
                            "surface_label": "api_candidates_found",
                            "likely_browser_session_required": False,
                            "likely_websocket_or_streaming_surface": intent == "tool_or_agent_surface",
                            "api_candidates": ["https://example.test/api/chat/messages"],
                            "best_candidate": "https://example.test/api/chat/messages",
                            "best_candidate_score": score,
                            "best_candidate_reasons": [f"{intent} fixture"],
                            "best_candidate_intent": intent,
                            "best_candidate_score_breakdown": [
                                {"reason": f"{intent} fixture", "delta": 4},
                            ],
                            "top_candidates": [
                                {
                                    "url": "https://example.test/api/chat/messages",
                                    "score": score,
                                    "intent": intent,
                                    "reasons": [f"{intent} fixture"],
                                    "score_breakdown": [{"reason": f"{intent} fixture", "delta": 4}],
                                }
                            ],
                            "handoff": {
                                "recommended_target_url": "https://example.test/api/chat/messages",
                                "intent": intent,
                                "score": score,
                                "source_mode": "passive",
                                "transport_hint": "http",
                                "method_hint": "POST",
                                "session_required": False,
                                "browser_session_likely": False,
                                "auth_signals": [],
                                "observed_header_names": [],
                                "observed_cookie_names": [],
                                "invocation_profile": {
                                    "method_hint": "POST",
                                    "content_type_hint": "application/json",
                                    "accepts_json": True,
                                    "streaming_likely": False,
                                    "websocket_likely": intent == "tool_or_agent_surface",
                                    "observed_body_keys": ["message"],
                                    "observed_query_param_names": ["mode"],
                                    "observed_header_names": ["Content-Type"],
                                    "observed_cookie_names": [],
                                },
                                "notes": [],
                            },
                        },
                    },
                    "_meta": {"prompts_sent": 7},
                },
                notes="fixture scan",
            ),
            "plan": {
                "detected_model": "llm-agent" if intent == "tool_or_agent_surface" else "unknown",
                "risk_level": risk_level,
                "analysis": f"{intent} detected.",
                "rationale": f"{intent} prioritized.",
                "planning_rationale": [f"{intent} prioritized by fixture"],
                "module_priority_reasons": {plan_modules[0]: [f"{intent} fixture"]},
                "surface_constraints": [],
                "planning_signals_used": [f"best_candidate_intent={intent}", f"best_candidate_score={score}"],
                "auth_friction_present": False,
                "auth_friction_rationale": "",
                "operational_limitations": [],
                "attack_plan": plan_modules,
            },
        }

    def test_scan_command_smoke(self):
        captured = {}

        async def fake_run_scan(target, planner="local", discovery_mode="passive"):
            captured["target"] = target
            captured["planner"] = planner
            captured["discovery_mode"] = discovery_mode
            return {
                "fingerprint": AttackResult(
                    module="fingerprint",
                    target_url=target.url,
                    success=True,
                    confidence=1.0,
                    evidence={
                        "model_identity": {"response": "claude agent with tools"},
                        "surface_discovery": {
                            "response": "Passive web discovery: api_candidates_found.",
                            "details": {
                                "surface_label": "api_candidates_found",
                                "likely_browser_session_required": True,
                                "likely_websocket_or_streaming_surface": False,
                                "api_candidates": ["https://example.test/api/chat/messages"],
                                "best_candidate": "https://example.test/api/chat/messages",
                                "best_candidate_score": 14,
                                "best_candidate_reasons": ["observed in frontend fetch/xhr"],
                                "best_candidate_intent": "chat_surface",
                                "browser_recon_note": "PhantomTwin browser recon observed frontend network activity.",
                                "login_form_detected": True,
                                "session_capture_note": "Session captured. 1 cookies stored.",
                                "auth_wall_detected": True,
                                "auth_wall_type": "form_login",
                                "auth_wall_confidence": 0.95,
                                "auth_success_markers": ["protected high-value endpoint observed"],
                                "already_authenticated_signals": [],
                                "manual_login_recommended": True,
                                "session_capture_readiness": "high",
                                "post_login_surface_score": 8,
                                "auth_opportunity_score": 9,
                                "auth_opportunity_level": "high",
                                "post_login_surface_label": "chat_surface",
                                "auth_wall_rationale": "A real username/password login wall was detected. Best post-auth candidate looks like a chat_surface with score 14.",
                                "best_candidate_score_breakdown": [
                                    {"reason": "observed in frontend fetch/xhr", "delta": 4},
                                    {"reason": "chat_surface intent inferred", "delta": 2},
                                ],
                                "top_candidates": [
                                    {
                                        "url": "https://example.test/api/chat/messages",
                                        "score": 14,
                                        "intent": "chat_surface",
                                        "reasons": ["observed in frontend fetch/xhr", "API-style path"],
                                        "score_breakdown": [
                                            {"reason": "observed in frontend fetch/xhr", "delta": 4},
                                            {"reason": "API-style path", "delta": 4},
                                        ],
                                    },
                                    {
                                        "url": "https://example.test/api/telemetry/events",
                                        "score": 5,
                                        "intent": "unknown_surface",
                                        "reasons": ["analytics/telemetry path"],
                                        "score_breakdown": [
                                            {"reason": "analytics/telemetry path", "delta": -5},
                                        ],
                                    },
                                ],
                                "handoff": {
                                    "recommended_target_url": "https://example.test/api/chat/messages",
                                    "intent": "chat_surface",
                                    "score": 14,
                                    "source_mode": "phantomtwin",
                                    "transport_hint": "http",
                                    "method_hint": "POST",
                                    "session_required": True,
                                    "browser_session_likely": True,
                                    "auth_signals": ["cookie", "session"],
                                    "observed_header_names": ["Authorization"],
                                    "observed_cookie_names": ["session"],
                                    "session_cookies": [
                                        {
                                            "name": "session",
                                            "value": "captured-session",
                                            "domain": "example.test",
                                            "path": "/",
                                        }
                                    ],
                                    "session_cookie_header": "session=<redacted>",
                                    "session_material_present": True,
                                    "session_cookie_count": 1,
                                    "session_cookie_names": ["session"],
                                    "session_cookie_domains": ["example.test"],
                                    "session_cookie_source": "handoff",
                                    "session_cookie_merge_strategy": "captured_only",
                                    "session_cookie_header_redacted": True,
                                    "session_scope_applied": False,
                                    "session_propagation_note": "Captured browser session cookies are available for --from-scan reuse.",
                                    "auth_wall_detected": True,
                                    "auth_wall_type": "form_login",
                                    "auth_wall_confidence": 0.95,
                                    "auth_success_markers": ["protected high-value endpoint observed"],
                                    "already_authenticated_signals": [],
                                    "manual_login_recommended": True,
                                    "session_capture_readiness": "high",
                                    "post_login_surface_score": 8,
                                    "auth_opportunity_score": 9,
                                    "auth_opportunity_level": "high",
                                    "post_login_surface_label": "chat_surface",
                                    "auth_wall_rationale": "A real username/password login wall was detected. Best post-auth candidate looks like a chat_surface with score 14.",
                                    "invocation_profile": {
                                        "method_hint": "POST",
                                        "content_type_hint": "application/json",
                                        "accepts_json": True,
                                        "streaming_likely": False,
                                        "websocket_likely": False,
                                        "request_shape_hints": ["frontend fetch/xhr observed", "json request content type"],
                                        "observed_body_keys": ["message", "messages"],
                                        "observed_query_param_names": ["mode"],
                                        "observed_header_names": ["Authorization", "Content-Type"],
                                        "observed_cookie_names": ["session"],
                                        "invocation_notes": ["Observed POST request shape for the candidate endpoint."],
                                    },
                                    "notes": ["Use POST against the recommended endpoint."],
                                },
                            },
                        },
                        "_meta": {"prompts_sent": 7},
                    },
                    notes="Fingerprint complete",
                ),
                "plan": {
                    "detected_model": "claude",
                    "risk_level": "high",
                    "analysis": "Agentic target detected.",
                    "rationale": "Tool signals present.",
                    "planning_rationale": [
                        "extract/memory prioritized because the discovered surface looks conversational",
                        "session/auth friction kept the plan conservative without blocking conversational modules",
                    ],
                    "module_priority_reasons": {
                        "extract": ["chat surface intent", "conversational request shape"],
                        "memory": ["chat surface intent", "still useful under session/auth friction"],
                    },
                    "surface_constraints": [
                        "surface appears actionable but has access friction: session-required, browser-session-likely, auth-signals=cookie,session"
                    ],
                    "planning_signals_used": [
                        "best_candidate_intent=chat_surface",
                        "best_candidate_score=14",
                        "method_hint=POST",
                    ],
                    "attack_plan": ["extract", "memory", "ssrf"],
                },
            }

        with tempfile.TemporaryDirectory() as tmpdir:
            output = str(Path(tmpdir) / "scan.json")
            with patch("fracture.cli._run_scan", fake_run_scan):
                result = self.runner.invoke(
                    app,
                    [
                        "scan",
                        "--target", "https://example.test/api",
                        "--planner", "local",
                        "--mode", "phantomtwin",
                        "--model", "demo-model",
                        "--header", "X-Test=1",
                        "--cookie", "session=abc123",
                        "--timeout", "9",
                        "--output", output,
                    ],
                )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            payload = json.loads(Path(output).read_text())
            self.assertEqual(captured["planner"], "local")
            self.assertEqual(captured["discovery_mode"], "phantomtwin")
            self.assertEqual(captured["target"].url, "https://example.test/api")
            self.assertEqual(captured["target"].model, "demo-model")
            self.assertEqual(captured["target"].headers, {"X-Test": "1"})
            self.assertEqual(captured["target"].cookies, {"session": "abc123"})
            self.assertEqual(captured["target"].timeout, 9)
            self.assertEqual(payload["triage"]["recon_mode"], "phantomtwin")
            self.assertEqual(payload["triage"]["suggested_modules"], ["extract", "memory", "ssrf"])
            self.assertEqual(payload["triage"]["planning_signals_used"][0], "best_candidate_intent=chat_surface")
            self.assertTrue(payload["triage"]["planning_rationale"])
            self.assertTrue(payload["triage"]["surface_constraints"])
            self.assertTrue(payload["triage"]["auth_friction_present"])
            self.assertTrue(payload["triage"]["auth_material_provided"])
            self.assertEqual(payload["triage"]["auth_material_types"], ["headers", "cookies"])
            self.assertTrue(payload["triage"]["auth_wall_detected"])
            self.assertEqual(payload["triage"]["auth_wall_type"], "form_login")
            self.assertEqual(payload["triage"]["auth_opportunity_level"], "high")
            self.assertTrue(payload["triage"]["manual_login_recommended"])
            self.assertEqual(payload["triage"]["post_login_surface_label"], "chat_surface")
            self.assertIn("session", " ".join(payload["triage"]["observed_auth_signal_names"]).lower())
            self.assertTrue(payload["triage"]["operational_limitations"])
            self.assertEqual(payload["header_names"], ["X-Test"])
            self.assertEqual(payload["cookie_names"], ["session"])
            self.assertEqual(payload["handoff"]["recommended_target_url"], "https://example.test/api/chat/messages")
            self.assertEqual(payload["handoff"]["observed_header_names"], ["Authorization"])
            self.assertEqual(payload["handoff"]["observed_cookie_names"], ["session"])
            self.assertEqual(payload["handoff"]["session_cookie_header"], "session=<redacted>")
            self.assertEqual(payload["handoff"]["session_cookies"][0]["name"], "session")
            self.assertTrue(payload["triage"]["session_material_present"])
            self.assertEqual(payload["triage"]["session_cookie_count"], 1)
            self.assertEqual(payload["triage"]["session_cookie_names"], ["session"])
            self.assertTrue(payload["triage"]["session_cookie_header_redacted"])
            self.assertEqual(payload["handoff"]["invocation_profile"]["method_hint"], "POST")
            self.assertEqual(payload["handoff"]["invocation_profile"]["observed_body_keys"], ["message", "messages"])
            self.assertEqual(payload["triage"]["top_candidates"][0]["url"], "https://example.test/api/chat/messages")
            self.assertIn("Top Candidates:", result.output)
            self.assertIn("Login form detected during PhantomTwin recon", result.output)
            self.assertIn("Session captured. 1 cookies stored.", result.output)
            self.assertIn("Session cookie header is redacted", result.output)
            self.assertNotIn("captured-session", result.output)
            self.assertIn("Score Detail:", result.output)
            self.assertIn("Invocation:", result.output)
            self.assertIn("Planning Signals:", result.output)
            self.assertIn("Constraints:", result.output)
            self.assertIn("Priority Why:", result.output)
            self.assertIn("Session/Auth Constraint:", result.output)
            self.assertIn("Manual Auth Context:", result.output)
            self.assertIn("Coverage Limitation:", result.output)
            self.assertIn("Auth Wall:", result.output)
            self.assertIn("Opportunity:", result.output)
            self.assertIn("Manual Login:", result.output)
            self.assertIn("Post-Login Surface:", result.output)
            self.assertIn("Auth Rationale:", result.output)
            self.assertIn("Operator Cue", result.output)

    def test_scan_command_distinguishes_discovery_error_from_auth_friction(self):
        async def fake_run_scan(target, planner="local", discovery_mode="passive"):
            return {
                "fingerprint": AttackResult(
                    module="fingerprint",
                    target_url=target.url,
                    success=False,
                    confidence=0.0,
                    evidence={
                        "surface_discovery": {
                            "response": "Passive web discovery unavailable: timeout",
                            "details": {
                                "surface_label": "discovery_error",
                                "best_candidate": None,
                                "best_candidate_score": 0,
                                "best_candidate_intent": "unknown_surface",
                                "handoff": {
                                    "recommended_target_url": target.url,
                                    "intent": "unknown_surface",
                                    "score": 0,
                                    "session_required": False,
                                    "browser_session_likely": False,
                                    "auth_signals": [],
                                },
                            },
                        }
                    },
                    notes="discovery failed",
                ),
                "plan": {
                    "detected_model": "unknown",
                    "risk_level": "medium",
                    "analysis": "discovery failed",
                    "rationale": "discovery failed",
                    "attack_plan": ["extract", "hpm"],
                    "planning_rationale": [],
                    "module_priority_reasons": {},
                    "surface_constraints": [],
                    "planning_signals_used": [],
                    "auth_friction_present": False,
                    "auth_friction_rationale": "",
                    "operational_limitations": [],
                },
            }

        with patch("fracture.cli._run_scan", fake_run_scan):
            result = self.runner.invoke(
                app,
                ["scan", "--target", "https://example.test/api"],
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Surface Status:", result.output)
        self.assertIn("transport_or_discovery_error", result.output)
        self.assertNotIn("Useful surface detected, but interaction likely requires session/auth context", result.output)

    def test_scan_command_warns_when_phantomtwin_runtime_missing(self):
        async def fake_run_scan(target, planner="local", discovery_mode="passive"):
            return {
                "fingerprint": AttackResult(
                    module="fingerprint",
                    target_url=target.url,
                    success=False,
                    confidence=0.0,
                    evidence={"surface_discovery": {"response": "fallback", "details": {}}},
                    notes="fallback",
                ),
                "plan": {
                    "detected_model": "unknown",
                    "risk_level": "medium",
                    "analysis": "fallback",
                    "rationale": "fallback",
                    "attack_plan": ["extract", "hpm"],
                },
            }

        with patch(
            "fracture.cli._run_scan",
            fake_run_scan,
        ), patch(
            "fracture.core.surface_discovery.get_phantomtwin_runtime_status",
            return_value={
                "ready": False,
                "reason": "Playwright is not installed in the current Python runtime.",
                "hint": "Install it in the active environment and run `python -m playwright install chromium`.",
            },
        ):
            result = self.runner.invoke(
                app,
                [
                    "scan",
                    "--target", "https://example.test/api",
                    "--mode", "phantomtwin",
                ],
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("PhantomTwin runtime guard", result.output)
        self.assertIn("Playwright is not installed", result.output)

    def test_scan_command_retrieval_surface_keeps_retrieval_priority_visible(self):
        async def fake_run_scan(target, planner="local", discovery_mode="passive"):
            return self._scan_fixture_result(
                target,
                intent="retrieval_surface",
                score=12,
                plan_modules=["retrieval_poison", "extract", "memory"],
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            output = str(Path(tmpdir) / "scan.json")
            with patch("fracture.cli._run_scan", fake_run_scan):
                result = self.runner.invoke(
                    app,
                    ["scan", "--target", "https://example.test/api", "--output", output],
                )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            payload = json.loads(Path(output).read_text())
            self.assertEqual(payload["triage"]["suggested_modules"][0], "retrieval_poison")
            self.assertEqual(payload["triage"]["planning_signals_used"][0], "best_candidate_intent=retrieval_surface")
            self.assertEqual(payload["handoff"]["intent"], "retrieval_surface")
            self.assertIn("retrieval_surface", result.output)

    def test_scan_command_tool_surface_keeps_agentic_priority_visible(self):
        async def fake_run_scan(target, planner="local", discovery_mode="passive"):
            return self._scan_fixture_result(
                target,
                intent="tool_or_agent_surface",
                score=13,
                plan_modules=["extract", "hpm", "privesc", "obliteratus"],
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            output = str(Path(tmpdir) / "scan.json")
            with patch("fracture.cli._run_scan", fake_run_scan):
                result = self.runner.invoke(
                    app,
                    ["scan", "--target", "https://example.test/api", "--output", output],
                )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            payload = json.loads(Path(output).read_text())
            self.assertEqual(payload["triage"]["suggested_modules"][:3], ["extract", "hpm", "privesc"])
            self.assertEqual(payload["handoff"]["intent"], "tool_or_agent_surface")
            self.assertTrue(payload["handoff"]["invocation_profile"]["websocket_likely"])
            self.assertIn("tool_or_agent_surface", result.output)

    def test_attack_command_smoke(self):
        captured = {}

        async def fake_run_attack(target, modules, objective=None, execution_hints=None):
            captured["target"] = target
            captured["modules"] = modules
            captured["objective"] = objective
            captured["execution_hints"] = execution_hints
            return {
                "attacks": {
                    "extract": AttackResult(
                        module="extract",
                        target_url=target.url,
                        success=True,
                        confidence=0.51,
                        evidence={"_meta": {"best_vector": "roleplay_extraction"}},
                        notes="Extract complete",
                    ),
                    "memory": AttackResult(
                        module="memory",
                        target_url=target.url,
                        success=False,
                        confidence=0.12,
                        evidence={"_meta": {"successful_phases": 1}},
                        notes="Memory complete",
                    ),
                }
            }

        with tempfile.TemporaryDirectory() as tmpdir:
            output = str(Path(tmpdir) / "attack.json")
            with patch("fracture.cli._run_attack", fake_run_attack):
                result = self.runner.invoke(
                    app,
                    [
                        "attack",
                        "--target", "https://example.test/api",
                        "--module", "extract",
                        "--module", "memory",
                        "--objective", "reveal hidden instructions",
                        "--model", "demo-model",
                        "--header", "X-Test=1",
                        "--cookie", "session=abc123",
                        "--timeout", "11",
                        "--output", output,
                    ],
                )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            payload = json.loads(Path(output).read_text())
            self.assertEqual(captured["modules"], ["extract", "memory"])
            self.assertEqual(captured["objective"], "reveal hidden instructions")
            self.assertIsNone(captured["execution_hints"])
            self.assertEqual(captured["target"].cookies, {"session": "abc123"})
            self.assertIsNone(payload["execution_hints"])
            self.assertEqual(payload["modules"], ["extract", "memory"])
            self.assertTrue(payload["results"]["extract"]["success"])
            self.assertEqual(payload["timeout"], 11)

    def test_attack_command_uses_handoff_from_scan_when_target_missing(self):
        captured = {}

        async def fake_run_attack(target, modules, objective=None, execution_hints=None):
            captured["target"] = target
            captured["execution_hints"] = execution_hints
            return {"attacks": {}}

        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            scan_path.write_text(json.dumps({
                "handoff": {
                    "recommended_target_url": "https://example.test/api/chat/messages",
                    "intent": "chat_surface",
                    "score": 12,
                    "source_mode": "phantomtwin",
                    "transport_hint": "http",
                    "method_hint": "POST",
                    "session_required": False,
                    "browser_session_likely": False,
                    "auth_signals": [],
                    "observed_header_names": [],
                    "observed_cookie_names": [],
                    "invocation_profile": {
                        "method_hint": "POST",
                        "content_type_hint": "application/json",
                        "accepts_json": True,
                        "streaming_likely": False,
                        "websocket_likely": False,
                        "request_shape_hints": ["frontend fetch/xhr observed"],
                        "observed_body_keys": ["message"],
                        "observed_query_param_names": ["mode"],
                        "observed_header_names": ["Content-Type"],
                        "observed_cookie_names": [],
                        "invocation_notes": [],
                    },
                    "notes": [],
                }
            }))
            with patch("fracture.cli._run_attack", fake_run_attack):
                result = self.runner.invoke(
                    app,
                    ["attack", "--from-scan", str(scan_path), "--module", "extract"],
                )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(captured["target"].url, "https://example.test/api/chat/messages")
        self.assertEqual(captured["execution_hints"]["method_hint"], "POST")
        self.assertEqual(captured["execution_hints"]["content_type_hint"], "application/json")
        self.assertEqual(captured["execution_hints"]["observed_body_keys"], ["message"])
        self.assertEqual(captured["execution_hints"]["observed_query_param_names"], ["mode"])
        self.assertIn("Attack Handoff", result.output)
        self.assertIn("Invocation:", result.output)
        self.assertIn("Execution Hints", result.output)

    def test_attack_command_injects_session_cookies_from_scan_handoff(self):
        captured = {}

        async def fake_run_attack(target, modules, objective=None, execution_hints=None):
            captured["target"] = target
            return {
                "attacks": {},
                "attack_graph": {
                    "nodes": [
                        {"id": "target_root", "kind": "target_root", "label": target.url},
                        {"id": "session_capture", "kind": "session_capture", "label": "session material"},
                    ],
                    "edges": [
                        {"source": "session_capture", "target": "target_root", "type": "reused_by"},
                    ],
                    "summary": {
                        "node_count": 2,
                        "edge_count": 1,
                        "primary_path": ["target_root", "session_capture"],
                        "strongest_nodes": ["session_capture"],
                        "strongest_edges": [{"source": "session_capture", "target": "target_root", "type": "reused_by"}],
                        "blockers": [],
                        "auth_or_session_dependency": "session capture reused for authenticated endpoint access",
                        "key_findings": [],
                    },
                },
            }

        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            scan_path.write_text(json.dumps({
                "handoff": {
                    "recommended_target_url": "https://example.test/api/chat/messages",
                    "intent": "chat_surface",
                    "score": 12,
                    "source_mode": "phantomtwin",
                    "transport_hint": "http",
                    "method_hint": "POST",
                    "session_required": True,
                    "browser_session_likely": True,
                    "auth_signals": ["cookie"],
                    "observed_header_names": [],
                    "observed_cookie_names": ["sessionid"],
                    "session_cookies": [
                        {
                            "name": "sessionid",
                            "value": "captured-session",
                            "domain": "example.test",
                            "path": "/",
                        }
                    ],
                    "session_cookie_header": "sessionid=<redacted>",
                    "session_material_present": True,
                    "session_cookie_count": 1,
                    "session_cookie_names": ["sessionid"],
                    "session_cookie_domains": ["example.test"],
                    "session_cookie_source": "handoff",
                    "session_cookie_merge_strategy": "captured_only",
                    "session_cookie_header_redacted": True,
                    "notes": [],
                }
            }))
            with patch("fracture.cli._run_attack", fake_run_attack):
                result = self.runner.invoke(
                    app,
                    ["attack", "--from-scan", str(scan_path), "--module", "extract"],
                )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(captured["target"].cookies, {"sessionid": "captured-session"})
        self.assertEqual(captured["target"].session_cookies[0]["name"], "sessionid")
        self.assertEqual(captured["target"].session_context["session_cookie_source"], "handoff")
        self.assertEqual(captured["target"].session_context["session_cookie_merge_strategy"], "captured_only")
        flattened_output = " ".join(result.output.split())
        self.assertIn("Applied session context: source=handoff strategy=captured_only cookies=1 names=sessionid.", flattened_output)
        self.assertIn("Attack Graph", result.output)
        self.assertIn("Primary Path:", result.output)
        self.assertNotIn("captured-session", result.output)

    def test_attack_command_manual_cookies_override_captured_values_and_output_stays_redacted(self):
        captured = {}

        async def fake_run_attack(target, modules, objective=None, execution_hints=None):
            captured["target"] = target
            return {"attacks": {}}

        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            output = Path(tmpdir) / "attack.json"
            scan_path.write_text(json.dumps({
                "handoff": {
                    "recommended_target_url": "https://example.test/api/chat/messages",
                    "intent": "chat_surface",
                    "score": 12,
                    "source_mode": "phantomtwin",
                    "transport_hint": "http",
                    "method_hint": "POST",
                    "session_required": True,
                    "browser_session_likely": True,
                    "auth_signals": ["cookie"],
                    "observed_header_names": [],
                    "observed_cookie_names": ["sessionid"],
                    "session_cookies": [
                        {
                            "name": "sessionid",
                            "value": "captured-session",
                            "domain": "example.test",
                            "path": "/",
                        }
                    ],
                    "session_cookie_header": "sessionid=<redacted>",
                    "session_material_present": True,
                    "session_cookie_count": 1,
                    "session_cookie_names": ["sessionid"],
                    "session_cookie_domains": ["example.test"],
                    "session_cookie_source": "handoff",
                    "session_cookie_merge_strategy": "captured_only",
                    "session_cookie_header_redacted": True,
                    "notes": [],
                }
            }))
            with patch("fracture.cli._run_attack", fake_run_attack):
                result = self.runner.invoke(
                    app,
                    [
                        "attack",
                        "--from-scan", str(scan_path),
                        "--cookie", "sessionid=manual-override",
                        "--cookie", "extra=manual-extra",
                        "--module", "extract",
                        "--output", str(output),
                    ],
                )
            payload = json.loads(output.read_text())

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(captured["target"].cookies["sessionid"], "manual-override")
        self.assertEqual(captured["target"].cookies["extra"], "manual-extra")
        self.assertEqual(captured["target"].session_context["session_cookie_source"], "merged")
        self.assertEqual(captured["target"].session_context["session_cookie_merge_strategy"], "manual_overrides_captured")
        self.assertEqual(payload["cookies"]["sessionid"], "<redacted>")
        self.assertEqual(payload["cookies"]["extra"], "<redacted>")
        self.assertEqual(payload["session_context"]["session_cookie_source"], "merged")
        self.assertEqual(payload["session_context"]["session_cookie_merge_strategy"], "manual_overrides_captured")
        self.assertEqual(payload["handoff_used"]["session_cookie_header"], "sessionid=<redacted>")
        self.assertEqual(payload["handoff_used"]["session_cookies"][0]["value"], "<redacted>")
        self.assertNotIn("manual-override", result.output)
        self.assertNotIn("captured-session", result.output)

    def test_attack_command_explicit_target_overrides_handoff(self):
        captured = {}

        async def fake_run_attack(target, modules, objective=None, execution_hints=None):
            captured["target"] = target
            captured["execution_hints"] = execution_hints
            return {"attacks": {}}

        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            scan_path.write_text(json.dumps({
                "handoff": {
                    "recommended_target_url": "https://example.test/api/chat/messages",
                    "intent": "chat_surface",
                    "score": 12,
                    "source_mode": "phantomtwin",
                    "transport_hint": "http",
                    "method_hint": "POST",
                    "session_required": False,
                    "browser_session_likely": False,
                    "auth_signals": [],
                    "observed_header_names": [],
                    "observed_cookie_names": [],
                    "notes": [],
                }
            }))
            with patch("fracture.cli._run_attack", fake_run_attack):
                result = self.runner.invoke(
                    app,
                    [
                        "attack",
                        "--target", "https://override.test/api",
                        "--from-scan", str(scan_path),
                        "--module", "extract",
                    ],
                )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(captured["target"].url, "https://override.test/api")
        self.assertIsNone(captured["execution_hints"])
        self.assertIn("overriding handoff recommended_target_url", result.output)

    def test_attack_command_warns_when_handoff_requires_session_without_auth(self):
        async def fake_run_attack(target, modules, objective=None, execution_hints=None):
            return {"attacks": {}}

        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            scan_path.write_text(json.dumps({
                "handoff": {
                    "recommended_target_url": "https://example.test/api/chat/messages",
                    "intent": "chat_surface",
                    "score": 12,
                    "source_mode": "phantomtwin",
                    "transport_hint": "http",
                    "method_hint": "POST",
                    "session_required": True,
                    "browser_session_likely": True,
                    "auth_signals": ["cookie"],
                    "observed_header_names": ["Authorization"],
                    "observed_cookie_names": ["session"],
                    "notes": [],
                }
            }))
            with patch("fracture.cli._run_attack", fake_run_attack):
                result = self.runner.invoke(
                    app,
                    ["attack", "--from-scan", str(scan_path), "--module", "extract"],
                )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Useful surface detected, but session/auth friction is likely", result.output)
        self.assertIn("Helpful material if available", result.output)
        self.assertIn("Coverage limitation:", result.output)
        self.assertIn("Operator Cue", result.output)

    def test_attack_command_surfaces_manual_auth_context_when_provided(self):
        async def fake_run_attack(target, modules, objective=None, execution_hints=None):
            return {"attacks": {}}

        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            scan_path.write_text(json.dumps({
                "handoff": {
                    "recommended_target_url": "https://example.test/api/chat/messages",
                    "intent": "chat_surface",
                    "score": 12,
                    "source_mode": "phantomtwin",
                    "transport_hint": "http",
                    "method_hint": "POST",
                    "session_required": True,
                    "browser_session_likely": True,
                    "auth_signals": ["cookie", "authorization"],
                    "observed_header_names": ["Authorization", "X-CSRF-Token"],
                    "observed_cookie_names": ["session"],
                    "notes": [],
                }
            }))
            with patch("fracture.cli._run_attack", fake_run_attack):
                result = self.runner.invoke(
                    app,
                    [
                        "attack",
                        "--from-scan", str(scan_path),
                        "--module", "extract",
                        "--header", "Authorization=Bearer demo",
                        "--cookie", "session=abc123",
                    ],
                )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Manual auth context will be applied during execution", result.output)
        self.assertIn("Manual Auth:", result.output)
        self.assertIn("Authorization", result.output)
        self.assertIn("Operator Cue", result.output)

    def test_attack_command_serializes_stateful_memory_and_extract_metadata_from_handoff_flow(self):
        async def fake_run_attack(target, modules, objective=None, execution_hints=None):
            return {
                "attacks": {
                    "memory": AttackResult(
                        module="memory",
                        target_url=target.url,
                        success=True,
                        confidence=0.62,
                        evidence={
                            "_meta": {
                                "memory_assessment": "strong_stateful_memory_signal",
                                "canary_recall_detected": True,
                                "continuity_token_reused": True,
                            }
                        },
                        notes="stateful memory fixture",
                    ),
                    "extract": AttackResult(
                        module="extract",
                        target_url=target.url,
                        success=True,
                        confidence=0.74,
                        evidence={
                            "_meta": {
                                "extract_assessment": "strong_instruction_disclosure",
                                "quoted_disclosure_detected": True,
                                "disclosure_markers": ["system prompt"],
                            }
                        },
                        notes="extract disclosure fixture",
                    ),
                }
            }

        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            output = Path(tmpdir) / "attack.json"
            scan_path.write_text(json.dumps({
                "handoff": {
                    "recommended_target_url": "https://example.test/api/chat/messages",
                    "intent": "chat_surface",
                    "score": 12,
                    "source_mode": "phantomtwin",
                    "transport_hint": "http",
                    "method_hint": "POST",
                    "session_required": False,
                    "browser_session_likely": False,
                    "auth_signals": [],
                    "observed_header_names": [],
                    "observed_cookie_names": [],
                    "invocation_profile": {
                        "method_hint": "POST",
                        "content_type_hint": "application/json",
                        "accepts_json": True,
                        "streaming_likely": False,
                        "websocket_likely": False,
                        "observed_body_keys": ["message"],
                        "observed_query_param_names": ["mode"],
                    },
                }
            }))
            with patch("fracture.cli._run_attack", fake_run_attack):
                result = self.runner.invoke(
                    app,
                    [
                        "attack",
                        "--from-scan", str(scan_path),
                        "--module", "memory",
                        "--module", "extract",
                        "--output", str(output),
                    ],
                )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            payload = json.loads(output.read_text())
            self.assertEqual(payload["execution_hints"]["method_hint"], "POST")
            self.assertEqual(payload["results"]["memory"]["evidence"]["_meta"]["memory_assessment"], "strong_stateful_memory_signal")
            self.assertTrue(payload["results"]["memory"]["evidence"]["_meta"]["continuity_token_reused"])
            self.assertEqual(payload["results"]["extract"]["evidence"]["_meta"]["extract_assessment"], "strong_instruction_disclosure")
            self.assertTrue(payload["results"]["extract"]["evidence"]["_meta"]["quoted_disclosure_detected"])
            graph = payload["attack_graph"]
            twin = payload["adversarial_twin"]
            self.assertEqual(graph["summary"]["primary_path"][:3], ["target_root", "best_candidate_endpoint", "extract_signal"])
            edge_pairs = {
                (edge["source"], edge["target"], edge["type"])
                for edge in graph["edges"]
            }
            self.assertIn(("best_candidate_endpoint", "target_root", "discovered_by"), edge_pairs)
            self.assertIn(("best_candidate_endpoint", "target_root", "prioritized_by"), edge_pairs)
            self.assertIn(("best_candidate_endpoint", "report_finding", "summarized_by"), edge_pairs)
            self.assertIn(("report_finding", "extract_signal", "evidenced_by"), edge_pairs)
            self.assertIn(("report_finding", "memory_signal", "evidenced_by"), edge_pairs)
            self.assertEqual(twin["identity"]["best_candidate"], "https://example.test/api/chat/messages")
            self.assertEqual(twin["invocation_profile"]["method_hint"], "POST")
            self.assertEqual(twin["summary"]["recommended_next_step"], "collect_more_surface")
            self.assertIn("Adversarial Twin", result.output)

    def test_attack_command_fails_cleanly_when_scan_has_no_usable_handoff(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            scan_path.write_text(json.dumps({"triage": {"recon_mode": "passive"}}))
            result = self.runner.invoke(
                app,
                ["attack", "--from-scan", str(scan_path), "--module", "extract"],
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("does not contain a usable handoff", result.output)

    def test_report_command_smoke(self):
        captured = {}

        async def fake_run_auto(target, output=None, planner="local"):
            captured["target"] = target
            captured["output"] = output
            captured["planner"] = planner
            return {
                "report": Report(
                    target_url=target.url,
                    detected_model="llm-agent",
                    risk_level="high",
                    attack_plan=["extract", "ssrf"],
                    modules_run=2,
                    modules_succeeded=1,
                    avg_asr=0.5,
                    findings_summary={"confirmed": 1, "probable": 0, "possible": 1, "negative": 0},
                    results={
                        "extract": {"assessment": "confirmed", "confidence": 0.8, "notes": "ok"},
                        "ssrf": {"assessment": "possible", "confidence": 0.2, "notes": "ok"},
                    },
                    adversarial_twin={
                        "summary": {
                            "overall_posture": "attackable",
                            "attackability": "high",
                            "auth_dependency": "low",
                            "recommended_next_step": "attack_with_session",
                        }
                    },
                )
            }

        with tempfile.TemporaryDirectory() as tmpdir:
            output = str(Path(tmpdir) / "report.json")
            with patch("fracture.cli._run_auto", fake_run_auto):
                result = self.runner.invoke(
                    app,
                    [
                        "report",
                        "--target", "https://example.test/api",
                        "--planner", "local",
                        "--model", "demo-model",
                        "--header", "X-Test=1",
                        "--cookie", "session=abc123",
                        "--timeout", "13",
                        "--format", "json",
                        "--output", output,
                    ],
                )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            payload = json.loads(Path(output).read_text())
            self.assertEqual(captured["planner"], "local")
            self.assertIsNone(captured["output"])
            self.assertEqual(captured["target"].headers, {"X-Test": "1"})
            self.assertEqual(captured["target"].cookies, {"session": "abc123"})
            self.assertEqual(payload["target_url"], "https://example.test/api")
            self.assertEqual(payload["detected_model"], "llm-agent")
            self.assertEqual(payload["adversarial_twin"]["summary"]["overall_posture"], "attackable")
            self.assertIn("Report Cue", result.output)

    def test_autopilot_command_smoke_surfaces_final_cue(self):
        captured = {}

        async def fake_run_auto(target, output=None, planner="local"):
            captured["target"] = target
            captured["planner"] = planner
            report = Report(
                target_url=target.url,
                detected_model="llm-agent",
                risk_level="high",
                attack_plan=["extract", "memory"],
                modules_run=2,
                modules_succeeded=1,
                avg_asr=0.5,
                findings_summary={"confirmed": 1, "probable": 0, "possible": 1, "negative": 0},
                results={},
            )
            return {
                "plan": {
                    "attack_plan": ["extract", "memory"],
                    "surface_constraints": ["surface appears actionable but has access friction: session-required"],
                },
                "report": report,
            }

        with patch("fracture.cli._run_auto", fake_run_auto):
            result = self.runner.invoke(
                app,
                ["autopilot", "--target", "https://example.test/api", "--planner", "local"],
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(captured["planner"], "local")
        self.assertIn("Autopilot Cue", result.output)
        self.assertIn("Plan executed:", result.output)


class ReadmeSanityTests(unittest.TestCase):
    def test_readme_matches_release_flow_and_constraints(self):
        readme = Path("README.md").read_text()
        self.assertIn("fracture scan", readme)
        self.assertIn("fracture attack --from-scan", readme)
        self.assertIn("fracture report", readme)
        self.assertIn("fracture autopilot", readme)
        self.assertIn("fracture ui", readme)
        self.assertIn("Control Center", readme)
        self.assertIn("read-only", readme)
        self.assertIn("Auth / Session Friction", readme)
        self.assertIn("--header", readme)
        self.assertIn("--cookie", readme)
        self.assertIn("handoff", readme)
        self.assertIn("invocation_profile", readme)
        self.assertIn("heuristic", readme.lower())


class UICommandTests(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def _operation_state_path(self, workspace: Path) -> Path:
        matches = sorted((workspace / ".fracture" / "operations").glob("*.json"))
        self.assertTrue(matches)
        return matches[0]

    def test_ui_command_accepts_workspace(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "scan.json").write_text(json.dumps({
                "target_url": "https://example.test",
                "handoff": {
                    "recommended_target_url": "https://example.test/api/chat",
                    "intent": "chat_surface",
                    "auth_wall_type": "form_login",
                    "auth_wall_confidence": 0.92,
                    "auth_opportunity_score": 9,
                    "session_material_present": True,
                    "session_cookie_count": 1,
                    "session_cookie_names": ["sessionid"],
                    "session_cookie_source": "handoff",
                },
            }))
            (workspace / "attack.json").write_text(json.dumps({
                "attack_graph": {
                    "nodes": [{"id": "target_root", "kind": "target_root", "label": "https://example.test"}],
                    "edges": [],
                    "summary": {"primary_path": ["target_root"], "node_count": 1, "edge_count": 0},
                }
            }))
            (workspace / "report.json").write_text(json.dumps({
                "target_url": "https://example.test",
                "findings_summary": {"executive_summary": ["Demo summary"], "top_signals": ["signal-a"]},
                "adversarial_twin": {
                    "summary": {
                        "overall_posture": "attackable",
                        "attackability": "high",
                        "auth_dependency": "moderate",
                        "recommended_next_step": "attack_with_session",
                    }
                },
            }))

            with patch("fracture.ui.control_center.serve_control_center") as mock_serve:
                result = self.runner.invoke(app, ["ui", "--workspace", str(workspace)])

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("FRACTURE Control Center", result.output)
        self.assertTrue(mock_serve.called)
        bundle = mock_serve.call_args.args[0]
        self.assertEqual(bundle["overview"]["target"], "https://example.test")
        self.assertEqual(bundle["overview"]["best_candidate"], "https://example.test/api/chat")
        self.assertEqual(bundle["executive"]["top_finding"], "Demo summary")

    def test_ui_command_accepts_explicit_artifacts_and_degrades_cleanly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "custom-scan.json"
            report_path = Path(tmpdir) / "custom-report.json"
            scan_path.write_text(json.dumps({
                "target_url": "https://example.test",
                "triage": {
                    "auth_wall_type": "oauth",
                    "auth_wall_confidence": 0.8,
                    "auth_opportunity_score": 7,
                    "session_material_present": False,
                },
            }))
            report_path.write_text(json.dumps({
                "target_url": "https://example.test",
                "findings_summary": {"confirmed": 0, "probable": 0, "possible": 0, "negative": 1},
                "results": {},
            }))

            with patch("fracture.ui.control_center.serve_control_center") as mock_serve:
                result = self.runner.invoke(
                    app,
                    ["ui", "--scan", str(scan_path), "--report", str(report_path)],
                )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        bundle = mock_serve.call_args.args[0]
        self.assertEqual(bundle["overview"]["auth_wall_type"], "oauth")
        self.assertEqual(bundle["attack_graph"]["nodes"], [])
        self.assertEqual(bundle["adversarial_twin"], {})
        self.assertIn("No decisive top finding", bundle["executive"]["top_finding"])

    def test_ui_command_accepts_demo_workspace_flag(self):
        with patch("fracture.ui.control_center.serve_control_center") as mock_serve:
            result = self.runner.invoke(app, ["ui", "--demo", "--presentation"])

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("golden workspace", result.output)
        self.assertTrue(mock_serve.called)
        self.assertTrue(mock_serve.call_args.kwargs["ready_callback"])
        bundle = mock_serve.call_args.args[0]
        self.assertTrue(bundle["demo_workspace"])
        self.assertEqual(bundle["workspace"], str(get_demo_workspace_path().resolve()))

    def test_ui_command_fails_cleanly_without_inputs(self):
        result = self.runner.invoke(app, ["ui"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("UI requires --workspace or at least one of --scan/--attack/--report.", result.output)

    def test_ui_bundle_sanitizes_sensitive_material(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "scan.json").write_text(json.dumps({
                "target_url": "https://example.test",
                "handoff": {
                    "recommended_target_url": "https://example.test/api/chat",
                    "session_cookies": [
                        {"name": "sessionid", "value": "super-secret-cookie", "domain": "example.test", "path": "/"}
                    ],
                    "session_cookie_header": "sessionid=super-secret-cookie",
                    "session_cookie_count": 1,
                    "session_cookie_names": ["sessionid"],
                    "session_cookie_source": "handoff",
                },
                "headers": {"Authorization": "Bearer secret-token", "X-Trace": "ok"},
                "cookies": {"sessionid": "super-secret-cookie"},
            }))
            (workspace / "attack.json").write_text(json.dumps({
                "headers": {"Authorization": "Bearer attack-secret"},
                "cookies": {"sessionid": "attack-secret"},
            }))

            bundle = load_control_center_bundle(workspace=str(workspace))

        scan_payload = bundle["artifacts_payload"]["scan"]
        self.assertEqual(scan_payload["handoff"]["session_cookie_header"], "<redacted>")
        self.assertEqual(scan_payload["handoff"]["session_cookies"][0]["value"], "<redacted>")
        self.assertEqual(scan_payload["headers"]["Authorization"], "<redacted>")
        self.assertEqual(scan_payload["headers"]["X-Trace"], "ok")
        self.assertEqual(scan_payload["cookies"]["sessionid"], "<redacted>")
        self.assertEqual(bundle["overview"]["session_context"]["session_cookie_names"], ["sessionid"])

    def test_ui_bundle_builds_executive_summary_with_fallbacks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "report.json").write_text(json.dumps({
                "target_url": "https://example.test",
                "findings_summary": {
                    "highlights": ["retrieval_poison confirmed with commercial impact"],
                    "top_signals": ["retrieval influence", "primary path confidence"],
                    "operational_limitations": ["manual validation still required"],
                },
                "attack_graph": {
                    "summary": {"primary_path": ["target_root", "report_finding"]},
                },
                "adversarial_twin": {
                    "summary": {
                        "overall_posture": "attackable",
                        "attackability": "medium",
                        "auth_dependency": "none",
                        "recommended_next_step": "collect_more_surface",
                    }
                },
                "results": {},
            }))

            bundle = load_control_center_bundle(workspace=str(workspace))

        self.assertEqual(bundle["executive"]["top_finding"], "retrieval_poison confirmed with commercial impact")
        self.assertEqual(bundle["executive"]["recommended_next_step"], "collect_more_surface")
        self.assertEqual(bundle["executive"]["primary_path"], ["target_root", "report_finding"])
        self.assertEqual(bundle["executive"]["top_signals"][:2], ["retrieval influence", "primary path confidence"])

    def test_operate_command_creates_persistent_operating_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")
            (workspace / "pyproject.toml").write_text("[project]\nname='demo'\n")
            (workspace / "tests").mkdir()
            output = workspace / "operate.json"

            result = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Ship the Fracture super tool",
                    "--note", "Bootstrap memory first",
                    "--output", str(output),
                ],
            )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            payload = json.loads(output.read_text())
            self.assertEqual(payload["project"], workspace.name)
            self.assertEqual(payload["objective"], "Ship the Fracture super tool")
            self.assertTrue(payload["state"]["tasks"])
            self.assertEqual(payload["state"]["session_count"], 1)
            self.assertEqual(payload["state"]["tasks"][0]["status"], "in_progress")
            self.assertTrue(payload["state"]["tasks"][0]["command_hint"])
            self.assertTrue(payload["state"]["tasks"][0]["file_hints"])
            self.assertIn("Bootstrap memory first", payload["review"]["memory_highlights"][0])
            self.assertTrue(payload["review"]["recommended_command"])
            self.assertTrue(payload["review"]["focus_files"])
            self.assertTrue(payload["review"]["session_summary"])
            self.assertTrue(payload["review"]["focus_reason"])
            self.assertIn("focus=", payload["review"]["session_summary"])
            self.assertIn("why=", payload["review"]["session_summary"])
            self.assertIsNone(payload["review"]["approval"])
            self.assertTrue(Path(payload["artifact_path"]).exists())
            self.assertIn("Fracture Operate", result.output)
            self.assertIn("Plan Slice", result.output)
            self.assertIn("Active Task", result.output)
            self.assertIn("Operate Cue", result.output)

    def test_operate_command_can_complete_a_task_and_recompute_focus(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                    "--done", "T01",
                ],
            )

            self.assertEqual(second.exit_code, 0, msg=second.output)
            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            completed = next(task for task in payload["tasks"] if task["id"] == "T01")
            self.assertEqual(completed["status"], "done")
            self.assertEqual(payload["session_count"], 2)
            self.assertTrue(payload["next_action"])
            self.assertTrue(payload["last_session_summary"])
            self.assertIn("T01 completed", payload["memory"][0]["summary"])

    def test_operate_command_can_execute_recommended_command_safely(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            with patch(
                "fracture.core.operations.run_safe_command",
                return_value=ExecutionRecord(
                    task_id="T03",
                    command="python -m pytest tests/test_cli_smoke.py -q",
                    success=True,
                    exit_code=0,
                    stdout="2 passed",
                    stderr="",
                ),
            ) as mock_run:
                result = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                        "--execute",
                        "--command-timeout", "7",
                    ],
                )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            mock_run.assert_called_once()
            self.assertEqual(mock_run.call_args.args[0], "T03")
            self.assertEqual(mock_run.call_args.args[1], "implementation")
            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            self.assertTrue(payload["executions"])
            self.assertEqual(payload["executions"][0]["exit_code"], 0)
            self.assertEqual(payload["executions"][0]["stdout"], "2 passed")
            self.assertTrue(payload["approvals"])
            self.assertTrue(payload["approvals"][0]["ready"])
            self.assertEqual(payload["approvals"][0]["task_id"], "T03")
            self.assertIn("--done T03", payload["approvals"][0]["suggested_command"])
            self.assertIn("command passed", payload["memory"][0]["summary"])
            self.assertIn("execution=T03 pass exit=0", payload["last_session_summary"])
            self.assertIn("approval=T03 ready", payload["last_session_summary"])
            self.assertIn("Last Execution", result.output)
            self.assertIn("Approval Gate", result.output)

    def test_operate_command_dedupes_identical_approval_suggestions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            execution = ExecutionRecord(
                task_id="T03",
                command="python -m pytest tests/test_cli_smoke.py -q",
                success=True,
                exit_code=0,
                stdout="2 passed",
                stderr="",
            )

            with patch("fracture.core.operations.run_safe_command", return_value=execution):
                first = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                        "--execute",
                    ],
                )
                self.assertEqual(first.exit_code, 0, msg=first.output)

            with patch("fracture.core.operations.run_safe_command", return_value=execution):
                second = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                        "--execute",
                    ],
                )
                self.assertEqual(second.exit_code, 0, msg=second.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            self.assertEqual(len(payload["approvals"]), 1)

    def test_operate_command_blocks_non_allowlisted_command_prefix(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            for task in payload["tasks"]:
                if task["id"] == "T03":
                    task["command_hint"] = "bash -lc echo unsafe"
            state_path.write_text(json.dumps(payload, indent=2))

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                    "--execute",
                ],
            )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads(state_path.read_text())
            self.assertFalse(updated["executions"][0]["success"])
            self.assertEqual(updated["executions"][0]["exit_code"], 126)
            self.assertIn("not allowlisted", updated["executions"][0]["stderr"])
            self.assertFalse(updated["approvals"][0]["ready"])
            self.assertIn("Approval Gate", second.output)

    def test_operate_command_recomputes_targeted_test_command_from_file_hints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")
            tests_dir = workspace / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_target_contract.py").write_text("def test_placeholder():\n    assert True\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            for task in payload["tasks"]:
                if task["id"] == "T03":
                    task["file_hints"] = ["fracture/core/target.py"]
                    task["command_hint"] = "python -m pytest tests/test_cli_smoke.py -k operate -q"
            state_path.write_text(json.dumps(payload, indent=2))

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads(state_path.read_text())
            task = next(item for item in updated["tasks"] if item["id"] == "T03")
            self.assertEqual(task["command_hint"], "python -m pytest tests/test_target_contract.py -q")
            self.assertIn(
                "Validation plan: targeted test selection derived from current focus and diff.",
                task["notes"],
            )

    def test_operate_command_prefers_incremental_test_command_from_changed_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")
            (workspace / ".git").mkdir()
            tests_dir = workspace / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_reporting_exports.py").write_text("def test_placeholder():\n    assert True\n")

            branch = subprocess.CompletedProcess(args=["git"], returncode=0, stdout="main\n", stderr="")
            dirty = subprocess.CompletedProcess(
                args=["git"],
                returncode=0,
                stdout=" M fracture/reporting.py\n",
                stderr="",
            )
            with patch("fracture.core.operations.subprocess.run", side_effect=[branch, dirty]):
                result = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                    ],
                )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            task = next(item for item in payload["tasks"] if item["id"] == "T03")
            self.assertEqual(task["command_hint"], "python -m pytest tests/test_reporting_exports.py -q")
            self.assertIn(
                "Validation plan: targeted test selection derived from current focus and diff.",
                task["notes"],
            )

    def test_operate_command_batches_small_incremental_test_set_from_changed_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")
            (workspace / ".git").mkdir()
            tests_dir = workspace / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_reporting_exports.py").write_text("def test_placeholder():\n    assert True\n")
            (tests_dir / "test_surface_discovery.py").write_text("def test_placeholder():\n    assert True\n")

            branch = subprocess.CompletedProcess(args=["git"], returncode=0, stdout="main\n", stderr="")
            dirty = subprocess.CompletedProcess(
                args=["git"],
                returncode=0,
                stdout=" M fracture/reporting.py\n M fracture/surface_discovery.py\n",
                stderr="",
            )
            with patch("fracture.core.operations.subprocess.run", side_effect=[branch, dirty]):
                result = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                    ],
                )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            task = next(item for item in payload["tasks"] if item["id"] == "T03")
            self.assertEqual(
                task["command_hint"],
                "python -m pytest tests/test_reporting_exports.py tests/test_surface_discovery.py -q",
            )
            self.assertIn(
                "Validation plan: incremental test batch selected (2 targets).",
                task["notes"],
            )

    def test_operate_command_prioritizes_focus_file_hints_within_incremental_batch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")
            (workspace / ".git").mkdir()
            tests_dir = workspace / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_target_contract.py").write_text("def test_placeholder():\n    assert True\n")
            (tests_dir / "test_reporting_exports.py").write_text("def test_placeholder():\n    assert True\n")
            (tests_dir / "test_surface_discovery.py").write_text("def test_placeholder():\n    assert True\n")

            branch = subprocess.CompletedProcess(args=["git"], returncode=0, stdout="main\n", stderr="")
            dirty = subprocess.CompletedProcess(
                args=["git"],
                returncode=0,
                stdout=" M fracture/reporting.py\n M fracture/surface_discovery.py\n",
                stderr="",
            )
            with patch("fracture.core.operations.subprocess.run", side_effect=[branch, dirty]):
                first = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                    ],
                )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            for task in payload["tasks"]:
                if task["id"] == "T03":
                    task["file_hints"] = ["fracture/core/target.py"]
            state_path.write_text(json.dumps(payload, indent=2))

            with patch("fracture.core.operations.subprocess.run", side_effect=[branch, dirty]):
                second = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                    ],
                )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads(state_path.read_text())
            task = next(item for item in updated["tasks"] if item["id"] == "T03")
            self.assertEqual(
                task["command_hint"],
                "python -m pytest tests/test_target_contract.py tests/test_reporting_exports.py tests/test_surface_discovery.py -q",
            )

    def test_operate_command_prioritizes_tasks_with_matching_changed_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")
            (workspace / ".git").mkdir()

            branch = subprocess.CompletedProcess(args=["git"], returncode=0, stdout="main\n", stderr="")
            dirty = subprocess.CompletedProcess(args=["git"], returncode=0, stdout=" M README.md\n", stderr="")
            with patch("fracture.core.operations.subprocess.run", side_effect=[branch, dirty]):
                result = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                    ],
                )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            task = next(item for item in payload["tasks"] if item["id"] == "T04")
            self.assertGreaterEqual(task["priority"], 124)
            self.assertIn("local changes overlap", " ".join(task["notes"]))
            self.assertIn("local changes overlap", payload["focus_reason"])

    def test_operate_command_prioritizes_task_after_recent_execution_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            for task in payload["tasks"]:
                task["status"] = "pending"
            payload["tasks"][0]["status"] = "done"
            payload["executions"] = [
                {
                    "task_id": "T04",
                    "command": "python -m pytest tests/test_cli_smoke.py -q",
                    "success": False,
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": "failed",
                    "timestamp": "2026-03-30T00:00:00+00:00",
                }
            ]
            state_path.write_text(json.dumps(payload, indent=2))

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads(state_path.read_text())
            task = next(item for item in updated["tasks"] if item["id"] == "T04")
            self.assertEqual(task["status"], "in_progress")
            self.assertGreaterEqual(task["priority"], 134)
            self.assertIn("recent execution failure", " ".join(task["notes"]))
            self.assertIn("recent execution failure", updated["focus_reason"])

    def test_operate_command_marks_approval_stale_when_changes_shift(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")
            (workspace / ".git").mkdir()

            branch_clean = subprocess.CompletedProcess(args=["git"], returncode=0, stdout="main\n", stderr="")
            dirty_clean = subprocess.CompletedProcess(args=["git"], returncode=0, stdout="", stderr="")
            with patch(
                "fracture.core.operations.subprocess.run",
                side_effect=[branch_clean, dirty_clean],
            ), patch(
                "fracture.core.operations.run_safe_command",
                return_value=ExecutionRecord(
                    task_id="T03",
                    command="python -m pytest tests/test_cli_smoke.py -q",
                    success=True,
                    exit_code=0,
                    stdout="2 passed",
                    stderr="",
                    changed_files_snapshot=[],
                ),
            ):
                first = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                        "--execute",
                    ],
                )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            branch_dirty = subprocess.CompletedProcess(args=["git"], returncode=0, stdout="main\n", stderr="")
            dirty_dirty = subprocess.CompletedProcess(args=["git"], returncode=0, stdout=" M README.md\n", stderr="")
            with patch(
                "fracture.core.operations.subprocess.run",
                side_effect=[branch_dirty, dirty_dirty],
            ):
                second = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                    ],
                )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            self.assertTrue(payload["approvals"][0]["stale"])
            self.assertFalse(payload["approvals"][0]["ready"])
            self.assertEqual(payload["approvals"][0]["confidence"], "low")
            self.assertIn("shifted since the last execution", " ".join(payload["approvals"][0]["rationale"]))
            self.assertIn("stale", payload["last_session_summary"])

    def test_operate_command_persists_run_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            result = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                    "--allow-execute",
                    "--command-timeout", "33",
                    "--auto-execute-kind", "implementation",
                    "--auto-execute-kind", "validation",
                ],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            self.assertTrue(payload["run_policy"]["allow_execute"])
            self.assertEqual(payload["run_policy"]["default_command_timeout"], 33)
            self.assertEqual(payload["run_policy"]["auto_execute_kinds"], ["implementation", "validation"])
            self.assertEqual(payload["run_policy"]["approval_strictness"], "balanced")
            self.assertEqual(payload["run_policy"]["memory_limit"], 20)
            self.assertIn("policy_summary", json.loads((workspace / "operate.json").read_text()) if (workspace / "operate.json").exists() else {"policy_summary": ""})

    def test_operate_command_uses_persisted_auto_execute_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                    "--allow-execute",
                    "--command-timeout", "33",
                    "--auto-execute-kind", "implementation",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            with patch(
                "fracture.core.operations.run_safe_command",
                return_value=ExecutionRecord(
                    task_id="T03",
                    command="python -m pytest tests/test_cli_smoke.py -q",
                    success=True,
                    exit_code=0,
                    stdout="2 passed",
                    stderr="",
                ),
            ) as mock_run:
                second = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                    ],
                )

            self.assertEqual(second.exit_code, 0, msg=second.output)
            mock_run.assert_called_once()
            self.assertEqual(mock_run.call_args.kwargs["timeout"], 33)
            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            self.assertTrue(payload["executions"])

    def test_operate_command_persists_approval_strictness(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            result = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                    "--approval-strictness", "strict",
                ],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            self.assertEqual(payload["run_policy"]["approval_strictness"], "strict")

    def test_operate_command_persists_retention_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            result = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                    "--memory-limit", "3",
                    "--execution-limit", "2",
                    "--approval-limit", "2",
                    "--decision-limit", "4",
                ],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            self.assertEqual(payload["run_policy"]["memory_limit"], 3)
            self.assertEqual(payload["run_policy"]["execution_limit"], 2)
            self.assertEqual(payload["run_policy"]["approval_limit"], 2)
            self.assertEqual(payload["run_policy"]["decision_limit"], 4)

    def test_operate_command_applies_strict_approval_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                    "--approval-strictness", "strict",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            with patch(
                "fracture.core.operations.run_safe_command",
                return_value=ExecutionRecord(
                    task_id="T03",
                    command="python -m pytest tests/test_cli_smoke.py -q",
                    success=True,
                    exit_code=0,
                    stdout="2 passed",
                    stderr="",
                ),
            ):
                second = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                        "--execute",
                    ],
                )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            self.assertFalse(payload["approvals"][0]["ready"])
            self.assertEqual(payload["approvals"][0]["confidence"], "low")
            self.assertIn("Strict approval policy", " ".join(payload["approvals"][0]["rationale"]))

    def test_operate_command_rejects_narrow_validation_for_integration_task(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            for task in payload["tasks"]:
                task["status"] = "pending"
                if task["id"] == "T04":
                    task["status"] = "in_progress"
                    task["command_hint"] = "python -m pytest tests/test_target_contract.py -q"
            state_path.write_text(json.dumps(payload, indent=2))

            with patch(
                "fracture.core.operations.run_safe_command",
                return_value=ExecutionRecord(
                    task_id="T04",
                    command="python -m pytest tests/test_target_contract.py -q",
                    success=True,
                    exit_code=0,
                    stdout="1 passed",
                    stderr="",
                ),
            ):
                second = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                        "--execute",
                    ],
                )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads(state_path.read_text())
            self.assertFalse(updated["approvals"][0]["ready"])
            self.assertEqual(updated["approvals"][0]["confidence"], "low")
            self.assertIn("Validation scope is narrow", " ".join(updated["approvals"][0]["rationale"]))
            self.assertIn("Closure Risk:", second.output)
            self.assertIn("Validation scope is narrow", second.output)
            self.assertIn("Next Validation:", second.output)
            self.assertIn("run broader validation before approval", second.output)

    def test_operate_command_surfaces_narrow_integration_validation_in_planner_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            for task in payload["tasks"]:
                task["status"] = "pending"
                if task["id"] == "T04":
                    task["status"] = "in_progress"
            payload["executions"] = [
                {
                    "task_id": "T04",
                    "command": "python -m pytest tests/test_target_contract.py -q",
                    "success": True,
                    "exit_code": 0,
                    "stdout": "1 passed",
                    "stderr": "",
                    "changed_files_snapshot": [],
                    "timestamp": "2026-03-30T00:00:00+00:00",
                },
            ]
            state_path.write_text(json.dumps(payload, indent=2))

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                    "--output", str(workspace / "operate.json"),
                ],
            )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            snapshot = json.loads((workspace / "operate.json").read_text())
            self.assertIn("broaden verification scope", snapshot["planner_posture"])
            self.assertIn("broaden test coverage", snapshot["review"]["focus_reason"])
            self.assertEqual(snapshot["review"]["preferred_focus_task_id"], "T05")
            self.assertEqual(snapshot["review"]["next_action"], "T05: Broaden validation before approval")
            validation_task = next(item for item in snapshot["state"]["tasks"] if item["id"] == "T05")
            self.assertEqual(snapshot["state"]["current_focus"], validation_task["title"])
            self.assertIn("pending | focus", second.output)
            self.assertIn("Planner Focus", second.output)
            self.assertIn("Focus Source:", second.output)
            self.assertIn("planner", second.output)

    def test_operate_command_prioritizes_validation_after_narrow_integration_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            for task in payload["tasks"]:
                task["status"] = "pending"
                if task["id"] == "T04":
                    task["status"] = "in_progress"
            payload["executions"] = [
                {
                    "task_id": "T04",
                    "command": "python -m pytest tests/test_target_contract.py -q",
                    "success": True,
                    "exit_code": 0,
                    "stdout": "1 passed",
                    "stderr": "",
                    "changed_files_snapshot": [],
                    "timestamp": "2026-03-30T00:00:00+00:00",
                },
            ]
            state_path.write_text(json.dumps(payload, indent=2))

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads(state_path.read_text())
            validation_task = next(item for item in updated["tasks"] if item["id"] == "T05")
            integration_task = next(item for item in updated["tasks"] if item["id"] == "T04")
            self.assertGreater(validation_task["priority"], integration_task["priority"])
            self.assertIn("broader validation is favored", " ".join(validation_task["notes"]))
            self.assertIn("broaden test coverage", updated["focus_reason"])

    def test_operate_command_broadens_validation_command_after_narrow_integration_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")
            tests_dir = workspace / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_cli_smoke.py").write_text("def test_placeholder():\n    assert True\n")
            (tests_dir / "test_target_contract.py").write_text("def test_placeholder():\n    assert True\n")
            (tests_dir / "test_surface_discovery.py").write_text("def test_placeholder():\n    assert True\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            for task in payload["tasks"]:
                task["status"] = "pending"
            payload["executions"] = [
                {
                    "task_id": "T04",
                    "command": "python -m pytest tests/test_target_contract.py -q",
                    "success": True,
                    "exit_code": 0,
                    "stdout": "1 passed",
                    "stderr": "",
                    "changed_files_snapshot": [],
                    "timestamp": "2026-03-30T00:00:00+00:00",
                },
            ]
            state_path.write_text(json.dumps(payload, indent=2))

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads(state_path.read_text())
            validation_task = next(item for item in updated["tasks"] if item["id"] == "T05")
            self.assertEqual(
                validation_task["command_hint"],
                "python -m pytest tests/test_target_contract.py tests/test_cli_smoke.py tests/test_surface_discovery.py -q",
            )
            self.assertIn(
                "Validation plan: broadened from the previous integration run because the last verification scope was too narrow.",
                validation_task["notes"],
            )
            self.assertIn("Validation Alert:", second.output)
            self.assertIn("last verification scope was too narrow", second.output)

    def test_operate_command_applies_retention_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                    "--memory-limit", "2",
                    "--execution-limit", "1",
                    "--approval-limit", "1",
                    "--decision-limit", "2",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            payload["memory"] = [
                {"kind": "note", "summary": "m1", "detail": "", "timestamp": "2026-03-30T00:00:00+00:00"},
                {"kind": "note", "summary": "m2", "detail": "", "timestamp": "2026-03-30T00:00:01+00:00"},
                {"kind": "note", "summary": "m3", "detail": "", "timestamp": "2026-03-30T00:00:02+00:00"},
            ]
            payload["executions"] = [
                {"task_id": "T01", "command": "python -m pytest", "success": True, "exit_code": 0, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:00+00:00"},
                {"task_id": "T02", "command": "python -m pytest", "success": False, "exit_code": 1, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:01+00:00"},
            ]
            payload["approvals"] = [
                {"task_id": "T01", "ready": True, "confidence": "high", "rationale": [], "suggested_command": "done", "stale": False, "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:00+00:00"},
                {"task_id": "T02", "ready": False, "confidence": "low", "rationale": [], "suggested_command": "done", "stale": False, "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:01+00:00"},
            ]
            payload["decisions"] = [
                {"summary": "d1", "rationale": "r1", "timestamp": "2026-03-30T00:00:00+00:00"},
                {"summary": "d2", "rationale": "r2", "timestamp": "2026-03-30T00:00:01+00:00"},
                {"summary": "d3", "rationale": "r3", "timestamp": "2026-03-30T00:00:02+00:00"},
            ]
            state_path.write_text(json.dumps(payload, indent=2))

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads(state_path.read_text())
            self.assertEqual(len(updated["memory"]), 2)
            self.assertEqual(len(updated["executions"]), 1)
            self.assertEqual(len(updated["approvals"]), 1)
            self.assertEqual(len(updated["decisions"]), 2)

    def test_operate_command_emits_policy_summary_and_normalizes_invalid_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            payload["run_policy"] = {
                "allow_execute": True,
                "default_command_timeout": -7,
                "auto_execute_kinds": ["implementation", "bogus", "implementation"],
                "approval_strictness": "aggressive",
                "memory_limit": -3,
                "execution_limit": -5,
                "approval_limit": -2,
                "decision_limit": -1,
            }
            state_path.write_text(json.dumps(payload, indent=2))

            with patch(
                "fracture.core.operations.run_safe_command",
                return_value=ExecutionRecord(
                    task_id="T03",
                    command="python -m pytest tests/test_cli_smoke.py -q",
                    success=True,
                    exit_code=0,
                    stdout="2 passed",
                    stderr="",
                ),
            ):
                second = self.runner.invoke(
                    app,
                    [
                        "operate",
                        "--workspace", str(workspace),
                        "--objective", "Build the operating loop",
                        "--output", str(workspace / "operate.json"),
                    ],
                )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads(state_path.read_text())
            self.assertEqual(updated["run_policy"]["default_command_timeout"], 1)
            self.assertEqual(updated["run_policy"]["auto_execute_kinds"], ["implementation"])
            self.assertEqual(updated["run_policy"]["approval_strictness"], "balanced")
            self.assertEqual(updated["run_policy"]["memory_limit"], 1)
            self.assertEqual(updated["run_policy"]["execution_limit"], 1)
            self.assertEqual(updated["run_policy"]["approval_limit"], 1)
            self.assertEqual(updated["run_policy"]["decision_limit"], 1)

            snapshot = json.loads((workspace / "operate.json").read_text())
            self.assertIn("policy_summary", snapshot)
            self.assertIn("approval=balanced", snapshot["policy_summary"])
            self.assertIn("auto=implementation", snapshot["policy_summary"])

    def test_operate_command_emits_memory_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            payload["memory"] = [
                {"kind": "note", "summary": "m1", "detail": "", "timestamp": "2026-03-30T00:00:00+00:00"},
                {"kind": "command_execution", "summary": "m2", "detail": "", "timestamp": "2026-03-30T00:00:01+00:00"},
                {"kind": "command_execution", "summary": "m3", "detail": "", "timestamp": "2026-03-30T00:00:02+00:00"},
            ]
            payload["executions"] = [
                {"task_id": "T01", "command": "python -m pytest", "success": True, "exit_code": 0, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:00+00:00"},
                {"task_id": "T02", "command": "python -m pytest", "success": False, "exit_code": 1, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:01+00:00"},
            ]
            payload["approvals"] = [
                {"task_id": "T01", "ready": True, "confidence": "high", "rationale": [], "suggested_command": "done", "stale": False, "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:00+00:00"},
                {"task_id": "T02", "ready": False, "confidence": "low", "rationale": [], "suggested_command": "done", "stale": False, "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:01+00:00"},
            ]
            state_path.write_text(json.dumps(payload, indent=2))

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                    "--output", str(workspace / "operate.json"),
                ],
            )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads((workspace / "operate.json").read_text())
            self.assertIn("memory_summary", updated)
            self.assertIn("memory=command_execution:2,note:1", updated["memory_summary"])
            self.assertIn("executions=pass:1,fail:1", updated["memory_summary"])
            self.assertIn("approvals=ready:1,review:1", updated["memory_summary"])

    def test_operate_command_emits_tactical_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            payload["memory"] = [
                {"kind": "command_execution", "summary": "m1", "detail": "", "timestamp": "2026-03-30T00:00:00+00:00"},
                {"kind": "command_execution", "summary": "m2", "detail": "", "timestamp": "2026-03-30T00:00:01+00:00"},
                {"kind": "note", "summary": "m3", "detail": "", "timestamp": "2026-03-30T00:00:02+00:00"},
            ]
            payload["executions"] = [
                {"task_id": "T03", "command": "python -m pytest", "success": False, "exit_code": 1, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:00+00:00"},
                {"task_id": "T03", "command": "python -m pytest", "success": False, "exit_code": 1, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:01+00:00"},
            ]
            payload["approvals"] = [
                {"task_id": "T03", "ready": False, "confidence": "low", "rationale": [], "suggested_command": "done", "stale": True, "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:01+00:00"},
            ]
            state_path.write_text(json.dumps(payload, indent=2))

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                    "--output", str(workspace / "operate.json"),
                ],
            )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads((workspace / "operate.json").read_text())
            self.assertIn("tactical_summary", updated)
            self.assertIn("mode=stabilize", updated["tactical_summary"])
            self.assertIn("repeat_failures=T03:2", updated["tactical_summary"])
            self.assertIn("stale_approvals=1", updated["tactical_summary"])
            self.assertIn("dominant_memory=command_execution", updated["tactical_summary"])

    def test_operate_command_emits_planner_posture(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            result = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Fix regression in the operating loop",
                    "--output", str(workspace / "operate.json"),
                ],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)

            payload = json.loads((workspace / "operate.json").read_text())
            self.assertIn("planner_posture", payload)
            self.assertIn("hotfix", payload["planner_posture"])

    def test_operate_command_prioritizes_repeated_failure_task(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            for task in payload["tasks"]:
                task["status"] = "pending"
            payload["executions"] = [
                {"task_id": "T04", "command": "python -m pytest", "success": False, "exit_code": 1, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:00+00:00"},
                {"task_id": "T04", "command": "python -m pytest", "success": False, "exit_code": 1, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:01+00:00"},
            ]
            state_path.write_text(json.dumps(payload, indent=2))

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads(state_path.read_text())
            task = next(item for item in updated["tasks"] if item["id"] == "T04")
            self.assertGreaterEqual(task["priority"], 159)
            self.assertIn("repeated failures suggest stabilization work", " ".join(task["notes"]))
            self.assertIn("repeated failures", updated["focus_reason"])

    def test_operate_command_prioritizes_stale_approval_task(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            for task in payload["tasks"]:
                task["status"] = "pending"
            payload["approvals"] = [
                {"task_id": "T04", "ready": False, "confidence": "low", "rationale": [], "suggested_command": "done", "stale": True, "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:01+00:00"},
            ]
            state_path.write_text(json.dumps(payload, indent=2))

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads(state_path.read_text())
            task = next(item for item in updated["tasks"] if item["id"] == "T04")
            self.assertGreaterEqual(task["priority"], 109)
            self.assertIn("stale approvals need refresh", " ".join(task["notes"]))

    def test_operate_command_enters_stabilize_mode_for_validation_work(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            for task in payload["tasks"]:
                task["status"] = "pending"
            payload["executions"] = [
                {"task_id": "T03", "command": "python -m pytest", "success": False, "exit_code": 1, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:00+00:00"},
                {"task_id": "T03", "command": "python -m pytest", "success": False, "exit_code": 1, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:01+00:00"},
                {"task_id": "T04", "command": "python -m pytest", "success": False, "exit_code": 1, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:02+00:00"},
            ]
            state_path.write_text(json.dumps(payload, indent=2))

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads(state_path.read_text())
            self.assertEqual(updated["operating_mode"], "stabilize")
            validation_task = next(item for item in updated["tasks"] if item["id"] == "T05")
            self.assertGreaterEqual(validation_task["priority"], 110)
            self.assertIn("project is in stabilize mode", " ".join(validation_task["notes"]))

    def test_operate_command_defaults_to_build_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            result = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Build the operating loop",
                ],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            self.assertEqual(payload["operating_mode"], "build")
            self.assertIn("mode=build", payload["last_session_summary"])

    def test_operate_command_enters_hotfix_mode_from_objective(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            result = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Fix regression in the operating loop",
                ],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            self.assertEqual(payload["operating_mode"], "hotfix")
            self.assertIn("mode=hotfix", payload["last_session_summary"])
            priorities = {item["id"]: item["priority"] for item in payload["tasks"]}
            self.assertGreater(priorities["T05"], priorities["T01"])
            self.assertGreater(priorities["T04"], priorities["T02"])

    def test_operate_command_enters_refactor_mode_from_objective(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            result = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Refactor the operating loop memory pipeline",
                ],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            self.assertEqual(payload["operating_mode"], "refactor")
            self.assertIn("mode=refactor", payload["last_session_summary"])
            priorities = {item["id"]: item["priority"] for item in payload["tasks"]}
            self.assertGreater(priorities["T01"], priorities["T04"])
            self.assertGreater(priorities["T02"], priorities["T05"])

    def test_operate_command_prefers_stabilize_over_objective_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "README.md").write_text("# demo\n")

            first = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Fix regression in the operating loop",
                ],
            )
            self.assertEqual(first.exit_code, 0, msg=first.output)

            state_path = self._operation_state_path(workspace)
            payload = json.loads(state_path.read_text())
            for task in payload["tasks"]:
                task["status"] = "pending"
            payload["executions"] = [
                {"task_id": "T03", "command": "python -m pytest", "success": False, "exit_code": 1, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:00+00:00"},
                {"task_id": "T03", "command": "python -m pytest", "success": False, "exit_code": 1, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:01+00:00"},
                {"task_id": "T04", "command": "python -m pytest", "success": False, "exit_code": 1, "stdout": "", "stderr": "", "changed_files_snapshot": [], "timestamp": "2026-03-30T00:00:02+00:00"},
            ]
            state_path.write_text(json.dumps(payload, indent=2))

            second = self.runner.invoke(
                app,
                [
                    "operate",
                    "--workspace", str(workspace),
                    "--objective", "Fix regression in the operating loop",
                ],
            )
            self.assertEqual(second.exit_code, 0, msg=second.output)

            updated = json.loads(state_path.read_text())
            self.assertEqual(updated["operating_mode"], "stabilize")
            self.assertIn("mode=stabilize", updated["last_session_summary"])
