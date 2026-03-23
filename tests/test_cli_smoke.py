import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from fracture.agents.report import Report
from fracture.cli import app
from fracture.core.result import AttackResult


class CLISmokeTests(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

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
            self.assertIn("session", " ".join(payload["triage"]["observed_auth_signal_names"]).lower())
            self.assertTrue(payload["triage"]["operational_limitations"])
            self.assertEqual(payload["header_names"], ["X-Test"])
            self.assertEqual(payload["cookie_names"], ["session"])
            self.assertEqual(payload["handoff"]["recommended_target_url"], "https://example.test/api/chat/messages")
            self.assertEqual(payload["handoff"]["observed_header_names"], ["Authorization"])
            self.assertEqual(payload["handoff"]["observed_cookie_names"], ["session"])
            self.assertEqual(payload["handoff"]["invocation_profile"]["method_hint"], "POST")
            self.assertEqual(payload["handoff"]["invocation_profile"]["observed_body_keys"], ["message", "messages"])
            self.assertEqual(payload["triage"]["top_candidates"][0]["url"], "https://example.test/api/chat/messages")
            self.assertIn("Top Candidates:", result.output)
            self.assertIn("Score Detail:", result.output)
            self.assertIn("Invocation:", result.output)
            self.assertIn("Planning Signals:", result.output)
            self.assertIn("Constraints:", result.output)
            self.assertIn("Priority Why:", result.output)
            self.assertIn("Session/Auth Constraint:", result.output)
            self.assertIn("Manual Auth Context:", result.output)
            self.assertIn("Coverage Limitation:", result.output)
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
        self.assertIn("Auth / Session Friction", readme)
        self.assertIn("--header", readme)
        self.assertIn("--cookie", readme)
        self.assertIn("handoff", readme)
        self.assertIn("invocation_profile", readme)
        self.assertIn("heuristic", readme.lower())
