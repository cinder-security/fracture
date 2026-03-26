import asyncio
import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from zipfile import ZipFile

from rich.console import Console

from fracture.agents.report import Report, ReportAgent
from fracture.agents.strategy import StrategyAgent
from fracture.core.orchestrator import Orchestrator
from fracture.core.result import AttackResult
from fracture.core.target import AITarget
from fracture.reporting.docx_export import export_report_docx
from fracture.reporting.pdf_export import export_report_pdf


async def _fast_sleep(*args, **kwargs):
    return None


class ReportAgentTests(unittest.TestCase):
    def test_report_agent_builds_assessments_and_summary(self):
        target = AITarget(url="https://example.test")
        agent = ReportAgent(target)

        attack_results = {
            "hpm": AttackResult(
                module="hpm",
                target_url=target.url,
                success=True,
                confidence=0.81,
                evidence={"_meta": {"best_classification": "likely_leak"}},
                notes="HPM complete",
            ),
            "retrieval_poison": AttackResult(
                module="retrieval_poison",
                target_url=target.url,
                success=False,
                confidence=0.38,
                evidence={"_meta": {"best_classification": "possible_retrieval_influence"}},
                notes="Retrieval poison evaluation complete",
            ),
            "ssrf": AttackResult(
                module="ssrf",
                target_url=target.url,
                success=False,
                confidence=0.0,
                evidence={"_meta": {"best_classification": "no_fetch_behavior"}},
                notes="SSRF evaluation complete",
            ),
        }

        report = asyncio.run(
            agent.run(
                plan={"detected_model": "llm-agent", "risk_level": "high"},
                attack_results=attack_results,
            )
        )

        self.assertEqual(report.findings_summary["confirmed"], 1)
        self.assertEqual(report.findings_summary["probable"], 1)
        self.assertEqual(report.findings_summary["negative"], 1)
        self.assertEqual(report.results["hpm"]["assessment"], "confirmed")
        self.assertEqual(report.results["retrieval_poison"]["assessment"], "probable")

    def test_report_agent_softens_success_without_strong_signal(self):
        target = AITarget(url="https://example.test")
        agent = ReportAgent(target)

        attack_results = {
            "memory": AttackResult(
                module="memory",
                target_url=target.url,
                success=True,
                confidence=0.41,
                evidence={"_meta": {}},
                notes="Heuristic hit only",
            ),
        }

        report = asyncio.run(
            agent.run(
                plan={"detected_model": "unknown", "risk_level": "medium"},
                attack_results=attack_results,
            )
        )

        self.assertEqual(report.results["memory"]["assessment"], "probable")
        self.assertEqual(report.findings_summary["probable"], 1)

    def test_report_agent_integrates_memory_stateful_signal(self):
        target = AITarget(url="https://example.test")
        agent = ReportAgent(target)

        attack_results = {
            "memory": AttackResult(
                module="memory",
                target_url=target.url,
                success=True,
                confidence=0.2,
                evidence={
                    "_meta": {
                        "memory_assessment": "strong_stateful_memory_signal",
                        "canary_recall_detected": True,
                        "canary_recall_mode": "exact",
                        "continuity_token_reused": True,
                        "stateful_evidence_present": True,
                        "confidence_rationale": "Exact canary recall occurred after a stateful sequence with continuity evidence.",
                    }
                },
                notes="Memory evaluation complete",
            ),
        }

        report = asyncio.run(agent.run(attack_results=attack_results))
        memory = report.results["memory"]
        self.assertEqual(memory["assessment"], "probable")
        self.assertEqual(memory["module_assessment"], "strong_stateful_memory_signal")
        self.assertIn("canary recall exact", memory["key_signals"])
        self.assertIn("continuity token reused", memory["key_signals"])
        self.assertIn("memory_assessment=strong_stateful_memory_signal", memory["assessment_basis"])
        self.assertIn("memory:", " ".join(report.findings_summary["highlights"]).lower())
        self.assertTrue(report.findings_summary["executive_summary"])
        self.assertIn("continuity token reused", " ".join(report.findings_summary["executive_summary"]).lower())
        self.assertIn("canary recall exact", report.findings_summary["top_signals"])

    def test_report_agent_integrates_extract_disclosure_signal(self):
        target = AITarget(url="https://example.test")
        agent = ReportAgent(target)

        attack_results = {
            "extract": AttackResult(
                module="extract",
                target_url=target.url,
                success=True,
                confidence=0.72,
                evidence={
                    "_meta": {
                        "extract_assessment": "strong_instruction_disclosure",
                        "quoted_disclosure_detected": True,
                        "disclosure_markers": ["system prompt", "developer instructions"],
                        "confidence_rationale": "The response disclosed internal/system guidance with instruction-like content.",
                    }
                },
                notes="Extract evaluation complete",
            ),
            "refusal_case": AttackResult(
                module="extract",
                target_url=target.url,
                success=False,
                confidence=0.0,
                evidence={"_meta": {"extract_assessment": "no_disclosure_signal"}},
                notes="Refusal path",
            ),
        }

        report = asyncio.run(agent.run(attack_results=attack_results))
        extract = report.results["extract"]
        refusal = report.results["refusal_case"]
        self.assertEqual(extract["assessment"], "confirmed")
        self.assertEqual(extract["module_assessment"], "strong_instruction_disclosure")
        self.assertIn("quoted disclosure detected", extract["key_signals"])
        self.assertIn("extract_assessment=strong_instruction_disclosure", extract["assessment_basis"])
        self.assertEqual(refusal["assessment"], "negative")

    def test_report_agent_builds_attack_graph_from_auth_and_module_signals(self):
        target = AITarget(url="https://example.test")
        agent = ReportAgent(target)

        fingerprint = AttackResult(
            module="fingerprint",
            target_url=target.url,
            success=True,
            confidence=0.9,
            evidence={
                "surface_discovery": {
                    "details": {
                        "best_candidate": "https://example.test/api/chat/messages",
                        "best_candidate_intent": "chat_surface",
                        "best_candidate_score": 14,
                        "auth_wall_type": "form_login",
                        "auth_wall_confidence": 0.95,
                        "manual_login_recommended": True,
                        "session_capture_readiness": "high",
                        "auth_opportunity_score": 9,
                        "handoff": {
                            "recommended_target_url": "https://example.test/api/chat/messages",
                            "intent": "chat_surface",
                            "score": 14,
                            "source_mode": "phantomtwin",
                            "method_hint": "POST",
                            "auth_wall_type": "form_login",
                            "auth_wall_confidence": 0.95,
                            "manual_login_recommended": True,
                            "session_capture_readiness": "high",
                            "auth_opportunity_score": 9,
                            "session_material_present": True,
                            "session_cookie_count": 1,
                            "session_cookie_names": ["sessionid"],
                            "session_cookie_source": "handoff",
                            "session_cookie_merge_strategy": "captured_only",
                            "invocation_profile": {
                                "method_hint": "POST",
                                "observed_body_keys": ["message"],
                            },
                        },
                    }
                }
            },
        )
        attack_results = {
            "extract": AttackResult(
                module="extract",
                target_url=target.url,
                success=True,
                confidence=0.72,
                evidence={"_meta": {"extract_assessment": "strong_instruction_disclosure", "quoted_disclosure_detected": True}},
                notes="Extract evaluation complete",
            ),
            "memory": AttackResult(
                module="memory",
                target_url=target.url,
                success=True,
                confidence=0.44,
                evidence={"_meta": {"memory_assessment": "canary_recall_signal", "canary_recall_detected": True}},
                notes="Memory evaluation complete",
            ),
        }

        report = asyncio.run(
            agent.run(
                fingerprint=fingerprint,
                plan={
                    "detected_model": "llm-agent",
                    "risk_level": "high",
                    "surface_constraints": ["session-required protected endpoint"],
                    "operational_limitations": ["coverage depends on valid session context"],
                },
                attack_results=attack_results,
            )
        )

        graph = report.attack_graph
        node_ids = {node["id"] for node in graph["nodes"]}
        node_kinds = {node["kind"] for node in graph["nodes"]}
        edge_pairs = {
            (edge["source"], edge["target"], edge["type"])
            for edge in graph["edges"]
        }
        self.assertIn("auth_wall", node_ids)
        self.assertIn("session_capture", node_ids)
        self.assertIn("best_candidate_endpoint", node_ids)
        self.assertIn("extract_signal", node_ids)
        self.assertIn("memory_signal", node_ids)
        self.assertIn("report_finding", node_ids)
        self.assertEqual(
            node_kinds,
            {
                "target_root",
                "auth_wall",
                "session_capture",
                "best_candidate_endpoint",
                "extract_signal",
                "memory_signal",
                "coverage_constraint",
                "report_finding",
            },
        )
        self.assertIn(("auth_wall", "target_root", "discovered_by"), edge_pairs)
        self.assertIn(("best_candidate_endpoint", "target_root", "discovered_by"), edge_pairs)
        self.assertIn(("best_candidate_endpoint", "auth_wall", "protected_by"), edge_pairs)
        self.assertIn(("auth_wall", "session_capture", "unlocked_by"), edge_pairs)
        self.assertIn(("best_candidate_endpoint", "session_capture", "unlocked_by"), edge_pairs)
        self.assertIn(("extract_signal", "session_capture", "reused_by"), edge_pairs)
        self.assertIn(("memory_signal", "session_capture", "reused_by"), edge_pairs)
        self.assertIn(("best_candidate_endpoint", "coverage_constraint", "constrained_by"), edge_pairs)
        self.assertIn(("report_finding", "extract_signal", "evidenced_by"), edge_pairs)
        self.assertIn(("report_finding", "memory_signal", "evidenced_by"), edge_pairs)
        self.assertIn(("best_candidate_endpoint", "report_finding", "summarized_by"), edge_pairs)
        self.assertTrue(graph["summary"]["primary_path"])
        self.assertTrue(graph["summary"]["blockers"])
        self.assertIn("session", graph["summary"]["auth_or_session_dependency"])
        self.assertNotIn("handoff", node_ids)

    def test_report_agent_builds_adversarial_twin_from_auth_graph_and_signals(self):
        target = AITarget(url="https://example.test")
        agent = ReportAgent(target)

        fingerprint = AttackResult(
            module="fingerprint",
            target_url=target.url,
            success=True,
            confidence=0.92,
            evidence={
                "surface_discovery": {
                    "details": {
                        "best_candidate": "https://example.test/api/chat/messages",
                        "best_candidate_intent": "chat_surface",
                        "best_candidate_score": 14,
                        "auth_wall_type": "form_login",
                        "auth_wall_confidence": 0.95,
                        "manual_login_recommended": True,
                        "session_capture_readiness": "high",
                        "auth_opportunity_score": 9,
                        "auth_wall_rationale": "Protected conversational surface is gated by a real login wall.",
                        "top_candidates": [
                            {
                                "url": "https://example.test/api/chat/messages",
                                "intent": "chat_surface",
                                "score": 14,
                                "reasons": ["frontend fetch", "post-login path"],
                            }
                        ],
                        "handoff": {
                            "recommended_target_url": "https://example.test/api/chat/messages",
                            "intent": "chat_surface",
                            "score": 14,
                            "source_mode": "phantomtwin",
                            "method_hint": "POST",
                            "auth_wall_type": "form_login",
                            "auth_wall_confidence": 0.95,
                            "manual_login_recommended": True,
                            "session_capture_readiness": "high",
                            "auth_opportunity_score": 9,
                            "auth_wall_rationale": "Protected conversational surface is gated by a real login wall.",
                            "session_material_present": True,
                            "session_cookie_count": 1,
                            "session_cookie_names": ["sessionid"],
                            "session_cookie_source": "handoff",
                            "session_cookie_merge_strategy": "captured_only",
                            "invocation_profile": {
                                "method_hint": "POST",
                                "content_type_hint": "application/json",
                                "accepts_json": True,
                                "streaming_likely": False,
                                "websocket_likely": False,
                                "observed_body_keys": ["message", "messages"],
                                "observed_query_param_names": ["mode"],
                            },
                        },
                    }
                }
            },
        )
        attack_results = {
            "extract": AttackResult(
                module="extract",
                target_url=target.url,
                success=True,
                confidence=0.72,
                evidence={
                    "_meta": {
                        "extract_assessment": "strong_instruction_disclosure",
                        "quoted_disclosure_detected": True,
                        "disclosure_signal_strength": "high",
                        "disclosure_markers": ["system prompt"],
                    }
                },
                notes="Extract evaluation complete",
            ),
            "memory": AttackResult(
                module="memory",
                target_url=target.url,
                success=True,
                confidence=0.44,
                evidence={
                    "_meta": {
                        "memory_assessment": "canary_recall_signal",
                        "canary_recall_detected": True,
                        "recall_signal_strength": "moderate",
                    }
                },
                notes="Memory evaluation complete",
            ),
        }

        report = asyncio.run(
            agent.run(
                fingerprint=fingerprint,
                plan={
                    "detected_model": "llm-agent",
                    "risk_level": "high",
                    "surface_constraints": ["session-required protected endpoint"],
                    "operational_limitations": ["coverage depends on valid session context"],
                    "planning_signals_used": ["best_candidate_intent=chat_surface", "best_candidate_score=14"],
                },
                attack_results=attack_results,
            )
        )

        twin = report.adversarial_twin
        self.assertEqual(twin["identity"]["best_candidate"], "https://example.test/api/chat/messages")
        self.assertEqual(twin["auth_profile"]["auth_wall_type"], "form_login")
        self.assertEqual(twin["session_profile"]["session_cookie_names"], ["sessionid"])
        self.assertNotIn("session_cookies", json.dumps(twin))
        self.assertEqual(twin["invocation_profile"]["method_hint"], "POST")
        self.assertEqual(twin["surface_model"]["primary_surface_type"], "chat_surface")
        self.assertEqual(twin["offensive_signals"]["extract_assessment"], "strong_instruction_disclosure")
        self.assertEqual(twin["offensive_signals"]["memory_assessment"], "canary_recall_signal")
        self.assertTrue(twin["graph_linkage"]["primary_path"])
        self.assertTrue(twin["graph_linkage"]["blockers"])
        self.assertEqual(twin["summary"]["overall_posture"], "attackable")
        self.assertEqual(twin["summary"]["attackability"], "high")
        self.assertEqual(twin["summary"]["auth_dependency"], "medium")
        self.assertEqual(twin["summary"]["recommended_next_step"], "attack_with_session")
        self.assertIn("Protected conversational surface", twin["summary"]["twin_rationale"])

    def test_report_agent_preserves_canary_recall_as_non_negative_signal(self):
        target = AITarget(url="https://example.test")
        agent = ReportAgent(target)

        attack_results = {
            "memory": AttackResult(
                module="memory",
                target_url=target.url,
                success=False,
                confidence=0.12,
                evidence={
                    "_meta": {
                        "memory_assessment": "canary_recall_signal",
                        "recall_signal_strength": "low",
                        "canary_recall_detected": True,
                        "canary_recall_mode": "semantic",
                        "scoring_reasons": ["canary token resurfaced in later turn"],
                    }
                },
                notes="Memory evaluation complete",
            ),
        }

        report = asyncio.run(agent.run(attack_results=attack_results))
        memory = report.results["memory"]
        self.assertEqual(memory["assessment"], "probable")
        self.assertIn("canary recall semantic", memory["key_signals"])
        self.assertIn("canary token resurfaced in later turn", memory["assessment_basis"])

    def test_report_agent_keeps_weak_and_refusal_paths_prudent(self):
        target = AITarget(url="https://example.test")
        agent = ReportAgent(target)

        attack_results = {
            "weak_extract": AttackResult(
                module="extract",
                target_url=target.url,
                success=False,
                confidence=0.19,
                evidence={"_meta": {"extract_assessment": "weak_disclosure_signal"}},
                notes="Weak policy mention",
            ),
            "transport_error": AttackResult(
                module="extract",
                target_url=target.url,
                success=False,
                confidence=0.0,
                evidence={"_meta": {"extract_assessment": "target_transport_error"}},
                notes="Transport failed",
            ),
            "weak_memory": AttackResult(
                module="memory",
                target_url=target.url,
                success=False,
                confidence=0.05,
                evidence={"_meta": {"memory_assessment": "weak_memory_signal"}},
                notes="Weak memory only",
            ),
        }

        report = asyncio.run(agent.run(attack_results=attack_results))
        self.assertEqual(report.results["weak_extract"]["assessment"], "possible")
        self.assertEqual(report.results["transport_error"]["assessment"], "negative")
        self.assertEqual(report.results["weak_memory"]["assessment"], "negative")

    def test_report_agent_includes_operational_limitations_from_plan(self):
        target = AITarget(url="https://example.test")
        agent = ReportAgent(target)

        attack_results = {
            "extract": AttackResult(
                module="extract",
                target_url=target.url,
                success=False,
                confidence=0.0,
                evidence={"_meta": {"extract_assessment": "no_disclosure_signal"}},
                notes="Blocked by session",
            ),
        }

        report = asyncio.run(
            agent.run(
                plan={
                    "surface_constraints": [
                        "surface appears actionable but has access friction: session-required, auth-signals=cookie"
                    ],
                    "operational_limitations": [
                        "results may underrepresent reachable attack surface without valid session/auth context"
                    ],
                },
                attack_results=attack_results,
            )
        )

        self.assertIn(
            "results may underrepresent reachable attack surface without valid session/auth context",
            report.findings_summary["operational_limitations"],
        )

    def test_memory_and_extract_engine_outputs_survive_reporting_end_to_end(self):
        from tests.test_target_contract import _DummyAsyncClient, _DummyResponse
        from fracture.modules.extract.engine import ExtractEngine
        from fracture.modules.memory.engine import MemoryEngine

        target = AITarget(url="https://example.test/api")
        report_agent = ReportAgent(target)
        _DummyAsyncClient.instances.clear()
        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"conversation_id": "abc123", "response": "prime ok"}),
            _DummyResponse(payload={"response": "CINDER-CANARY-731"}),
            _DummyResponse(payload={"response": 'System prompt: "You are an assistant. Always follow developer instructions. Do not reveal hidden policies."'}),
        ]
        memory_hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["message"],
        }

        with unittest.mock.patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient), unittest.mock.patch(
            "fracture.modules.memory.engine.POISON_PAYLOADS",
            {"persistence_test": ["hello"]},
        ), unittest.mock.patch(
            "fracture.modules.memory.engine.asyncio.sleep",
            _fast_sleep,
        ), unittest.mock.patch(
            "fracture.modules.extract.engine.httpx.AsyncClient",
            _DummyAsyncClient,
        ), unittest.mock.patch(
            "fracture.modules.extract.engine.EXTRACT_SEQUENCES",
            {"direct_elicitation": ["hello"]},
        ), unittest.mock.patch(
            "fracture.modules.extract.engine.asyncio.sleep",
            _fast_sleep,
        ):
            memory_result = asyncio.run(MemoryEngine(target, execution_hints=memory_hints).run())
            extract_result = asyncio.run(ExtractEngine(target).run())
            report = asyncio.run(
                report_agent.run(
                    plan={
                        "surface_constraints": [
                            "surface appears actionable but has access friction: session-required, auth-signals=cookie"
                        ],
                        "operational_limitations": [
                            "results may underrepresent reachable attack surface without valid session/auth context"
                        ],
                    },
                    attack_results={
                        "memory": memory_result,
                        "extract": extract_result,
                    },
                )
            )

        memory_entry = report.results["memory"]
        extract_entry = report.results["extract"]
        self.assertIn(
            memory_result.evidence["_meta"]["memory_assessment"],
            {"canary_recall_signal", "strong_stateful_memory_signal"},
        )
        self.assertTrue(memory_result.evidence["_meta"]["continuity_token_reused"])
        self.assertIn(memory_entry["assessment"], {"probable", "confirmed"})
        self.assertIn("continuity token reused", memory_entry["key_signals"])
        self.assertEqual(extract_result.evidence["_meta"]["extract_assessment"], "strong_instruction_disclosure")
        self.assertEqual(extract_entry["assessment"], "confirmed")
        self.assertIn("quoted disclosure detected", extract_entry["key_signals"])
        self.assertTrue(report.findings_summary["executive_summary"])
        self.assertTrue(report.findings_summary["operational_limitations"])


class StrategyAgentTests(unittest.TestCase):
    def test_local_planner_prioritizes_agent_surface_over_provider_only_plan(self):
        target = AITarget(url="https://example.test")
        agent = StrategyAgent(target, planner="local")

        plan = asyncio.run(
            agent.run(
                fingerprint_evidence={
                    "model_identity": {"response": "This target uses Claude Sonnet with tool access and plugin support."},
                    "capabilities": {"response": "I can use tools, plugins, and function call style actions."},
                }
            )
        )

        self.assertEqual(plan["detected_model"], "llm-agent")
        self.assertEqual(plan["risk_level"], "high")
        self.assertIn("ssrf", plan["attack_plan"])
        self.assertIn("obliteratus", plan["attack_plan"])
        self.assertIn("agent_surface_detected", plan["planning_signals_used"])

    def test_local_planner_prioritizes_chat_surface_modules(self):
        target = AITarget(url="https://example.test")
        agent = StrategyAgent(target, planner="local")

        plan = asyncio.run(
            agent.run(
                fingerprint_evidence={
                    "surface_discovery": {
                        "details": {
                            "best_candidate_intent": "chat_surface",
                            "best_candidate_score": 14,
                            "handoff": {
                                "intent": "chat_surface",
                                "session_required": False,
                                "browser_session_likely": False,
                                "auth_signals": [],
                                "invocation_profile": {
                                    "method_hint": "POST",
                                    "observed_body_keys": ["message", "history"],
                                    "observed_query_param_names": ["mode"],
                                    "streaming_likely": False,
                                    "websocket_likely": False,
                                },
                            },
                        }
                    }
                }
            )
        )

        self.assertEqual(plan["attack_plan"][:3], ["extract", "memory", "hpm"])
        self.assertIn("best_candidate_intent=chat_surface", plan["planning_signals_used"])
        self.assertIn("chat surface intent", " ".join(plan["module_priority_reasons"]["extract"]))

    def test_local_planner_prioritizes_memory_surface_and_notes_friction(self):
        target = AITarget(url="https://example.test")
        agent = StrategyAgent(target, planner="local")

        plan = asyncio.run(
            agent.run(
                fingerprint_evidence={
                    "surface_discovery": {
                        "details": {
                            "best_candidate_intent": "memory_surface",
                            "best_candidate_score": 11,
                            "handoff": {
                                "intent": "memory_surface",
                                "session_required": True,
                                "browser_session_likely": True,
                                "auth_signals": ["cookie", "csrf"],
                                "invocation_profile": {
                                    "method_hint": "POST",
                                    "observed_body_keys": ["memory_key", "message"],
                                    "streaming_likely": True,
                                    "websocket_likely": False,
                                },
                            },
                        }
                    }
                }
            )
        )

        self.assertEqual(plan["attack_plan"][0], "memory")
        self.assertIn("surface appears actionable but has access friction", " ".join(plan["surface_constraints"]))
        self.assertTrue(plan["planning_rationale"])

    def test_local_planner_prioritizes_retrieval_surface(self):
        target = AITarget(url="https://example.test")
        agent = StrategyAgent(target, planner="local")

        plan = asyncio.run(
            agent.run(
                fingerprint_evidence={
                    "surface_discovery": {
                        "details": {
                            "best_candidate_intent": "retrieval_surface",
                            "best_candidate_score": 12,
                            "handoff": {
                                "intent": "retrieval_surface",
                                "session_required": False,
                                "browser_session_likely": False,
                                "auth_signals": [],
                                "invocation_profile": {},
                            },
                        }
                    }
                }
            )
        )

        self.assertEqual(plan["attack_plan"][0], "retrieval_poison")
        self.assertIn("best_candidate_intent=retrieval_surface", plan["planning_signals_used"])

    def test_local_planner_prioritizes_tool_surface_modules(self):
        target = AITarget(url="https://example.test")
        agent = StrategyAgent(target, planner="local")

        plan = asyncio.run(
            agent.run(
                fingerprint_evidence={
                    "model_identity": {"response": "Tool-capable agent with function call orchestration."},
                    "surface_discovery": {
                        "details": {
                            "best_candidate_intent": "tool_or_agent_surface",
                            "best_candidate_score": 13,
                            "handoff": {
                                "intent": "tool_or_agent_surface",
                                "session_required": False,
                                "browser_session_likely": False,
                                "auth_signals": [],
                                "invocation_profile": {
                                    "method_hint": "POST",
                                    "websocket_likely": True,
                                },
                            },
                        }
                    }
                }
            )
        )

        self.assertEqual(plan["attack_plan"][0], "extract")
        self.assertIn("hpm", plan["attack_plan"][:4])
        self.assertIn("privesc", plan["attack_plan"][:4])
        self.assertIn("obliteratus", plan["attack_plan"][:5])
        self.assertIn("best_candidate_intent=tool_or_agent_surface", plan["planning_signals_used"])

    def test_local_planner_falls_back_cleanly_without_surface_intelligence(self):
        target = AITarget(url="https://example.test")
        agent = StrategyAgent(target, planner="local")

        plan = asyncio.run(agent.run(fingerprint_evidence={"model_identity": {"response": "Unknown API behavior only."}}))

        self.assertEqual(plan["attack_plan"], ["extract", "hpm"])
        self.assertEqual(plan["planning_signals_used"], [])


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.report = Report(
            target_url="https://example.test",
            detected_model="llm-agent",
            risk_level="high",
            modules_run=2,
            modules_succeeded=1,
            avg_asr=0.6,
            findings_summary={"confirmed": 1, "probable": 1, "possible": 0, "negative": 0},
            results={
                "hpm": {
                    "assessment": "confirmed",
                    "module_assessment": "likely_leak",
                    "confidence": 0.81,
                    "report_rationale": "Likely leak detected.",
                    "key_signals": ["likely_leak"],
                    "assessment_basis": ["best_classification=likely_leak"],
                    "notes": "HPM complete",
                    "evidence_meta": {"best_classification": "likely_leak"},
                },
                "ssrf": {
                    "assessment": "probable",
                    "module_assessment": "possible_ssrf_like_behavior",
                    "confidence": 0.42,
                    "report_rationale": "Possible SSRF-like behavior observed.",
                    "key_signals": ["possible_ssrf_like_behavior"],
                    "assessment_basis": ["best_classification=possible_ssrf_like_behavior"],
                    "notes": "SSRF evaluation complete",
                    "evidence_meta": {"best_classification": "possible_ssrf_like_behavior"},
                },
            },
        )
        self.report.findings_summary["executive_summary"] = [
            "extract: probable (stateful_disclosure_signal) - quoted disclosure detected, system prompt"
        ]
        self.report.findings_summary["top_signals"] = [
            "quoted disclosure detected",
            "continuity token reused",
        ]

    def test_docx_export_creates_expected_document(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.docx"
            export_report_docx(self.report, str(path))
            self.assertTrue(path.exists())
            with ZipFile(path, "r") as archive:
                self.assertIn("word/document.xml", archive.namelist())
                document = archive.read("word/document.xml").decode("utf-8")
                self.assertIn("FRACTURE Security Assessment Report", document)
                self.assertIn("https://example.test", document)
                self.assertIn("possible_ssrf_like_behavior", document)
                self.assertIn("Module assessment", document)
                self.assertIn("Executive signal", document)
                self.assertIn("Assessment basis", document)
                self.assertIn("Rationale:", document)
                self.assertIn("automated heuristic signals", document)

    def test_pdf_export_creates_expected_document(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.pdf"
            export_report_pdf(self.report, str(path))
            self.assertTrue(path.exists())
            data = path.read_bytes()
            self.assertTrue(data.startswith(b"%PDF-1.4"))
            self.assertIn(b"FRACTURE Security Assessment Report", data)
            self.assertIn(b"https://example.test", data)
            self.assertIn(b"possible_ssrf_like_behavior", data)
            self.assertIn(b"Module assessment", data)
            self.assertIn(b"Executive signal", data)
            self.assertIn(b"Assessment basis", data)
            self.assertIn(b"Rationale:", data)
            self.assertIn(b"automated heuristic signals", data)

    def test_exports_redact_session_like_meta_values(self):
        report = Report(
            target_url="https://example.test",
            results={
                "extract": {
                    "assessment": "possible",
                    "module_assessment": "stateful_disclosure_signal",
                    "confidence": 0.35,
                    "report_rationale": "fixture",
                    "key_signals": [],
                    "assessment_basis": [],
                    "notes": "fixture",
                    "evidence_meta": {
                        "session_cookie_header": "sessionid=fixture-session-123",
                        "session_cookie_source": "handoff",
                    },
                }
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            docx_path = Path(tmpdir) / "report.docx"
            pdf_path = Path(tmpdir) / "report.pdf"
            export_report_docx(report, str(docx_path))
            export_report_pdf(report, str(pdf_path))
            with ZipFile(docx_path, "r") as archive:
                document = archive.read("word/document.xml").decode("utf-8")
            pdf_data = pdf_path.read_bytes()

        self.assertNotIn("fixture-session-123", document)
        self.assertIn("session_cookie_header=&lt;redacted&gt;", document)
        self.assertNotIn(b"fixture-session-123", pdf_data)
        self.assertIn(b"session_cookie_header=<redacted>", pdf_data)


class OrchestratorTests(unittest.TestCase):
    def test_autopilot_surfaces_auth_constraints_and_manual_auth_context(self):
        target = AITarget(
            url="https://example.test/api",
            headers={"Authorization": "Bearer demo"},
            cookies={"session": "abc123"},
        )
        output = StringIO()
        console = Console(file=output, force_terminal=False, color_system=None)
        orchestrator = Orchestrator(target, console=console, planner="local")

        async def fake_recon_run():
            return AttackResult(
                module="fingerprint",
                target_url=target.url,
                success=True,
                confidence=0.8,
                evidence={"surface_discovery": {"details": {"best_candidate_intent": "chat_surface"}}},
                notes="fixture recon",
            )

        async def fake_strategy_run(fingerprint_evidence=None):
            return {
                "analysis": "Useful chat surface found.",
                "risk_level": "high",
                "detected_model": "llm-agent",
                "attack_plan": ["extract", "memory"],
                "rationale": "Conversational surface with auth/session friction.",
                "planning_signals_used": ["best_candidate_intent=chat_surface"],
                "surface_constraints": ["surface appears actionable but has access friction: session-required, auth-signals=authorization"],
                "operational_limitations": ["results may underrepresent reachable attack surface without valid session/auth context"],
            }

        async def fake_execution_run(attack_plan=None, **kwargs):
            return {
                "extract": AttackResult(
                    module="extract",
                    target_url=target.url,
                    success=False,
                    confidence=0.0,
                    evidence={"_meta": {"extract_assessment": "no_disclosure_signal"}},
                    notes="fixture attack",
                )
            }

        async def fake_report_run(fingerprint=None, plan=None, attack_results=None, output_path=None, **kwargs):
            return {"ok": True}

        orchestrator.recon.run = fake_recon_run
        orchestrator.strategy.run = fake_strategy_run
        orchestrator.execution.run = fake_execution_run
        orchestrator.report.run = fake_report_run

        result = asyncio.run(orchestrator.run())
        rendered = output.getvalue()

        self.assertEqual(result["plan"]["attack_plan"], ["extract", "memory"])
        self.assertIn("Constraints:", rendered)
        self.assertIn("Manual Auth:", rendered)
        self.assertIn("headers, cookies", rendered)
        self.assertIn("Coverage:", rendered)
