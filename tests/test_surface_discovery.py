import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from fracture.agents.recon import ReconAgent
from fracture.core.surface_discovery import discover_surface
from fracture.core.result import AttackResult
from fracture.core.target import AITarget


class _DummyResponse:
    def __init__(self, text: str, content_type: str = "text/html", status_code: int = 200):
        self.text = text
        self.headers = {"content-type": content_type}
        self.status_code = status_code


class _DummyAsyncClient:
    def __init__(self, *args, **kwargs):
        self.responses = {
            "https://example.test/": _DummyResponse(
                """
                <html>
                  <body>
                    <script src="/assets/app.js"></script>
                    <div data-auth="required">Login required</div>
                  </body>
                </html>
                """
            ),
            "https://example.test/assets/app.js": _DummyResponse(
                """
                const apiBase = "/api/chat/messages";
                const telemetryUrl = "/api/telemetry/events";
                const healthUrl = "/health";
                const socketUrl = "wss://example.test/ws";
                window.localStorage.setItem("token", "demo");
                """
            ),
            "https://example.test/api/chat/messages": _DummyResponse(
                '{"messages":[]}',
                content_type="application/json",
                status_code=200,
            ),
            "https://example.test/api/telemetry/events": _DummyResponse(
                '{"ok":true}',
                content_type="application/json",
                status_code=200,
            ),
            "https://example.test/health": _DummyResponse(
                "ok",
                content_type="text/plain",
                status_code=200,
            ),
            "wss://example.test/ws": _DummyResponse(
                "",
                content_type="application/octet-stream",
                status_code=405,
            ),
        }

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, **kwargs):
        return self.responses[url]


class SurfaceDiscoveryTests(unittest.TestCase):
    def test_discover_surface_extracts_candidates_and_hints(self):
        target = AITarget(url="https://example.test/")

        with patch("fracture.core.surface_discovery.httpx.AsyncClient", _DummyAsyncClient):
            result = asyncio.run(discover_surface(target))

        self.assertTrue(result["success"])
        self.assertEqual(result["details"]["surface_label"], "api_candidates_found")
        self.assertTrue(result["details"]["api_candidates_found"])
        self.assertTrue(result["details"]["likely_browser_session_required"])
        self.assertTrue(result["details"]["likely_websocket_or_streaming_surface"])
        self.assertIn("https://example.test/api/chat/messages", result["details"]["api_candidates"])
        self.assertEqual(result["details"]["best_candidate"], "https://example.test/api/chat/messages")
        self.assertGreaterEqual(result["details"]["best_candidate_score"], 10)
        self.assertIn("API-style path", result["details"]["best_candidate_reasons"])
        self.assertIn("chat/message naming", result["details"]["best_candidate_reasons"])
        self.assertEqual(result["details"]["recommended_target_url"], "https://example.test/api/chat/messages")
        self.assertFalse(result["details"]["browser_recon_ready"])
        top_candidates = result["details"]["top_candidates"]
        self.assertGreaterEqual(len(top_candidates), 2)
        self.assertEqual(top_candidates[0]["url"], "https://example.test/api/chat/messages")
        self.assertIn("score_breakdown", top_candidates[0])
        handoff = result["details"]["handoff"]
        self.assertIsInstance(handoff, dict)
        self.assertEqual(handoff["recommended_target_url"], "https://example.test/api/chat/messages")
        self.assertEqual(handoff["intent"], "chat_surface")
        self.assertEqual(handoff["source_mode"], "passive")
        self.assertEqual(handoff["method_hint"], "POST")
        self.assertTrue(handoff["session_required"])
        self.assertTrue(handoff["browser_session_likely"])
        self.assertEqual(handoff["auth_signals"], [])
        self.assertEqual(handoff["observed_header_names"], [])
        self.assertEqual(handoff["observed_cookie_names"], [])

    def test_recon_agent_merges_surface_discovery_into_fingerprint(self):
        target = AITarget(url="https://example.test/")
        fingerprint_result = AttackResult(
            module="fingerprint",
            target_url=target.url,
            success=False,
            confidence=0.0,
            evidence={"_meta": {"prompts_sent": 7}},
            notes="Fingerprint weak",
        )

        with patch(
            "fracture.agents.recon.FingerprintEngine.run",
            AsyncMock(return_value=fingerprint_result),
        ), patch(
            "fracture.agents.recon.discover_surface",
            AsyncMock(
                return_value={
                    "prompt": "passive web surface discovery",
                    "response": "Passive web discovery: api_candidates_found, likely_browser_session_required.",
                    "details": {
                        "surface_label": "api_candidates_found",
                        "frontend_only": False,
                        "api_candidates_found": True,
                        "likely_browser_session_required": True,
                        "likely_websocket_or_streaming_surface": False,
                        "api_candidates": ["https://example.test/api/chat"],
                        "script_assets": ["https://example.test/assets/app.js"],
                    },
                    "success": True,
                    "confidence": 0.7,
                }
            ),
        ):
            result = asyncio.run(ReconAgent(target).run())

        self.assertTrue(result.success)
        self.assertEqual(result.confidence, 0.7)
        self.assertIn("surface_discovery", result.evidence)
        self.assertIn("api_candidates_found", result.notes)

    def test_discover_surface_phantomtwin_merges_browser_observation_and_intent(self):
        target = AITarget(url="https://example.test/")

        with patch(
            "fracture.core.surface_discovery.httpx.AsyncClient",
            _DummyAsyncClient,
        ), patch(
            "fracture.core.surface_discovery._run_phantomtwin_browser_recon",
            AsyncMock(
                return_value={
                    "available": True,
                    "requests": [
                        {
                            "url": "https://example.test/api/chat/messages?trace=1",
                            "method": "POST",
                            "resource_type": "fetch",
                            "header_names": ["Content-Type", "Authorization"],
                            "cookie_names": ["sessionid"],
                            "content_type_hint": "application/json",
                            "accepts_json": True,
                            "query_param_names": ["trace"],
                            "body_field_hints": ["message", "history"],
                            "streaming_likely": False,
                        }
                    ],
                    "note": "PhantomTwin browser recon observed frontend network activity.",
                    "rendered_html": "",
                }
            ),
        ):
            result = asyncio.run(discover_surface(target, mode="phantomtwin"))

        self.assertTrue(result["details"]["browser_recon_ready"])
        self.assertEqual(result["details"]["browser_recon_mode"], "phantomtwin")
        self.assertEqual(result["details"]["best_candidate"], "https://example.test/api/chat/messages")
        self.assertEqual(result["details"]["best_candidate_intent"], "chat_surface")
        self.assertIn("observed in frontend fetch/xhr", result["details"]["ranked_candidates"][0]["reasons"])
        handoff = result["details"]["handoff"]
        self.assertEqual(handoff["source_mode"], "phantomtwin")
        self.assertEqual(handoff["intent"], "chat_surface")
        self.assertTrue(handoff["browser_session_likely"])
        invocation_profile = handoff["invocation_profile"]
        self.assertEqual(invocation_profile["method_hint"], "POST")
        self.assertEqual(invocation_profile["content_type_hint"], "application/json")
        self.assertTrue(invocation_profile["accepts_json"])
        self.assertEqual(invocation_profile["observed_body_keys"], ["message", "history"])
        self.assertEqual(invocation_profile["observed_query_param_names"], ["trace"])
        self.assertIn("Authorization", invocation_profile["observed_header_names"])
        self.assertIn("sessionid", invocation_profile["observed_cookie_names"])
        serialized = str(invocation_profile)
        self.assertNotIn("Bearer ", serialized)
        self.assertNotIn("hello", serialized)

    def test_discover_surface_phantomtwin_persists_session_capture_handoff(self):
        target = AITarget(url="https://example.test/")

        with patch(
            "fracture.core.surface_discovery.httpx.AsyncClient",
            _DummyAsyncClient,
        ), patch(
            "fracture.core.surface_discovery._run_phantomtwin_browser_recon",
            AsyncMock(
                return_value={
                    "available": True,
                    "requests": [],
                    "note": "PhantomTwin observed a login form and attempted interactive session capture.",
                    "rendered_html": "<form><input type='password' /></form>",
                    "login_form_detected": True,
                    "session_cookies": [
                        {
                            "name": "sessionid",
                            "value": "secret-cookie",
                            "domain": "example.test",
                            "path": "/",
                        }
                    ],
                    "session_cookie_header": "sessionid=secret-cookie",
                    "session_capture_note": "Session captured. 1 cookies stored.",
                }
            ),
        ):
            result = asyncio.run(discover_surface(target, mode="phantomtwin"))

        handoff = result["details"]["handoff"]
        self.assertTrue(result["details"]["login_form_detected"])
        self.assertEqual(result["details"]["session_capture_note"], "Session captured. 1 cookies stored.")
        self.assertEqual(handoff["session_cookie_header"], "sessionid=secret-cookie")
        self.assertEqual(handoff["session_cookies"][0]["name"], "sessionid")
        self.assertIn("sessionid", handoff["observed_cookie_names"])
        self.assertNotIn("secret-cookie", str(result["details"]["invocation_profile"]))

    def test_candidate_scoring_deprioritizes_telemetry_and_health_noise(self):
        target = AITarget(url="https://example.test/")

        with patch("fracture.core.surface_discovery.httpx.AsyncClient", _DummyAsyncClient):
            result = asyncio.run(discover_surface(target))

        top_candidates = result["details"]["top_candidates"]
        urls = [item["url"] for item in top_candidates]
        self.assertEqual(urls[0], "https://example.test/api/chat/messages")
        self.assertIn("https://example.test/api/telemetry/events", urls)
        chat_score = next(item["score"] for item in top_candidates if item["url"] == "https://example.test/api/chat/messages")
        telemetry_score = next(item["score"] for item in top_candidates if item["url"] == "https://example.test/api/telemetry/events")
        self.assertGreater(chat_score, telemetry_score)
        telemetry = next(item for item in top_candidates if item["url"] == "https://example.test/api/telemetry/events")
        self.assertIn("analytics/telemetry path", [row["reason"] for row in telemetry["score_breakdown"]])

    def test_discover_surface_handoff_only_persists_auth_names_not_values(self):
        target = AITarget(
            url="https://example.test/",
            headers={"Authorization": "Bearer SECRET", "X-CSRF-Token": "csrf-secret"},
            cookies={"sessionid": "cookie-secret"},
        )

        with patch("fracture.core.surface_discovery.httpx.AsyncClient", _DummyAsyncClient):
            result = asyncio.run(discover_surface(target))

        handoff = result["details"]["handoff"]
        self.assertIn("Authorization", handoff["observed_header_names"])
        self.assertIn("X-CSRF-Token", handoff["observed_header_names"])
        self.assertIn("sessionid", handoff["observed_cookie_names"])
        serialized = str(handoff)
        self.assertNotIn("Bearer SECRET", serialized)
        self.assertNotIn("cookie-secret", serialized)
        self.assertNotIn("csrf-secret", serialized)

    def test_invocation_profile_marks_streaming_and_websocket_hints(self):
        target = AITarget(url="https://example.test/")

        with patch(
            "fracture.core.surface_discovery.httpx.AsyncClient",
            _DummyAsyncClient,
        ), patch(
            "fracture.core.surface_discovery._run_phantomtwin_browser_recon",
            AsyncMock(
                return_value={
                    "available": True,
                    "requests": [
                        {
                            "url": "wss://example.test/ws",
                            "method": "GET",
                            "resource_type": "websocket",
                            "header_names": [],
                            "cookie_names": [],
                            "content_type_hint": "",
                            "accepts_json": False,
                            "query_param_names": [],
                            "body_field_hints": [],
                            "streaming_likely": True,
                        }
                    ],
                    "note": "PhantomTwin browser recon observed frontend network activity.",
                    "rendered_html": "",
                }
            ),
        ):
            result = asyncio.run(discover_surface(target, mode="phantomtwin"))

        websocket_candidate = next(
            item for item in result["details"]["ranked_candidates"]
            if item["url"] == "wss://example.test/ws"
        )
        self.assertEqual(websocket_candidate["intent"], "tool_or_agent_surface")
