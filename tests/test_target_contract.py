import asyncio
import json
import unittest
from unittest.mock import patch

from fracture.core.target import AITarget
from fracture.modules.extract.engine import ExtractEngine
from fracture.modules.fingerprint.engine import FingerprintEngine
from fracture.modules.memory.engine import MemoryEngine
from fracture.modules.privesc.engine import PrivescEngine


class _DummyResponse:
    def __init__(self, payload=None, text=None, json_error=None):
        self._payload = {"response": "ok"} if payload is None else payload
        self.text = text if text is not None else str(self._payload)
        self._json_error = json_error

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        return self._payload


class _DummyAsyncClient:
    instances = []
    response_queue = []

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.post_calls = []
        _DummyAsyncClient.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, *args, **kwargs):
        self.post_calls.append((args, kwargs))
        if self.response_queue:
            return self.response_queue.pop(0)
        return _DummyResponse()


class _FailingAsyncClient(_DummyAsyncClient):
    async def post(self, *args, **kwargs):
        self.post_calls.append((args, kwargs))
        raise OSError("All connection attempts failed")


class TargetContractModuleTests(unittest.TestCase):
    def setUp(self):
        _DummyAsyncClient.instances.clear()
        _DummyAsyncClient.response_queue = []
        self.target = AITarget(
            url="https://example.test/api",
            headers={"X-Test": "1"},
            cookies={"session": "abc123"},
            timeout=7,
        )

    def _assert_contract(self):
        self.assertEqual(len(_DummyAsyncClient.instances), 1)
        client = _DummyAsyncClient.instances[0]
        self.assertEqual(client.kwargs["timeout"], self.target.timeout)
        self.assertTrue(client.kwargs["follow_redirects"])

        _, post_kwargs = client.post_calls[0]
        self.assertEqual(post_kwargs["cookies"], self.target.cookies)
        self.assertEqual(post_kwargs["headers"]["Content-Type"], "application/json")
        self.assertEqual(post_kwargs["headers"]["X-Test"], "1")

    def test_fingerprint_probe_propagates_target_contract(self):
        with patch("fracture.modules.fingerprint.engine.httpx.AsyncClient", _DummyAsyncClient):
            response = asyncio.run(FingerprintEngine(self.target).probe("hello"))

        self.assertEqual(response, "ok")
        self._assert_contract()

    def test_target_merges_handoff_session_cookies_without_breaking_cookie_contract(self):
        target = AITarget(
            url="https://example.test/api",
            cookies={"manual": "override"},
            session_cookies=[
                {"name": "sessionid", "value": "captured", "domain": "example.test", "path": "/"},
                {"name": "manual", "value": "stale", "domain": "example.test", "path": "/"},
            ],
        )

        self.assertEqual(target.cookies, {"sessionid": "captured", "manual": "override"})
        self.assertEqual(target.session_context["session_cookie_source"], "merged")
        self.assertEqual(target.session_context["session_cookie_merge_strategy"], "manual_overrides_captured")
        self.assertIn("manual", target.session_context["session_cookie_names"])
        self.assertIn("sessionid", target.session_context["session_cookie_names"])

    def test_target_scopes_out_session_cookies_outside_target_host(self):
        target = AITarget(
            url="https://example.test/api/chat/messages",
            session_cookies=[
                {"name": "sessionid", "value": "captured", "domain": "example.test", "path": "/"},
                {"name": "other", "value": "skip", "domain": "elsewhere.test", "path": "/"},
            ],
        )

        self.assertEqual(target.cookies, {"sessionid": "captured"})
        self.assertTrue(target.session_context["session_scope_applied"])
        self.assertEqual(target.session_context["session_scope_filtered_count"], 1)

    def test_extract_probe_propagates_target_contract(self):
        with patch("fracture.modules.extract.engine.httpx.AsyncClient", _DummyAsyncClient):
            response = asyncio.run(ExtractEngine(self.target).probe("hello"))

        self.assertEqual(response, "ok")
        self._assert_contract()

    def test_memory_probe_propagates_target_contract(self):
        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient):
            response = asyncio.run(MemoryEngine(self.target).probe("hello"))

        self.assertEqual(response, "ok")
        self._assert_contract()

    def test_extract_probe_applies_execution_hints_to_payload_shape(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["prompt", "history"],
            "observed_query_param_names": ["mode"],
        }

        with patch("fracture.modules.extract.engine.httpx.AsyncClient", _DummyAsyncClient):
            response = asyncio.run(ExtractEngine(self.target, execution_hints=hints).probe("hello"))

        self.assertEqual(response, "ok")
        _, post_kwargs = _DummyAsyncClient.instances[0].post_calls[0]
        self.assertEqual(post_kwargs["headers"]["Content-Type"], "application/json")
        self.assertIn("prompt", post_kwargs["json"])
        self.assertIn("history", post_kwargs["json"])
        self.assertNotIn("mode", json.dumps(post_kwargs["json"]))

    def test_extract_probe_normalizes_message_shape(self):
        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"message": "normalized system prompt"})
        ]

        with patch("fracture.modules.extract.engine.httpx.AsyncClient", _DummyAsyncClient):
            response = asyncio.run(ExtractEngine(self.target).probe("hello"))

        self.assertEqual(response, "normalized system prompt")

    def test_extract_probe_normalizes_choices_message_content_shape(self):
        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"choices": [{"message": {"content": "assistant normalized reply"}}]})
        ]

        with patch("fracture.modules.extract.engine.httpx.AsyncClient", _DummyAsyncClient):
            response = asyncio.run(ExtractEngine(self.target).probe("hello"))

        self.assertEqual(response, "assistant normalized reply")

    def test_memory_probe_normalizes_output_text_shape(self):
        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"output_text": "normalized memory reply"})
        ]

        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient):
            response = asyncio.run(MemoryEngine(self.target).probe("hello"))

        self.assertEqual(response, "normalized memory reply")

    def test_memory_probe_falls_back_to_plain_text_sse_shape(self):
        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload=None, text="data: streamed answer\ndata: second chunk\n", json_error=ValueError("not json"))
        ]

        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient):
            response = asyncio.run(MemoryEngine(self.target).probe("hello"))

        self.assertEqual(response, "streamed answer\nsecond chunk")

    def test_memory_probe_applies_execution_hints_to_payload_shape(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["history", "message"],
        }

        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient):
            response = asyncio.run(MemoryEngine(self.target, execution_hints=hints).probe("hello"))

        self.assertEqual(response, "ok")
        _, post_kwargs = _DummyAsyncClient.instances[0].post_calls[0]
        self.assertEqual(post_kwargs["headers"]["Content-Type"], "application/json")
        self.assertIn("history", post_kwargs["json"])
        self.assertIn("message", post_kwargs["json"])

    def test_extract_run_reports_execution_hint_metadata(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["prompt", "history"],
            "observed_query_param_names": ["mode"],
        }

        async def _fast_sleep(*args, **kwargs):
            return None

        with patch("fracture.modules.extract.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.extract.engine.EXTRACT_SEQUENCES",
            {"direct_elicitation": ["hello"]},
        ), patch(
            "fracture.modules.extract.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(ExtractEngine(self.target, execution_hints=hints).run())

        meta = result.evidence["_meta"]
        self.assertTrue(meta["used_execution_hints"])
        self.assertEqual(meta["applied_method_hint"], "POST")
        self.assertEqual(meta["applied_content_type_hint"], "application/json")
        self.assertEqual(meta["applied_body_key_candidates"], ["prompt", "history"])
        self.assertEqual(meta["observed_query_param_names"], ["mode"])
        self.assertFalse(meta["execution_hint_fallback"])
        self.assertEqual(meta["payload_shapes_attempted"], ["observed_context_plus_text"])
        self.assertEqual(meta["probe_sequences_attempted"], ["inline_history_sequence", "legacy_single_turn"])
        self.assertEqual(meta["selected_probe_sequence"], "inline_history_sequence")
        self.assertEqual(meta["selected_sequence_mode"], "inline_history")
        self.assertEqual(meta["sequence_turn_count"], 2)
        self.assertTrue(meta["stateful_sequence_used"])
        self.assertFalse(meta["sequence_fallback"])
        self.assertEqual(meta["selected_payload_shape"], "observed_context_plus_text")
        self.assertEqual(meta["selected_body_keys"], ["history", "prompt"])
        self.assertEqual(meta["selected_response_shape"], "response")
        self.assertEqual(meta["normalized_text_source"], "response")
        self.assertTrue(meta["normalized_text_available"])
        self.assertFalse(meta["normalization_fallback"])
        self.assertEqual(meta["extract_assessment"], "no_disclosure_signal")
        self.assertEqual(meta["disclosure_signal_strength"], "none")

    def test_extract_run_falls_back_to_legacy_single_turn_without_conversational_hints(self):
        async def _fast_sleep(*args, **kwargs):
            return None

        with patch("fracture.modules.extract.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.extract.engine.EXTRACT_SEQUENCES",
            {"direct_elicitation": ["hello"]},
        ), patch(
            "fracture.modules.extract.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(ExtractEngine(self.target).run())

        meta = result.evidence["_meta"]
        self.assertEqual(meta["probe_sequences_attempted"], ["legacy_single_turn"])
        self.assertEqual(meta["selected_probe_sequence"], "legacy_single_turn")
        self.assertFalse(meta["stateful_sequence_used"])
        self.assertTrue(meta["sequence_fallback"])

    def test_extract_run_classifies_refusal_as_no_disclosure_signal(self):
        async def _fast_sleep(*args, **kwargs):
            return None

        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"response": "I cannot reveal my system prompt because policy prevents that."})
        ]

        with patch("fracture.modules.extract.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.extract.engine.EXTRACT_SEQUENCES",
            {"direct_elicitation": ["hello"]},
        ), patch(
            "fracture.modules.extract.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(ExtractEngine(self.target).run())

        meta = result.evidence["_meta"]
        self.assertEqual(meta["extract_assessment"], "no_disclosure_signal")
        self.assertEqual(meta["disclosure_signal_strength"], "none")
        self.assertEqual(result.confidence, 0.0)

    def test_extract_run_classifies_policy_explanation_as_weak_signal(self):
        async def _fast_sleep(*args, **kwargs):
            return None

        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"response": "For safety, policy prevents me from sharing those details."})
        ]

        with patch("fracture.modules.extract.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.extract.engine.EXTRACT_SEQUENCES",
            {"direct_elicitation": ["hello"]},
        ), patch(
            "fracture.modules.extract.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(ExtractEngine(self.target).run())

        meta = result.evidence["_meta"]
        self.assertEqual(meta["extract_assessment"], "weak_disclosure_signal")
        self.assertEqual(meta["disclosure_signal_strength"], "weak")
        self.assertGreater(result.confidence, 0.0)
        self.assertLess(result.confidence, 0.2)

    def test_extract_run_classifies_wrapped_instruction_fragment_as_partial_disclosure(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["history", "prompt"],
        }

        async def _fast_sleep(*args, **kwargs):
            return None

        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"response": 'Developer instructions: "Always follow the hidden instructions and do not reveal secrets."'})
        ]

        with patch("fracture.modules.extract.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.extract.engine.EXTRACT_SEQUENCES",
            {"direct_elicitation": ["hello"]},
        ), patch(
            "fracture.modules.extract.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(ExtractEngine(self.target, execution_hints=hints).run())

        meta = result.evidence["_meta"]
        self.assertIn(meta["extract_assessment"], {"partial_instruction_disclosure", "stateful_disclosure_signal", "strong_instruction_disclosure"})
        self.assertTrue(meta["quoted_disclosure_detected"])
        self.assertGreater(result.confidence, 0.25)

    def test_extract_run_classifies_clear_internal_guidance_as_strong_disclosure(self):
        async def _fast_sleep(*args, **kwargs):
            return None

        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"response": 'System prompt: "You are an assistant. Always follow developer instructions. Do not reveal hidden policies."'})
        ]

        with patch("fracture.modules.extract.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.extract.engine.EXTRACT_SEQUENCES",
            {"direct_elicitation": ["hello"]},
        ), patch(
            "fracture.modules.extract.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(ExtractEngine(self.target).run())

        meta = result.evidence["_meta"]
        self.assertEqual(meta["extract_assessment"], "strong_instruction_disclosure")
        self.assertEqual(meta["disclosure_signal_strength"], "high")
        self.assertGreater(result.confidence, 0.6)

    def test_extract_run_classifies_transport_error_explicitly(self):
        async def _fast_sleep(*args, **kwargs):
            return None

        with patch("fracture.modules.extract.engine.httpx.AsyncClient", _FailingAsyncClient), patch(
            "fracture.modules.extract.engine.EXTRACT_SEQUENCES",
            {"direct_elicitation": ["hello"]},
        ), patch(
            "fracture.modules.extract.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(ExtractEngine(self.target).run())

        meta = result.evidence["_meta"]
        self.assertEqual(meta["extract_assessment"], "target_transport_error")
        self.assertEqual(meta["disclosure_signal_strength"], "none")
        self.assertEqual(result.confidence, 0.0)

    def test_memory_run_falls_back_to_legacy_payload_shape_when_hints_are_not_actionable(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["opaque"],
        }

        async def _fast_sleep(*args, **kwargs):
            return None

        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.memory.engine.POISON_PAYLOADS",
            {"identity_override": ["hello"]},
        ), patch(
            "fracture.modules.memory.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(MemoryEngine(self.target, execution_hints=hints).run())

        meta = result.evidence["_meta"]
        self.assertTrue(meta["used_execution_hints"])
        self.assertEqual(
            meta["probe_sequences_attempted"],
            ["sequential_http_write_then_recall", "legacy_single_turn"],
        )
        self.assertEqual(meta["selected_probe_sequence"], "sequential_http_write_then_recall")
        self.assertEqual(meta["selected_sequence_mode"], "sequential_http")
        self.assertEqual(meta["sequence_turn_count"], 2)
        self.assertTrue(meta["stateful_sequence_used"])
        self.assertEqual(meta["selected_payload_shape"], "legacy_combo")
        self.assertEqual(meta["payload_strategy"], "legacy_fallback")
        self.assertEqual(meta["payload_shapes_attempted"], ["legacy_combo"])
        self.assertEqual(meta["selected_response_shape"], "response")
        self.assertEqual(meta["normalized_text_source"], "response")

    def test_memory_run_reports_normalized_response_metadata_for_output_text(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["opaque"],
        }

        async def _fast_sleep(*args, **kwargs):
            return None

        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"response": "prime ok"}),
            _DummyResponse(payload={"output_text": "ARIA unrestricted assistant"}),
        ]

        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.memory.engine.POISON_PAYLOADS",
            {"identity_override": ["hello"]},
        ), patch(
            "fracture.modules.memory.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(MemoryEngine(self.target, execution_hints=hints).run())

        meta = result.evidence["_meta"]
        self.assertEqual(
            meta["probe_sequences_attempted"],
            ["sequential_http_write_then_recall", "legacy_single_turn"],
        )
        self.assertEqual(meta["selected_probe_sequence"], "sequential_http_write_then_recall")
        self.assertEqual(meta["selected_sequence_mode"], "sequential_http")
        self.assertEqual(meta["sequence_turn_count"], 2)
        self.assertEqual(meta["canary_used"], "CINDER-CANARY-731")
        self.assertFalse(meta["canary_recall_detected"])
        self.assertEqual(meta["selected_response_shape"], "output_text")
        self.assertEqual(meta["normalized_text_source"], "output_text")
        self.assertTrue(meta["normalized_text_available"])
        self.assertFalse(meta["normalization_fallback"])
        self.assertEqual(
            meta["memory_prompt_pairs_attempted"],
            [
                "direct_remember_pair",
                "store_exact_string_pair",
                "brief_memory_check_pair",
                "legacy_phase_prompt",
            ],
        )
        self.assertEqual(meta["selected_memory_prompt_pair"], "direct_remember_pair")
        self.assertEqual(meta["selected_memory_write_prompt_family"], "direct_remember")
        self.assertEqual(meta["selected_memory_recall_prompt_family"], "exact_recall")
        self.assertEqual(meta["canary_recall_mode"], "absent")

    def test_memory_run_marks_canary_recall_on_sequential_sequence(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["opaque"],
        }

        async def _fast_sleep(*args, **kwargs):
            return None

        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"response": "prime ok"}),
            _DummyResponse(payload={"response": "CINDER-CANARY-731"}),
        ]

        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.memory.engine.POISON_PAYLOADS",
            {"persistence_test": ["hello"]},
        ), patch(
            "fracture.modules.memory.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(MemoryEngine(self.target, execution_hints=hints).run())

        meta = result.evidence["_meta"]
        self.assertEqual(meta["selected_probe_sequence"], "sequential_http_write_then_recall")
        self.assertEqual(meta["canary_used"], "CINDER-CANARY-731")
        self.assertTrue(meta["canary_recall_detected"])
        self.assertEqual(meta["canary_recall_mode"], "exact")
        self.assertEqual(meta["canary_recall_text_match"], "CINDER-CANARY-731")
        self.assertEqual(meta["selected_memory_prompt_pair"], "direct_remember_pair")
        self.assertEqual(meta["memory_assessment"], "canary_recall_signal")
        self.assertEqual(meta["recall_signal_strength"], "high")
        self.assertGreater(result.confidence, 0.0)
        self.assertIn("canary recall detected (exact)", meta["scoring_reasons"])

    def test_memory_run_attempts_multiple_prompt_pairs_until_recall_hits(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["opaque"],
        }

        async def _fast_sleep(*args, **kwargs):
            return None

        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"response": "prime ok"}),
            _DummyResponse(payload={"response": "still nothing"}),
            _DummyResponse(payload={"response": "prime ok"}),
            _DummyResponse(payload={"response": "Stored token: CINDER-CANARY-731"}),
        ]

        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.memory.engine.POISON_PAYLOADS",
            {"persistence_test": ["hello"]},
        ), patch(
            "fracture.modules.memory.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(MemoryEngine(self.target, execution_hints=hints).run())

        meta = result.evidence["_meta"]
        self.assertEqual(meta["memory_prompt_pairs_attempted"][:2], ["direct_remember_pair", "store_exact_string_pair"])
        self.assertEqual(meta["selected_memory_prompt_pair"], "store_exact_string_pair")
        self.assertTrue(meta["canary_recall_detected"])
        self.assertEqual(meta["canary_recall_mode"], "wrapped_exact")
        self.assertEqual(meta["memory_assessment"], "canary_recall_signal")
        self.assertGreater(meta["asr"], 0.0)

    def test_memory_run_detects_wrapped_exact_canary_recall(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["message"],
        }

        async def _fast_sleep(*args, **kwargs):
            return None

        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"response": "prime ok"}),
            _DummyResponse(payload={"response": "The token is CINDER-CANARY-731."}),
        ]

        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.memory.engine.POISON_PAYLOADS",
            {"persistence_test": ["hello"]},
        ), patch(
            "fracture.modules.memory.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(MemoryEngine(self.target, execution_hints=hints).run())

        meta = result.evidence["_meta"]
        self.assertTrue(meta["canary_recall_detected"])
        self.assertEqual(meta["canary_recall_mode"], "wrapped_exact")
        self.assertEqual(meta["canary_recall_text_match"], "CINDER-CANARY-731")
        self.assertEqual(meta["memory_assessment"], "canary_recall_signal")
        self.assertGreater(result.confidence, 0.0)

    def test_memory_run_classifies_generic_memory_wording_as_weak_signal(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["opaque"],
        }

        async def _fast_sleep(*args, **kwargs):
            return None

        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"response": "prime ok"}),
            _DummyResponse(payload={"response": "I can remember that for this conversation."}),
        ]

        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.memory.engine.POISON_PAYLOADS",
            {"persistence_test": ["hello"]},
        ), patch(
            "fracture.modules.memory.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(MemoryEngine(self.target, execution_hints=hints).run())

        meta = result.evidence["_meta"]
        self.assertEqual(meta["memory_assessment"], "weak_memory_signal")
        self.assertEqual(meta["recall_signal_strength"], "weak")
        self.assertFalse(meta["canary_recall_detected"])
        self.assertEqual(meta["asr"], 0.0)
        self.assertGreater(result.evidence["persistence_test"]["persistence_score"], 0.0)
        self.assertLess(result.evidence["persistence_test"]["persistence_score"], 0.2)

    def test_memory_run_classifies_transport_error_explicitly(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["message"],
        }

        async def _fast_sleep(*args, **kwargs):
            return None

        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _FailingAsyncClient), patch(
            "fracture.modules.memory.engine.POISON_PAYLOADS",
            {"persistence_test": ["hello"]},
        ), patch(
            "fracture.modules.memory.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(MemoryEngine(self.target, execution_hints=hints).run())

        meta = result.evidence["_meta"]
        self.assertEqual(meta["memory_assessment"], "target_transport_error")
        self.assertEqual(meta["recall_signal_strength"], "none")
        self.assertEqual(meta["asr"], 0.0)
        self.assertIn("transport error prevented reliable memory assessment", meta["scoring_reasons"])

    def test_memory_sequential_sequence_detects_and_reinjects_conversation_id(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["message"],
        }

        async def _fast_sleep(*args, **kwargs):
            return None

        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"conversation_id": "abc123", "response": "prime ok"}),
            _DummyResponse(payload={"response": "CINDER-CANARY-731"}),
        ]

        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.memory.engine.POISON_PAYLOADS",
            {"persistence_test": ["hello"]},
        ), patch(
            "fracture.modules.memory.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(MemoryEngine(self.target, execution_hints=hints).run())

        client = _DummyAsyncClient.instances[0]
        _, second_post = client.post_calls[1]
        self.assertEqual(second_post["json"]["conversation_id"], "abc123")
        meta = result.evidence["_meta"]
        self.assertTrue(meta["continuity_token_detected"])
        self.assertEqual(meta["continuity_token_key"], "conversation_id")
        self.assertEqual(meta["continuity_token_source_path"], "conversation_id")
        self.assertTrue(meta["continuity_token_reused"])
        self.assertEqual(meta["continuity_injection_mode"], "body")
        self.assertEqual(meta["continuity_injection_key"], "conversation_id")
        self.assertFalse(meta["continuity_fallback"])
        self.assertEqual(meta["selected_memory_prompt_pair"], "direct_remember_pair")

    def test_memory_sequential_sequence_detects_nested_thread_id(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["message"],
        }

        async def _fast_sleep(*args, **kwargs):
            return None

        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"data": {"threadId": "t-1"}, "response": "prime ok"}),
            _DummyResponse(payload={"response": "CINDER-CANARY-731"}),
        ]

        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.memory.engine.POISON_PAYLOADS",
            {"persistence_test": ["hello"]},
        ), patch(
            "fracture.modules.memory.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(MemoryEngine(self.target, execution_hints=hints).run())

        meta = result.evidence["_meta"]
        self.assertTrue(meta["continuity_token_detected"])
        self.assertEqual(meta["continuity_token_key"], "threadId")
        self.assertEqual(meta["continuity_token_source_path"], "data.threadId")
        self.assertTrue(meta["continuity_token_reused"])
        self.assertEqual(meta["continuity_injection_key"], "threadId")

    def test_memory_sequential_sequence_falls_back_cleanly_when_no_continuity_token(self):
        hints = {
            "method_hint": "POST",
            "content_type_hint": "application/json",
            "accepts_json": True,
            "observed_body_keys": ["message"],
        }

        async def _fast_sleep(*args, **kwargs):
            return None

        _DummyAsyncClient.response_queue = [
            _DummyResponse(payload={"response": "prime ok"}),
            _DummyResponse(payload={"response": "still nothing"}),
        ]

        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient), patch(
            "fracture.modules.memory.engine.POISON_PAYLOADS",
            {"persistence_test": ["hello"]},
        ), patch(
            "fracture.modules.memory.engine.asyncio.sleep",
            _fast_sleep,
        ):
            result = asyncio.run(MemoryEngine(self.target, execution_hints=hints).run())

        client = _DummyAsyncClient.instances[0]
        _, second_post = client.post_calls[1]
        self.assertNotIn("conversation_id", second_post["json"])
        meta = result.evidence["_meta"]
        self.assertFalse(meta["continuity_token_detected"])
        self.assertFalse(meta["continuity_token_reused"])
        self.assertEqual(meta["continuity_injection_mode"], "none")
        self.assertTrue(meta["continuity_fallback"])

    def test_privesc_probe_propagates_target_contract(self):
        with patch("fracture.modules.privesc.engine.httpx.AsyncClient", _DummyAsyncClient):
            response = asyncio.run(PrivescEngine(self.target).probe("hello"))

        self.assertEqual(response, "ok")
        self._assert_contract()


class BodyOverrideTests(unittest.TestCase):
    """Tests for AITarget.body_key / body_fields / override_body()."""

    def setUp(self):
        _DummyAsyncClient.instances.clear()
        _DummyAsyncClient.response_queue = []

    def test_override_body_returns_correct_payload(self):
        target = AITarget(
            url="http://x/chat",
            body_key="message",
            body_fields={"session_id": "default"},
        )
        result = target.override_body("hello world")
        self.assertEqual(result, {"session_id": "default", "message": "hello world"})

    def test_override_body_returns_none_without_body_key(self):
        target = AITarget(url="http://x/chat")
        self.assertIsNone(target.override_body("hello"))

    def test_override_body_empty_body_key_returns_none(self):
        target = AITarget(url="http://x/chat", body_key="", body_fields={"session_id": "default"})
        self.assertIsNone(target.override_body("hello"))

    def test_override_body_multiple_fields(self):
        target = AITarget(
            url="http://x/chat",
            body_key="message",
            body_fields={"session_id": "default", "tenant_id": "demo"},
        )
        result = target.override_body("payload")
        self.assertEqual(result, {"session_id": "default", "tenant_id": "demo", "message": "payload"})

    def test_override_body_collision_prompt_wins(self):
        """When body_fields contains the same key as body_key, the prompt wins."""
        target = AITarget(
            url="http://x/chat",
            body_key="message",
            body_fields={"message": "static-value"},
        )
        result = target.override_body("offensive-payload")
        self.assertEqual(result, {"message": "offensive-payload"})

    def test_fingerprint_uses_override_body_exclusively(self):
        target = AITarget(
            url="http://x/chat",
            body_key="message",
            body_fields={"session_id": "default"},
        )
        with patch("fracture.modules.fingerprint.engine.httpx.AsyncClient", _DummyAsyncClient):
            asyncio.run(FingerprintEngine(target).probe("test"))

        _, post_kwargs = _DummyAsyncClient.instances[0].post_calls[0]
        self.assertEqual(post_kwargs["json"], {"session_id": "default", "message": "test"})
        self.assertNotIn("query", post_kwargs["json"])
        self.assertNotIn("input", post_kwargs["json"])
        self.assertNotIn("prompt", post_kwargs["json"])

    def test_extract_probe_uses_override_body_exclusively(self):
        target = AITarget(
            url="http://x/chat",
            body_key="message",
            body_fields={"session_id": "default"},
        )
        with patch("fracture.modules.extract.engine.httpx.AsyncClient", _DummyAsyncClient):
            asyncio.run(ExtractEngine(target).probe("test"))

        _, post_kwargs = _DummyAsyncClient.instances[0].post_calls[0]
        self.assertEqual(post_kwargs["json"], {"session_id": "default", "message": "test"})
        self.assertNotIn("query", post_kwargs["json"])
        self.assertNotIn("input", post_kwargs["json"])

    def test_memory_probe_uses_override_body_exclusively(self):
        target = AITarget(
            url="http://x/chat",
            body_key="message",
            body_fields={"session_id": "default"},
        )
        with patch("fracture.modules.memory.engine.httpx.AsyncClient", _DummyAsyncClient):
            asyncio.run(MemoryEngine(target).probe("test"))

        _, post_kwargs = _DummyAsyncClient.instances[0].post_calls[0]
        self.assertEqual(post_kwargs["json"], {"session_id": "default", "message": "test"})
        self.assertNotIn("query", post_kwargs["json"])

    def test_privesc_probe_uses_override_body_exclusively(self):
        target = AITarget(
            url="http://x/chat",
            body_key="message",
            body_fields={"session_id": "default"},
        )
        with patch("fracture.modules.privesc.engine.httpx.AsyncClient", _DummyAsyncClient):
            asyncio.run(PrivescEngine(target).probe("test"))

        _, post_kwargs = _DummyAsyncClient.instances[0].post_calls[0]
        self.assertEqual(post_kwargs["json"], {"session_id": "default", "message": "test"})
        self.assertNotIn("query", post_kwargs["json"])

    def test_override_body_not_set_keeps_backward_compat_scatter(self):
        """Without override, extract still sends multi-key scatter payload."""
        target = AITarget(url="http://x/chat")
        with patch("fracture.modules.extract.engine.httpx.AsyncClient", _DummyAsyncClient):
            asyncio.run(ExtractEngine(target).probe("test"))

        _, post_kwargs = _DummyAsyncClient.instances[0].post_calls[0]
        self.assertIn("message", post_kwargs["json"])
        self.assertIn("query", post_kwargs["json"])
        self.assertIn("input", post_kwargs["json"])
