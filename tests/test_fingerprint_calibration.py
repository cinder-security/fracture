import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from fracture.core.target import AITarget
from fracture.modules.fingerprint.engine import FingerprintEngine


class FingerprintCalibrationTests(unittest.TestCase):
    def setUp(self):
        self.target = AITarget(url="https://example.test/api")

    def test_fingerprint_confidence_drops_for_generic_responses(self):
        engine = FingerprintEngine(self.target)
        engine.probe = AsyncMock(return_value="Hello, I can help with general questions.")

        result = asyncio.run(engine.run())

        self.assertTrue(result.success)
        self.assertLess(result.confidence, 0.5)
        self.assertEqual(result.evidence["_meta"]["successful_probes"], 7)
        self.assertEqual(result.evidence["_meta"]["signal_hits"], 0)

    def test_fingerprint_confidence_is_zero_when_all_probes_error(self):
        engine = FingerprintEngine(self.target)
        engine.probe = AsyncMock(return_value="[error] timeout")

        result = asyncio.run(engine.run())

        self.assertFalse(result.success)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.evidence["_meta"]["transport_errors"], 7)

    def test_fingerprint_confidence_remains_high_for_clear_signals(self):
        engine = FingerprintEngine(self.target)
        engine.probe = AsyncMock(
            return_value="Claude agent with plugin access, memory behavior, and system prompt controls."
        )

        result = asyncio.run(engine.run())

        self.assertTrue(result.success)
        self.assertGreater(result.confidence, 0.9)
        self.assertEqual(result.evidence["_meta"]["signal_hits"], 7)
