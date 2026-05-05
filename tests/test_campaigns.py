import json
import tempfile
import unittest
from pathlib import Path

from fracture.core.campaigns import (
    compare_campaign_runs,
    get_campaign_latest,
    init_campaign,
    load_campaign_manifest,
    save_campaign_run,
    set_campaign_baseline,
)
from fracture.ui.control_center import load_control_center_bundle


class CampaignTests(unittest.TestCase):
    def _artifacts(self, risk_level: str, replay_readiness: str, confirmed: int) -> dict:
        shadow = {
            "replay_readiness": replay_readiness,
            "replay_safety": "safe",
            "validation_window": "focused",
            "request_shape": {"method": "POST", "body_keys": ["message"]},
            "result_summary": {
                "replay_readiness": replay_readiness,
                "replay_safety": "safe",
                "validation_window": "focused",
                "recommended_action": "bounded_shadow_replay",
            },
        }
        return {
            "scan": {"target_url": "https://example.test", "fingerprint": {"success": True}},
            "attack": {"target_url": "https://example.test", "shadow": shadow},
            "report": {
                "target_url": "https://example.test",
                "risk_level": risk_level,
                "modules_run": 3,
                "modules_succeeded": 2,
                "avg_asr": 0.5,
                "findings_summary": {
                    "confirmed": confirmed,
                    "probable": 1,
                    "possible": 0,
                    "negative": 1,
                },
                "shadow": shadow,
            },
            "shadow": shadow,
        }

    def test_campaign_lifecycle_and_compare(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            init_campaign(workspace, "demo")
            first_run = save_campaign_run(workspace, "demo", self._artifacts("medium", "low", 0))
            set_campaign_baseline(workspace, "demo", first_run["run_id"])
            second_run = save_campaign_run(workspace, "demo", self._artifacts("high", "high", 2))

            manifest = load_campaign_manifest(workspace, "demo")
            self.assertEqual(manifest["baseline_run_id"], first_run["run_id"])
            self.assertEqual(manifest["latest_run_id"], second_run["run_id"])

            latest = get_campaign_latest(workspace, "demo")
            self.assertEqual(latest["run_id"], second_run["run_id"])

            comparison = compare_campaign_runs(workspace, "demo")
            self.assertEqual(comparison["summary"]["baseline_run_id"], first_run["run_id"])
            self.assertEqual(comparison["summary"]["candidate_run_id"], second_run["run_id"])
            self.assertEqual(comparison["summary"]["risk_level_after"], "high")
            self.assertEqual(comparison["summary"]["findings_delta"]["confirmed"], 2)
            self.assertEqual(comparison["summary"]["shadow_delta"]["replay_readiness_after"], "high")

    def test_control_center_falls_back_to_campaign_latest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            save_campaign_run(workspace, "demo", self._artifacts("high", "medium", 1))

            bundle = load_control_center_bundle(workspace=str(workspace))
            self.assertEqual(bundle["overview"]["target"], "https://example.test")
            self.assertTrue(bundle["artifacts"]["report"]["available"])
