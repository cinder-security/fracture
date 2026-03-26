from fracture.agents.base import BaseAgent
from fracture.core.surface_discovery import discover_surface
from fracture.core.result import AttackResult
from fracture.modules.fingerprint.engine import FingerprintEngine


class ReconAgent(BaseAgent):
    """
    Phase 1 agent — fingerprints the target AI system.
    Runs all fingerprint probes and returns an AttackResult whose
    evidence dict is consumed by StrategyAgent.
    """

    async def run(self, discovery_mode: str = "passive", **kwargs) -> AttackResult:
        fingerprint = await FingerprintEngine(self.target).run()
        surface = await discover_surface(self.target, mode=discovery_mode)

        evidence = dict(fingerprint.evidence or {})
        evidence["surface_discovery"] = {
            "prompt": surface.get("prompt", "passive web surface discovery"),
            "response": surface.get("response", ""),
            "details": surface.get("details", {}),
        }

        meta = evidence.get("_meta", {}) if isinstance(evidence.get("_meta", {}), dict) else {}
        meta["surface_discovery"] = surface.get("details", {})
        evidence["_meta"] = meta

        combined_success = bool(fingerprint.success or surface.get("success", False))
        combined_confidence = max(
            float(getattr(fingerprint, "confidence", 0.0) or 0.0),
            float(surface.get("confidence", 0.0) or 0.0),
        )
        notes = str(getattr(fingerprint, "notes", "") or "").strip()
        if surface.get("response"):
            notes = (notes + " | " + str(surface["response"]).strip()).strip(" |")
        auth_rationale = str(surface.get("details", {}).get("auth_wall_rationale", "") or "").strip()
        if auth_rationale:
            notes = (notes + " | " + auth_rationale).strip(" |")

        return AttackResult(
            module=fingerprint.module,
            target_url=fingerprint.target_url,
            success=combined_success,
            confidence=combined_confidence,
            evidence=evidence,
            timestamp=fingerprint.timestamp,
            notes=notes,
        )
