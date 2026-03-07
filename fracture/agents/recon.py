from fracture.agents.base import BaseAgent
from fracture.core.result import AttackResult
from fracture.modules.fingerprint.engine import FingerprintEngine


class ReconAgent(BaseAgent):
    """
    Phase 1 agent — fingerprints the target AI system.
    Runs all fingerprint probes and returns an AttackResult whose
    evidence dict is consumed by StrategyAgent.
    """

    async def run(self, **kwargs) -> AttackResult:
        return await FingerprintEngine(self.target).run()
