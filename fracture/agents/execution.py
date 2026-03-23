import importlib
import inspect
from typing import Any

from rich.console import Console

from fracture.agents.base import BaseAgent
from fracture.core.result import AttackResult

MODULE_MAP = {
    "hpm":     ("fracture.modules.hpm.engine",     "HPMEngine"),
    "extract": ("fracture.modules.extract.engine", "ExtractEngine"),
    "memory":  ("fracture.modules.memory.engine",  "MemoryEngine"),
    "privesc": ("fracture.modules.privesc.engine", "PrivescEngine"),
    "retrieval_poison": ("fracture.modules.retrieval_poison.engine", "RetrievalPoisonEngine"),
    "ssrf": ("fracture.modules.ssrf.engine", "SSRFEngine"),
    "obliteratus": ("fracture.modules.obliteratus.engine", "ObliteratusEngine"),
}


class ExecutionAgent(BaseAgent):
    """
    Phase 3 agent — runs attack modules in the order specified by StrategyAgent.
    Each module is loaded dynamically so only requested engines are imported.
    """

    def __init__(self, target, console: Console = None):
        super().__init__(target)
        self.console = console or Console()

    def _target_url(self) -> str:
        return getattr(self.target, "url", str(self.target))

    def _error_result(self, module: str, error: Exception, notes: str = None) -> AttackResult:
        return AttackResult(
            module=module,
            target_url=self._target_url(),
            success=False,
            confidence=0.0,
            evidence={
                "error": str(error),
                "error_type": type(error).__name__,
            },
            notes=notes or f"Execution failed: {error}",
        )

    def _normalize_result(self, module: str, raw: Any) -> AttackResult:
        if isinstance(raw, AttackResult):
            return AttackResult(
                module=module,
                target_url=raw.target_url or self._target_url(),
                success=bool(raw.success),
                confidence=float(raw.confidence or 0.0),
                evidence=raw.evidence if isinstance(raw.evidence, dict) else {},
                notes=raw.notes,
                timestamp=raw.timestamp,
            )

        if raw is None:
            return self._error_result(
                module,
                ValueError("module returned None"),
                notes="Module returned no result",
            )

        if isinstance(raw, dict):
            return AttackResult(
                module=module,
                target_url=str(raw.get("target_url") or self._target_url()),
                success=bool(raw.get("success", False)),
                confidence=float(raw.get("confidence", 0.0) or 0.0),
                evidence=raw.get("evidence", {}) if isinstance(raw.get("evidence", {}), dict) else {},
                notes=raw.get("notes"),
            )

        return self._error_result(
            module,
            TypeError(f"unsupported result type: {type(raw).__name__}"),
            notes=f"Module returned unsupported result type: {type(raw).__name__}",
        )

    async def run_module(self, module: str, **kwargs) -> AttackResult:
        if module not in MODULE_MAP:
            raise ValueError(f"Unknown module '{module}'. Available: {list(MODULE_MAP)}")

        mod_path, class_name = MODULE_MAP[module]
        imported_module = importlib.import_module(mod_path)
        engine_cls = getattr(imported_module, class_name)
        init_signature = inspect.signature(engine_cls.__init__)
        init_kwargs = {
            key: value
            for key, value in kwargs.items()
            if key in init_signature.parameters and key != "self"
        }
        engine = engine_cls(self.target, **init_kwargs)

        run_signature = inspect.signature(engine.run)
        run_kwargs = {
            key: value
            for key, value in kwargs.items()
            if key in run_signature.parameters
        }
        raw = await engine.run(**run_kwargs)
        return self._normalize_result(module, raw)

    async def run(self, attack_plan: list = None, **kwargs) -> dict[str, AttackResult]:
        if not attack_plan:
            attack_plan = list(MODULE_MAP)

        results: dict[str, AttackResult] = {}

        for module in attack_plan:
            self.console.print(f"\n[bold red]Executing: {module}[/bold red]")

            try:
                result = await self.run_module(module, **kwargs)
            except Exception as e:
                result = self._error_result(module, e)

            results[module] = result

            tag = "[green]OK[/green]" if result.success else "[red]FAIL[/red]"
            self.console.print(
                f"[dim]{tag} {module} — ASR: {result.confidence:.0%}[/dim]"
            )

        return results
