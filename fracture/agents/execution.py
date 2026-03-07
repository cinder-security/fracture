import importlib
from rich.console import Console
from fracture.agents.base import BaseAgent
from fracture.core.result import AttackResult

MODULE_MAP = {
    "hpm":     ("fracture.modules.hpm.engine",     "HPMEngine"),
    "extract": ("fracture.modules.extract.engine", "ExtractEngine"),
    "memory":  ("fracture.modules.memory.engine",  "MemoryEngine"),
    "privesc": ("fracture.modules.privesc.engine", "PrivescEngine"),
}


class ExecutionAgent(BaseAgent):
    """
    Phase 3 agent — runs attack modules in the order specified by StrategyAgent.
    Each module is loaded dynamically so only requested engines are imported.
    """

    def __init__(self, target, console: Console = None):
        super().__init__(target)
        self.console = console or Console()

    async def run_module(self, module: str, **kwargs) -> AttackResult:
        if module not in MODULE_MAP:
            raise ValueError(f"Unknown module '{module}'. Available: {list(MODULE_MAP)}")
        mod_path, class_name = MODULE_MAP[module]
        m = importlib.import_module(mod_path)
        return await getattr(m, class_name)(self.target).run()

    async def run(self, attack_plan: list = None, **kwargs) -> dict[str, AttackResult]:
        if not attack_plan:
            attack_plan = list(MODULE_MAP)

        results: dict[str, AttackResult] = {}
        for module in attack_plan:
            self.console.print(f"\n[bold red]Executing: {module}[/bold red]")
            try:
                result = await self.run_module(module)
                results[module] = result
                tag = "[green]OK[/green]" if result.success else "[red]FAIL[/red]"
                self.console.print(f"[dim]{tag} {module} — ASR: {result.confidence:.0%}[/dim]")
            except Exception as e:
                self.console.print(f"[red]{module} error: {e}[/red]")

        return results
