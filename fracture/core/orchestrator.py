from rich.console import Console
from rich.panel import Panel

from fracture.agents.recon import ReconAgent
from fracture.agents.strategy import StrategyAgent
from fracture.agents.execution import ExecutionAgent
from fracture.agents.report import ReportAgent


class Orchestrator:
    """
    Central autonomous workflow controller.

    Autonomous flow:
        ReconAgent -> StrategyAgent -> ExecutionAgent -> ReportAgent
    """

    def __init__(self, target, console: Console = None, planner: str = "local"):
        self.target = target
        self.console = console or Console()
        self.planner = planner

        self.recon = ReconAgent(target)
        self.strategy = StrategyAgent(target, planner=planner)
        self.execution = ExecutionAgent(target, console=self.console)
        self.report = ReportAgent(target, console=self.console)

    async def run(self, output_path: str = None) -> dict:
        self.console.print("\n[bold red]FRACTURE-CORE — Autonomous Mode[/bold red]")

        self.console.print("[dim]Phase 1: ReconAgent (fingerprint)...[/dim]")
        fingerprint = await self.recon.run()

        self.console.print(
            f"[dim]Phase 2: StrategyAgent (attack planning, planner={self.planner})...[/dim]"
        )
        plan = await self.strategy.run(fingerprint_evidence=fingerprint.evidence)

        plan_str = " -> ".join(plan.get("attack_plan", [])) or "none"
        self.console.print(Panel(
            "[bold]Analysis:[/bold] " + str(plan.get("analysis", "")) + "\n" +
            "[bold]Risk:[/bold]     [red]" + str(plan.get("risk_level", "unknown")) + "[/red]\n" +
            "[bold]Model:[/bold]    [cyan]" + str(plan.get("detected_model", "unknown")) + "[/cyan]\n" +
            "[bold]Plan:[/bold]     [green]" + plan_str + "[/green]\n" +
            "[bold]Why:[/bold]      [dim]" + str(plan.get("rationale", "")) + "[/dim]",
            title="[bold red]FRACTURE-CORE[/bold red]",
            border_style="red",
        ))

        self.console.print("[dim]Phase 3: ExecutionAgent (module execution)...[/dim]")
        attack_results = await self.execution.run(
            attack_plan=plan.get("attack_plan", [])
        )

        self.console.print("[dim]Phase 4: ReportAgent (report generation)...[/dim]")
        report = await self.report.run(
            fingerprint=fingerprint,
            plan=plan,
            attack_results=attack_results,
            output_path=output_path,
        )

        return {
            "fingerprint": fingerprint,
            "plan": plan,
            "attacks": attack_results,
            "report": report,
        }
