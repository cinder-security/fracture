from rich.console import Console
from rich.panel import Panel

from fracture.agents.recon import ReconAgent
from fracture.agents.strategy import StrategyAgent
from fracture.agents.execution import ExecutionAgent
from fracture.agents.report import ReportAgent


def _auth_material_summary(target) -> str:
    headers = getattr(target, "headers", {}) or {}
    cookies = getattr(target, "cookies", {}) or {}
    parts = []
    if headers:
        parts.append("headers")
    if cookies:
        parts.append("cookies")
    return ", ".join(parts) if parts else "none"


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

    async def scan(self, discovery_mode: str = "passive") -> dict:
        self.console.print("\n[bold red]FRACTURE-CORE — Scan Mode[/bold red]")

        self.console.print("[dim]Phase 1: ReconAgent (fingerprint)...[/dim]")
        fingerprint = await self.recon.run(discovery_mode=discovery_mode)

        self.console.print(
            f"[dim]Phase 2: StrategyAgent (triage planning, planner={self.planner})...[/dim]"
        )
        plan = await self.strategy.run(fingerprint_evidence=fingerprint.evidence)

        return {
            "fingerprint": fingerprint,
            "plan": plan,
        }

    async def attack(self, attack_plan: list[str], **kwargs) -> dict:
        self.console.print("\n[bold red]FRACTURE-CORE — Attack Mode[/bold red]")

        attack_results = await self.execution.run(
            attack_plan=attack_plan,
            **kwargs,
        )

        return {
            "attacks": attack_results,
        }

    async def run(self, output_path: str = None) -> dict:
        self.console.print("\n[bold red]FRACTURE-CORE — Autonomous Mode[/bold red]")

        self.console.print("[dim]Phase 1: ReconAgent (fingerprint)...[/dim]")
        fingerprint = await self.recon.run()

        self.console.print(
            f"[dim]Phase 2: StrategyAgent (attack planning, planner={self.planner})...[/dim]"
        )
        plan = await self.strategy.run(fingerprint_evidence=fingerprint.evidence)

        plan_str = " -> ".join(plan.get("attack_plan", [])) or "none"
        planning_signals = ", ".join(plan.get("planning_signals_used", [])[:4]) or "none"
        constraints = "; ".join(plan.get("surface_constraints", [])[:2]) or "none"
        auth_material = _auth_material_summary(self.target)
        limitations = "; ".join(plan.get("operational_limitations", [])[:2]) or constraints
        self.console.print(Panel(
            "[bold]Analysis:[/bold] " + str(plan.get("analysis", "")) + "\n" +
            "[bold]Risk:[/bold]     [red]" + str(plan.get("risk_level", "unknown")) + "[/red]\n" +
            "[bold]Model:[/bold]    [cyan]" + str(plan.get("detected_model", "unknown")) + "[/cyan]\n" +
            "[bold]Plan:[/bold]     [green]" + plan_str + "[/green]\n" +
            "[bold]Signals:[/bold]  [dim]" + planning_signals + "[/dim]\n" +
            "[bold]Constraints:[/bold] [dim]" + constraints + "[/dim]\n" +
            "[bold]Manual Auth:[/bold] [dim]" + auth_material + "[/dim]\n" +
            "[bold]Coverage:[/bold] [dim]" + limitations + "[/dim]\n" +
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
