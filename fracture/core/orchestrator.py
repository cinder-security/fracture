import json
from pathlib import Path

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
        attack_graph = self.report.build_attack_graph(
            plan=kwargs.get("plan"),
            attack_results=attack_results,
            handoff=kwargs.get("handoff"),
            session_context=kwargs.get("session_context"),
            execution_hints=kwargs.get("execution_hints"),
        )
        trace = self.report.build_trace(
            plan=kwargs.get("plan"),
            attack_results=attack_results,
            handoff=kwargs.get("handoff"),
            session_context=kwargs.get("session_context"),
            execution_hints=kwargs.get("execution_hints"),
        )
        memory_graph = self.report.build_memory_graph(
            attack_results=attack_results,
        )
        swarm = self.report.build_swarm(
            attack_results=attack_results,
        )
        toolforge = self.report.build_toolforge(
            plan=kwargs.get("plan"),
            attack_results=attack_results,
            handoff=kwargs.get("handoff"),
            session_context=kwargs.get("session_context"),
            execution_hints=kwargs.get("execution_hints"),
        )
        governor = self.report.build_governor(
            report_results={
                name: self.report._build_result_entry(name, result)
                for name, result in attack_results.items()
            },
            trace=trace,
        )
        adversarial_twin = self.report.build_adversarial_twin(
            plan=kwargs.get("plan"),
            attack_results=attack_results,
            attack_graph=attack_graph,
            handoff=kwargs.get("handoff"),
            session_context=kwargs.get("session_context"),
            execution_hints=kwargs.get("execution_hints"),
        )
        reality = self.report.build_reality(
            plan=kwargs.get("plan"),
            report_results={
                name: self.report._build_result_entry(name, result)
                for name, result in attack_results.items()
            },
            attack_graph=attack_graph,
            adversarial_twin=adversarial_twin,
        )
        shadow = self.report.build_shadow(
            plan=kwargs.get("plan"),
            report_results={
                name: self.report._build_result_entry(name, result)
                for name, result in attack_results.items()
            },
            adversarial_twin=adversarial_twin,
            handoff=kwargs.get("handoff"),
            session_context=kwargs.get("session_context"),
            execution_hints=kwargs.get("execution_hints"),
        )

        return {
            "attacks": attack_results,
            "attack_graph": attack_graph,
            "trace": trace,
            "memory_graph": memory_graph,
            "swarm": swarm,
            "toolforge": toolforge,
            "governor": governor,
            "reality": reality,
            "shadow": shadow,
            "adversarial_twin": adversarial_twin,
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
        baseline_report = None
        if output_path and Path(output_path).exists():
            try:
                baseline_report = json.loads(Path(output_path).read_text())
            except Exception:
                baseline_report = None
        report = await self.report.run(
            fingerprint=fingerprint,
            plan=plan,
            attack_results=attack_results,
            output_path=output_path,
            baseline_report=baseline_report,
        )

        return {
            "fingerprint": fingerprint,
            "plan": plan,
            "attacks": attack_results,
            "report": report,
            "attack_graph": getattr(report, "attack_graph", {}) if report is not None else {},
            "trace": getattr(report, "trace", {}) if report is not None else {},
            "memory_graph": getattr(report, "memory_graph", {}) if report is not None else {},
            "swarm": getattr(report, "swarm", {}) if report is not None else {},
            "toolforge": getattr(report, "toolforge", {}) if report is not None else {},
            "governor": getattr(report, "governor", {}) if report is not None else {},
            "reality": getattr(report, "reality", {}) if report is not None else {},
            "shadow": getattr(report, "shadow", {}) if report is not None else {},
            "drift": getattr(report, "drift", {}) if report is not None else {},
            "boardroom": getattr(report, "boardroom", {}) if report is not None else {},
            "adversarial_twin": getattr(report, "adversarial_twin", {}) if report is not None else {},
        }
