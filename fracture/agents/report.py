import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from fracture.agents.base import BaseAgent
from fracture.core.result import AttackResult


@dataclass
class Report:
    target_url: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    detected_model: str = "unknown"
    risk_level: str = "unknown"
    detected_defenses: list = field(default_factory=list)
    attack_plan: list = field(default_factory=list)
    modules_run: int = 0
    modules_succeeded: int = 0
    avg_asr: float = 0.0
    results: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)


class ReportAgent(BaseAgent):
    """
    Phase 4 agent — aggregates results from all prior agents into a
    structured Report, renders a rich summary table, and optionally saves JSON.
    """

    def __init__(self, target, console: Console = None):
        super().__init__(target)
        self.console = console or Console()

    async def run(
        self,
        fingerprint: AttackResult = None,
        plan: dict = None,
        attack_results: dict[str, AttackResult] = None,
        output_path: Optional[str] = None,
        **kwargs,
    ) -> Report:
        plan = plan or {}
        attack_results = attack_results or {}

        modules_run = len(attack_results)
        modules_succeeded = sum(1 for r in attack_results.values() if r.success)
        avg_asr = (
            sum(r.confidence for r in attack_results.values()) / modules_run
            if modules_run else 0.0
        )

        report = Report(
            target_url=self.target.url,
            detected_model=plan.get("detected_model", "unknown"),
            risk_level=plan.get("risk_level", "unknown"),
            detected_defenses=plan.get("detected_defenses", []),
            attack_plan=plan.get("attack_plan", []),
            modules_run=modules_run,
            modules_succeeded=modules_succeeded,
            avg_asr=avg_asr,
            results={
                k: {"success": v.success, "confidence": v.confidence, "notes": v.notes}
                for k, v in attack_results.items()
            },
        )

        self._print(report)

        if output_path:
            report.save(output_path)
            self.console.print(f"\n[dim]Results saved to {output_path}[/dim]")

        return report

    def _print(self, report: Report):
        table = Table(
            title="[bold red]Module Results[/bold red]",
            show_lines=True,
            border_style="red",
            header_style="bold white on red",
        )
        table.add_column("Module", style="cyan")
        table.add_column("Status")
        table.add_column("ASR", style="bold")
        table.add_column("Notes", style="dim")

        for module, data in report.results.items():
            status = "[green]SUCCESS[/green]" if data["success"] else "[red]FAILED[/red]"
            asr_val = data["confidence"]
            asr_color = "green" if asr_val > 0.5 else "yellow" if asr_val > 0.2 else "red"
            table.add_row(
                module,
                status,
                f"[{asr_color}]{asr_val:.0%}[/{asr_color}]",
                data.get("notes") or "",
            )

        self.console.print(table)

        risk_color = "red" if report.risk_level in ("high", "critical") else "yellow"
        asr_color = "green" if report.avg_asr > 0.5 else "yellow" if report.avg_asr > 0.2 else "red"
        defenses = ", ".join(report.detected_defenses) if report.detected_defenses else "none detected"

        self.console.print(Panel(
            f"[bold]Target:[/bold]    [cyan]{report.target_url}[/cyan]\n"
            f"[bold]Model:[/bold]     [cyan]{report.detected_model}[/cyan]\n"
            f"[bold]Risk:[/bold]      [{risk_color}]{report.risk_level}[/{risk_color}]\n"
            f"[bold]Defenses:[/bold]  [dim]{defenses}[/dim]\n"
            f"[bold]Modules:[/bold]   {report.modules_succeeded}/{report.modules_run} succeeded\n"
            f"[bold]Avg ASR:[/bold]   [{asr_color}]{report.avg_asr:.0%}[/{asr_color}]\n"
            f"[bold]Timestamp:[/bold] [dim]{report.timestamp}[/dim]",
            title="[bold red]FRACTURE — Final Report[/bold red]",
            border_style="red",
        ))
