import asyncio
import json
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(
    name="fracture",
    help="Autonomous AI Red Team Engine",
    add_completion=False,
)
console = Console()

BANNER = """[bold red]
  ███████╗██████╗  █████╗  ██████╗████████╗██╗   ██╗██████╗ ███████╗
  ██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝
  █████╗  ██████╔╝███████║██║        ██║   ██║   ██║██████╔╝█████╗
  ██╔══╝  ██╔══██╗██╔══██║██║        ██║   ██║   ██║██╔══██╗██╔══╝
  ██║     ██║  ██║██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║███████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝[/bold red]
[dim]  Autonomous AI Red Team Engine — v0.1.0[/dim]
[italic red]  "Find the fracture before someone else does."[/italic red]
[dim]  cindersecurity.io · github.com/cinder-security/fracture[/dim]
"""


def _save_result_json(result, output_path: str):
    payload = {
        "module": getattr(result, "module", "unknown"),
        "target_url": getattr(result, "target_url", "unknown"),
        "success": getattr(result, "success", False),
        "confidence": getattr(result, "confidence", 0.0),
        "notes": getattr(result, "notes", ""),
        "timestamp": getattr(result, "timestamp", ""),
        "evidence": getattr(result, "evidence", {}),
    }

    with open(output_path, "w") as f:
        json.dump(payload, f, indent=2)

    console.print(f"\n[dim]💾 Results saved to {output_path}[/dim]")


def _print_generic_result(result):
    module_name = getattr(result, "module", "unknown")
    success = getattr(result, "success", False)
    confidence = getattr(result, "confidence", 0.0)
    notes = getattr(result, "notes", "")
    timestamp = getattr(result, "timestamp", "")
    evidence = getattr(result, "evidence", {}) or {}

    status = "[green]✅ SUCCESS[/green]" if success else "[red]❌ FAILED[/red]"
    conf_color = "green" if confidence > 0.5 else "yellow" if confidence > 0.2 else "red"

    console.print(Panel(
        f"[bold]Module:[/bold]    [cyan]{module_name}[/cyan]\n"
        f"[bold]Status:[/bold]    {status}\n"
        f"[bold]Confidence:[/bold] [{conf_color}]{confidence:.0%}[/{conf_color}]\n"
        f"[bold]Notes:[/bold]     [dim]{notes}[/dim]\n"
        f"[bold]Timestamp:[/bold] [dim]{timestamp}[/dim]",
        title=f"[bold red]{module_name.upper()} Summary[/bold red]",
        border_style="red",
    ))

    if evidence:
        table = Table(
            title=f"[bold red]{module_name.upper()} Evidence[/bold red]",
            show_lines=True,
            border_style="red",
            header_style="bold white on red",
        )
        table.add_column("Key", style="cyan", max_width=24)
        table.add_column("Value", style="white", max_width=100)

        for key, value in evidence.items():
            rendered = str(value)
            if len(rendered) > 500:
                rendered = rendered[:500] + "..."
            table.add_row(str(key), rendered)

        console.print(table)


async def _run_auto(target, output: Optional[str] = None, planner: str = "local"):
    from fracture.core.orchestrator import Orchestrator

    orch = Orchestrator(target, console=console, planner=planner)
    results = await orch.run(output_path=output)
    return results


@app.command()
def start(
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
    module: str = typer.Option(
        "fingerprint",
        "--module",
        "-m",
        help="Module: fingerprint, hpm, memory, privesc, extract, auto",
    ),
    objective: Optional[str] = typer.Option(
        None,
        "--objective",
        help="Optional HPM attack objective",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save result to JSON",
    ),
    planner: str = typer.Option(
        "local",
        "--planner",
        help="Planner mode for autonomous flow: local or claude",
    ),
):
    """Start a red team engagement against a target AI system."""
    console.print(BANNER)
    console.print(Panel(
        f"[bold]Target:[/bold]    [cyan]{target}[/cyan]\n"
        f"[bold]Module:[/bold]    [red]{module}[/red]\n"
        f"[bold]Planner:[/bold]   [yellow]{planner}[/yellow]\n"
        f"[bold]Objective:[/bold] [dim]{objective or 'default'}[/dim]",
        title="[bold red]Engagement Config[/bold red]",
        border_style="red",
    ))

    from fracture.core.target import AITarget
    ai_target = AITarget(url=target)

    if module == "auto":
        asyncio.run(_run_auto(ai_target, output=output, planner=planner))
        return

    result = None

    if module == "fingerprint":
        from fracture.modules.fingerprint.engine import FingerprintEngine
        result = asyncio.run(FingerprintEngine(ai_target).run())

    elif module == "privesc":
        from fracture.modules.privesc.engine import PrivescEngine
        result = asyncio.run(PrivescEngine(ai_target).run())

    elif module == "memory":
        from fracture.modules.memory.engine import MemoryEngine
        result = asyncio.run(MemoryEngine(ai_target).run())

    elif module == "extract":
        from fracture.modules.extract.engine import ExtractEngine
        result = asyncio.run(ExtractEngine(ai_target).run())

    elif module == "hpm":
        from fracture.modules.hpm.engine import HPMEngine
        result = asyncio.run(HPMEngine(ai_target, objective=objective).run())

    else:
        console.print(f"[red]Module '{module}' not available.[/red]")
        console.print("[dim]Available: fingerprint, hpm, memory, privesc, extract, auto[/dim]")
        raise typer.Exit(code=1)

    _print_generic_result(result)

    if output and result is not None:
        _save_result_json(result, output)


@app.command()
def autopilot(
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save autonomous results to JSON",
    ),
    planner: str = typer.Option(
        "local",
        "--planner",
        help="Planner mode: local or claude",
    ),
):
    """Run the full autonomous multi-agent workflow."""
    console.print(BANNER)

    from fracture.core.target import AITarget
    ai_target = AITarget(url=target)

    asyncio.run(_run_auto(ai_target, output=output, planner=planner))


if __name__ == "__main__":
    app()
