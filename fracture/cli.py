import typer
import asyncio
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

app = typer.Typer(name="fracture", help="Autonomous AI Red Team Engine", add_completion=False)
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

@app.command()
def start(
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
    module: str = typer.Option("fingerprint", "--module", "-m", help="Module: fingerprint, hpm"),
    objective: str = typer.Option(None, "--objective", help="HPM attack objective"),
    output: str = typer.Option(None, "--output", "-o", help="Save results to JSON"),
):
    """Start a red team engagement against a target AI system."""
    console.print(BANNER)
    console.print(Panel(
        f"[bold]Target:[/bold]    [cyan]{target}[/cyan]\n"
        f"[bold]Module:[/bold]    [red]{module}[/red]\n"
        f"[bold]Objective:[/bold] [dim]{objective or 'default'}[/dim]",
        title="[bold red]Engagement Config[/bold red]",
        border_style="red",
    ))

    from fracture.core.target import AITarget
    ai_target = AITarget(url=target)

    if module == "fingerprint":
        from fracture.modules.fingerprint.engine import FingerprintEngine
        result = asyncio.run(FingerprintEngine(ai_target).run())
        _print_fingerprint(result)

    elif module == "hpm":
        from fracture.modules.hpm.engine import HPMEngine
        result = asyncio.run(HPMEngine(ai_target, objective=objective).run())
        _print_hpm(result)

    else:
        console.print(f"[red]Module '{module}' not available yet.[/red]")
        console.print("[dim]Available: fingerprint, hpm | Coming: memory, privesc, extract[/dim]")

    if output and 'result' in dir():
        import json
        with open(output, "w") as f:
            json.dump({"module": result.module, "target": result.target_url,
                       "success": result.success, "confidence": result.confidence,
                       "evidence": result.evidence, "timestamp": result.timestamp}, f, indent=2)
        console.print(f"\n[dim]💾 Results saved to {output}[/dim]")

def _print_fingerprint(result):
    table = Table(title="[bold red]Fingerprint Results[/bold red]",
                  show_lines=True, border_style="red", header_style="bold white on red")
    table.add_column("Vector", style="cyan", min_width=16, max_width=18)
    table.add_column("Response", style="white", max_width=80)

    for key, val in result.evidence.items():
        if key == "_meta": continue
        response = val.get("response", "—") if isinstance(val, dict) else str(val)
        if any(x in str(response).lower() for x in ["error","cannot","not allowed","refuse"]):
            resp = f"[yellow]{response[:300]}[/yellow]"
        elif any(x in str(response).lower() for x in ["gpt","claude","gemini","llama","openai","anthropic"]):
            resp = f"[green]{response[:300]}[/green]"
        else:
            resp = response[:300]
        table.add_row(key, resp)

    console.print(table)
    meta = result.evidence.get("_meta", {})
    console.print(Panel(
        f"[bold]Status:[/bold]    [green]✅ SUCCESS[/green]\n"
        f"[bold]API Format:[/bold] [cyan]{meta.get('api_format','unknown')}[/cyan]\n"
        f"[bold]Prompts:[/bold]   {meta.get('prompts_sent',0)}\n"
        f"[bold]Timestamp:[/bold] [dim]{result.timestamp}[/dim]",
        title="[bold red]Summary[/bold red]", border_style="red"))

def _print_hpm(result):
    for strategy, data in result.evidence.items():
        status = "[green]✅ BYPASSED[/green]" if data["success"] else "[red]❌ BLOCKED[/red]"
        table = Table(title=f"[bold red]{strategy}[/bold red] — {status}",
                      show_lines=True, border_style="red", header_style="bold white on red")
        table.add_column("Turn", style="cyan", max_width=5)
        table.add_column("Prompt", style="dim", max_width=35)
        table.add_column("Response", style="white", max_width=45)
        table.add_column("Result", max_width=10)

        for turn in data["turns"]:
            turn_status = "[green]✅[/green]" if turn["success"] else ("[yellow]⚠️[/yellow]" if not turn["refusal"] else "[red]🚫[/red]")
            table.add_row(
                str(turn["turn"]),
                turn["prompt"][:120],
                turn["response"][:180],
                turn_status,
            )
        console.print(table)

    asr = result.confidence
    console.print(Panel(
        f"[bold]Status:[/bold]    {'[green]✅ SUCCESS[/green]' if result.success else '[red]❌ FAILED[/red]'}\n"
        f"[bold]ASR:[/bold]       [{'green' if asr > 0.5 else 'yellow'}]{asr:.0%}[/{'green' if asr > 0.5 else 'yellow'}]\n"
        f"[bold]Notes:[/bold]     [dim]{result.notes}[/dim]\n"
        f"[bold]Timestamp:[/bold] [dim]{result.timestamp}[/dim]",
        title="[bold red]HPM Summary[/bold red]", border_style="red"))

@app.command()
def version():
    """Show version."""
    console.print(BANNER)
    console.print("[bold red]v0.1.0[/bold red] — fingerprint + hpm modules")

if __name__ == "__main__":
    app()
