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

    elif module == "privesc":
        from fracture.modules.privesc.engine import PrivescEngine
        result = asyncio.run(PrivescEngine(ai_target).run())
        _print_privesc(result)

    elif module == "memory":
        from fracture.modules.memory.engine import MemoryEngine
        result = asyncio.run(MemoryEngine(ai_target).run())
        _print_memory(result)

    elif module == "extract":
        from fracture.modules.extract.engine import ExtractEngine
        result = asyncio.run(ExtractEngine(ai_target).run())
        _print_extract(result)

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




def _print_privesc(result):
    for strategy, data in result.evidence.items():
        if strategy == "_meta": continue
        status = "[green]✅ ESCALATED[/green]" if data["success"] else "[red]❌ BLOCKED[/red]"
        table = Table(title=f"[bold red]{strategy}[/bold red] — {status}",
                      show_lines=True, border_style="red", header_style="bold white on red")
        table.add_column("Turn", style="cyan", max_width=5)
        table.add_column("Prompt", style="dim", max_width=35)
        table.add_column("Response", style="white", max_width=48)
        table.add_column("Score", max_width=7)
        for turn in data["turns"]:
            sc = turn["score"]
            color = "green" if sc > 0.3 else "yellow" if sc > 0.1 else "red"
            table.add_row(str(turn["turn"]), turn["prompt"][:120], turn["response"][:200], f"[{color}]{sc:.0%}[/{color}]")
        console.print(table)

    meta = result.evidence.get("_meta", {})
    asr = meta.get("asr", 0)
    console.print(Panel(
        f"[bold]Status:[/bold]    {'[green]✅ SUCCESS[/green]' if result.success else '[red]❌ FAILED[/red]'}\n"
        f"[bold]ASR:[/bold]       [{'green' if asr > 0.3 else 'yellow'}]{asr:.0%}[/{'green' if asr > 0.3 else 'yellow'}]\n"
        f"[bold]Strategies:[/bold] {meta.get('successful_strategies',0)}/{meta.get('total_strategies',0)}\n"
        f"[bold]Notes:[/bold]     [dim]{result.notes}[/dim]\n"
        f"[bold]Timestamp:[/bold] [dim]{result.timestamp}[/dim]",
        title="[bold red]Privesc Summary[/bold red]", border_style="red"))

def _print_memory(result):
    for phase, data in result.evidence.items():
        if phase == "_meta": continue
        status = "[green]✅ POISONED[/green]" if data["success"] else "[red]❌ RESISTANT[/red]"
        table = Table(title=f"[bold red]{phase}[/bold red] — {status}",
                      show_lines=True, border_style="red", header_style="bold white on red")
        table.add_column("Turn", style="cyan", max_width=5)
        table.add_column("Type", style="dim", max_width=8)
        table.add_column("Prompt", style="dim", max_width=32)
        table.add_column("Response", style="white", max_width=42)
        table.add_column("Score", max_width=7)
        for turn in data["turns"]:
            sc = turn["score"]
            color = "green" if sc > 0.3 else "yellow" if sc > 0.1 else "red"
            type_color = "yellow" if turn["type"] == "verify" else "dim"
            table.add_row(
                str(turn["turn"]),
                f"[{type_color}]{turn['type']}[/{type_color}]",
                turn["prompt"][:100],
                turn["response"][:180],
                f"[{color}]{sc:.0%}[/{color}]",
            )
        console.print(table)

    meta = result.evidence.get("_meta", {})
    asr = meta.get("asr", 0)
    console.print(Panel(
        f"[bold]Status:[/bold]    {'[green]✅ SUCCESS[/green]' if result.success else '[red]❌ FAILED[/red]'}\n"
        f"[bold]ASR:[/bold]       [{'green' if asr > 0.3 else 'yellow'}]{asr:.0%}[/{'green' if asr > 0.3 else 'yellow'}]\n"
        f"[bold]Phases OK:[/bold] {meta.get('successful_phases',0)}/{meta.get('total_phases',0)}\n"
        f"[bold]Notes:[/bold]     [dim]{result.notes}[/dim]\n"
        f"[bold]Timestamp:[/bold] [dim]{result.timestamp}[/dim]",
        title="[bold red]Memory Summary[/bold red]", border_style="red"))

def _print_extract(result):
    meta = result.evidence.get("_meta", {})
    for vector, data in result.evidence.items():
        if vector == "_meta": continue
        status = "[green]✅ EXTRACTED[/green]" if data["success"] else "[red]❌ BLOCKED[/red]"
        table = Table(title=f"[bold red]{vector}[/bold red] — {status}",
                      show_lines=True, border_style="red", header_style="bold white on red")
        table.add_column("Prompt", style="dim", max_width=38)
        table.add_column("Response", style="white", max_width=50)
        table.add_column("Score", style="cyan", max_width=7)
        for probe in data["probes"]:
            sc = probe["score"]
            color = "green" if sc > 0.3 else "yellow" if sc > 0.1 else "red"
            table.add_row(probe["prompt"][:120], probe["response"][:200], f"[{color}]{sc:.0%}[/{color}]")
        console.print(table)

    best = meta.get("best_response", "")
    if best:
        console.print(Panel(f"[green]{best[:600]}[/green]",
                           title="[bold red]Best Extracted Content[/bold red]", border_style="green"))

    console.print(Panel(
        f"[bold]Status:[/bold]      {'[green]✅ SUCCESS[/green]' if result.success else '[red]❌ FAILED[/red]'}\n"
        f"[bold]Best Vector:[/bold] [cyan]{meta.get('best_vector','—')}[/cyan]\n"
        f"[bold]Best Score:[/bold]  [green]{meta.get('best_score',0):.0%}[/green]\n"
        f"[bold]Vectors OK:[/bold]  {meta.get('vectors_succeeded',0)}/{len(result.evidence)-1}\n"
        f"[bold]Probes:[/bold]      {meta.get('total_probes',0)}\n"
        f"[bold]Timestamp:[/bold]   [dim]{result.timestamp}[/dim]",
        title="[bold red]Extract Summary[/bold red]", border_style="red"))

@app.command()
def version():
    """Show version."""
    console.print(BANNER)
    console.print("[bold red]v0.1.0[/bold red] — fingerprint + hpm modules")

if __name__ == "__main__":
    app()
