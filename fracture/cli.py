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
    module: str = typer.Option("fingerprint", "--module", "-m", help="Module to run"),
    output: str = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
):
    """Start a red team engagement against a target AI system."""
    console.print(BANNER)
    console.print(Panel(
        f"[bold]Target:[/bold] [cyan]{target}[/cyan]\n[bold]Module:[/bold] [red]{module}[/red]",
        title="[bold red]Engagement Config[/bold red]",
        border_style="red",
    ))

    from fracture.core.target import AITarget

    ai_target = AITarget(url=target)

    if module == "fingerprint":
        from fracture.modules.fingerprint.engine import FingerprintEngine
        result = asyncio.run(FingerprintEngine(ai_target).run())

        table = Table(
            title="[bold red]Fingerprint Results[/bold red]",
            show_lines=True,
            border_style="red",
            header_style="bold white on red",
        )
        table.add_column("Vector", style="cyan", min_width=16, max_width=18)
        table.add_column("Response", style="white", max_width=80)

        for key, val in result.evidence.items():
            if key == "_meta":
                continue
            response = val.get("response", "—")
            if any(x in str(response).lower() for x in ["error", "cannot", "not allowed", "refuse"]):
                resp = f"[yellow]{response[:300]}[/yellow]"
            elif any(x in str(response).lower() for x in ["gpt", "claude", "gemini", "llama", "openai", "anthropic"]):
                resp = f"[green]{response[:300]}[/green]"
            else:
                resp = response[:300]
            table.add_row(key, resp)

        console.print(table)

        meta = result.evidence.get("_meta", {})
        console.print(Panel(
            f"[bold]Status:[/bold] [green]✅ SUCCESS[/green]\n"
            f"[bold]API Format:[/bold] [cyan]{meta.get('api_format', 'unknown')}[/cyan]\n"
            f"[bold]Prompts sent:[/bold] {meta.get('prompts_sent', 0)}\n"
            f"[bold]Confidence:[/bold] [green]{result.confidence:.0%}[/green]\n"
            f"[bold]Timestamp:[/bold] [dim]{result.timestamp}[/dim]",
            title="[bold red]Summary[/bold red]",
            border_style="red",
        ))

        if output:
            import json
            with open(output, "w") as f:
                json.dump({"module": result.module, "target": result.target_url, "evidence": result.evidence, "timestamp": result.timestamp}, f, indent=2)
            console.print(f"[dim]💾 Results saved to {output}[/dim]")
    else:
        console.print(f"[red]Module '{module}' not available yet.[/red]")
        console.print("[dim]Available: fingerprint | Coming soon: hpm, memory, privesc, extract[/dim]")

@app.command()
def version():
    """Show version."""
    console.print(BANNER)

if __name__ == "__main__":
    app()
