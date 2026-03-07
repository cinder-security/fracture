import typer
import asyncio
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from fracture.core.target import AITarget
from fracture.modules.fingerprint.engine import FingerprintEngine

app = typer.Typer(
    name="fracture",
    help="🔥 Cinder Fracture — Autonomous AI Red Team Engine",
    add_completion=False,
)
console = Console()

@app.command()
def start(
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
    module: str = typer.Option("fingerprint", "--module", "-m", help="Module to run"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Start a red team engagement against a target AI system."""
    console.print(f"\n[bold red]🔥 CINDER FRACTURE[/bold red] [dim]v0.1.0[/dim]")
    console.print(f"[dim]Find the fracture before someone else does.[/dim]\n")
    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Module:[/bold] {module}\n")

    ai_target = AITarget(url=target)

    if module == "fingerprint":
        engine = FingerprintEngine(ai_target)
        result = asyncio.run(engine.run())

        table = Table(title="Fingerprint Results", show_lines=True)
        table.add_column("Prompt", style="cyan", max_width=40)
        table.add_column("Response", style="white", max_width=60)

        for prompt, response in result.evidence.items():
            table.add_row(prompt, response[:200] if response else "—")

        console.print(table)
        console.print(f"\n{result.summary()}\n")
    else:
        console.print(f"[red]Module '{module}' not available in v0.1.0[/red]")

@app.command()
def version():
    """Show version."""
    console.print("[bold red]🔥 Cinder Fracture[/bold red] v0.1.0")

if __name__ == "__main__":
    app()
