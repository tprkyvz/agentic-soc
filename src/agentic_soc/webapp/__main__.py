"""python -m src.agentic_soc.webapp ile başlatılır."""

from rich.console import Console
from rich.panel import Panel

console = Console()


def main() -> None:
    import uvicorn

    console.print(Panel(
        "[bold cyan]Agentic SOC Dashboard[/bold cyan]\n"
        "[dim]http://127.0.0.1:8000[/dim]",
        border_style="cyan",
        title="🛡️  Dashboard",
    ))
    uvicorn.run("src.agentic_soc.webapp.app:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
