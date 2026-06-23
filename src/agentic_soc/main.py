"""
main.py – Agentic SOC giriş noktası.

Kullanım:
  python -m src.agentic_soc.main --source file --log-file lab/logs/ssh_bruteforce/sample_auth.log
  python -m src.agentic_soc.main --source docker
  python -m src.agentic_soc.main --source docker --container victim_ssh_server
"""

import argparse
import sys

from rich.console import Console
from rich.panel import Panel

from .utils.config import settings
from .utils.llm_client import check_ollama_connection
from .knowledge_base.embeddings import check_embedding_model
from .knowledge_base.storage import count_cases
from .engine.pipeline import run_file_mode, run_docker_mode

console = Console()


def _print_banner() -> None:
    console.print(Panel(
        "[bold cyan]Agentic SOC[/bold cyan]\n"
        "[dim]Multi-Agent LLM-Driven Security Operations Center[/dim]\n\n"
        f"Model: [yellow]{settings.ollama_model}[/yellow] | "
        f"Ollama: [yellow]{settings.ollama_base_url}[/yellow]",
        border_style="cyan",
        title="🛡️  v0.1.0",
    ))


def _check_prerequisites(source: str) -> bool:
    """Başlamadan önce gerekli servislerin hazır olduğunu doğrula."""
    ok = True

    # Ollama kontrolü
    console.print("[dim]Ollama bağlantısı kontrol ediliyor...[/dim]", end=" ")
    connected, msg = check_ollama_connection()
    if connected:
        console.print(f"[green]✓[/green] {msg}")
    else:
        console.print(f"[red]✗[/red] {msg}")
        console.print("[yellow]Ollama çalışmıyor. 'ollama serve' komutunu çalıştır.[/yellow]")
        ok = False

    # Embedding modeli kontrolü
    console.print("[dim]Embedding modeli kontrol ediliyor...[/dim]", end=" ")
    emb_ok, emb_msg = check_embedding_model()
    if emb_ok:
        console.print(f"[green]✓[/green] {emb_msg}")
    else:
        console.print(f"[yellow]⚠[/yellow] {emb_msg}")
        console.print("[dim]KB özelliği devre dışı (embedding modeli yok). Diğer özellikler çalışır.[/dim]")

    # KB durum bilgisi
    kb_count = count_cases()
    if kb_count > 0:
        console.print(f"[green]✓[/green] Knowledge Base: {kb_count} vaka yüklendi")
    else:
        console.print(f"[yellow]⚠[/yellow] Knowledge Base boş. ")
        console.print("[dim]  Doldurmak için: python -m src.agentic_soc.main --seed[/dim]")

    # Docker kontrolü (sadece docker modunda)
    if source == "docker":
        console.print("[dim]Docker kontrol ediliyor...[/dim]", end=" ")
        try:
            import docker
            client = docker.from_env()
            client.ping()
            console.print("[green]✓[/green] Docker çalışıyor")
        except Exception as e:
            console.print(f"[red]✗[/red] Docker hatası: {e}")
            console.print("[yellow]Docker daemon çalışıyor mu? 'sudo systemctl start docker'[/yellow]")
            ok = False

    return ok


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Agentic SOC – LLM tabanlı güvenlik log analizi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  Dosya modu (test):
    python -m src.agentic_soc.main --source file --log-file lab/logs/ssh_bruteforce/sample_auth.log

  Docker modu (canlı):
    python -m src.agentic_soc.main --source docker

  Farklı model ile:
    python -m src.agentic_soc.main --source file --log-file mylog.txt --model mistral
        """,
    )
    parser.add_argument(
        "--source",
        choices=["file", "docker"],
        default="file",
        help="Log kaynağı (varsayılan: file)",
    )
    parser.add_argument(
        "--log-file",
        default="lab/logs/ssh_bruteforce/sample_auth.log",
        help="Analiz edilecek log dosyası (sadece --source file ile)",
    )
    parser.add_argument(
        "--container",
        default=None,
        help=f"Docker container adı (varsayılan: {settings.ssh_container_name})",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=f"Ollama model adı (varsayılan: {settings.ollama_model})",
    )
    parser.add_argument(
        "--no-check",
        action="store_true",
        help="Ön kontrolleri atla",
    )
    parser.add_argument(
        "--seed",
        action="store_true",
        help="Knowledge Base'i başlangıç vakalarıyla doldur ve çık",
    )
    parser.add_argument(
        "--seed-force",
        action="store_true",
        help="KB'yi zorla yeniden doldur (mevcut verilerin üzerine yaz)",
    )

    args = parser.parse_args()

    # Model override
    if args.model:
        settings.ollama_model = args.model

    _print_banner()

    # --seed modu: KB'yi doldur ve çık
    if args.seed or args.seed_force:
        from .knowledge_base.seeder import seed_knowledge_base
        seed_knowledge_base(force=args.seed_force)
        sys.exit(0)

    # Ön kontrol
    if not args.no_check:
        if not _check_prerequisites(args.source):
            console.print("\n[red]Ön koşullar sağlanamadı. Çıkılıyor.[/red]")
            sys.exit(1)

    console.print()

    # Çalıştır
    if args.source == "file":
        run_file_mode(args.log_file)
    elif args.source == "docker":
        run_docker_mode(args.container)


if __name__ == "__main__":
    main()
