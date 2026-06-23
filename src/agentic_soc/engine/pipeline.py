"""
engine/pipeline.py – Ana pipeline: log ingestor + graph orkestrasyonu + çıktı.

İki mod:
  - file:   Statik log dosyası okuma (test için)
  - docker: Docker container stream (canlı lab)
"""

import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from .models import AgentState, LogEntry, LogSource, SecurityEvent, ThreatLevel
from .graph import soc_graph
from ..utils.config import settings
from ..utils.parsers import parse_ssh_line, ParsedSSHEvent

console = Console()


# ---------------------------------------------------------------------------
# Olay oluşturma: Birden fazla ham log → tek SecurityEvent
# ---------------------------------------------------------------------------

def _group_events_from_parsed(
    parsed_events: list[ParsedSSHEvent],
    raw_entries: list[LogEntry],
    source: str,
) -> list[SecurityEvent]:
    """
    Parse edilmiş SSH olaylarını IP bazında grupla ve SecurityEvent listesi döndür.
    """
    # IP başına olayları grupla
    by_ip: dict[str, list[ParsedSSHEvent]] = defaultdict(list)
    for ev in parsed_events:
        key = ev.ip_address or "unknown"
        by_ip[key].append(ev)

    security_events = []
    for ip, events in by_ip.items():
        failed = sum(1 for e in events if e.event_type in ("failed_password", "invalid_user"))
        success = sum(1 for e in events if e.event_type == "accepted")
        usernames = list(dict.fromkeys(e.username for e in events if e.username))  # sıralı unique

        # IP'ye ait ham logları bul
        ip_raw = [r for r in raw_entries if ip in r.raw_log] or raw_entries[:5]

        summary = (
            f"{failed} başarısız, {success} başarılı giriş – "
            f"IP: {ip} – kullanıcılar: {', '.join(usernames[:3])}"
        )

        security_events.append(
            SecurityEvent(
                event_id=str(uuid.uuid4()),
                source_ip=ip if ip != "unknown" else None,
                target_service="ssh",
                failed_attempts=failed,
                successful_attempts=success,
                attempted_usernames=usernames,
                time_window_seconds=settings.triage_time_window_seconds,
                raw_log_entries=ip_raw,
                summary=summary,
            )
        )

    return security_events


# ---------------------------------------------------------------------------
# Çıktı formatlama
# ---------------------------------------------------------------------------

def _threat_color(level: ThreatLevel) -> str:
    return {"benign": "green", "suspicious": "yellow", "malicious": "red"}.get(level.value, "white")


def _print_report(state_dict: dict) -> None:
    """AgentState dict'ini güzel bir rapor olarak terminale bas."""
    state = AgentState(**state_dict)
    triage = state.triage_result
    analysis = state.analysis_result
    mitigation = state.mitigation_result

    if triage is None:
        console.print("[dim]Triage sonucu yok.[/dim]")
        return

    color = _threat_color(triage.threat_level)
    level_str = triage.threat_level.value.upper()

    # Başlık
    console.print()
    console.rule(f"[bold {color}]🛡️  AGENTIC SOC – {level_str}[/bold {color}]")

    # Triage tablosu
    t = Table(box=box.ROUNDED, show_header=False, padding=(0, 1))
    t.add_column("Alan", style="bold cyan", width=22)
    t.add_column("Değer")
    t.add_row("Tehdit Seviyesi", f"[bold {color}]{level_str}[/bold {color}]")
    t.add_row("Güven Skoru", f"%{int(triage.confidence * 100)}")
    t.add_row("IP Adresi", state.event.source_ip or "bilinmiyor")
    t.add_row("Başarısız Deneme", str(state.event.failed_attempts))
    t.add_row("Başarılı Giriş", str(state.event.successful_attempts))
    t.add_row("Denenen Kullanıcılar", ", ".join(state.event.attempted_usernames[:5]) or "—")
    t.add_row("Triage Gerekçesi", triage.reason)
    console.print(t)

    # MALICIOUS/SUSPICIOUS ise detaylar
    if triage.threat_level != ThreatLevel.BENIGN and analysis:
        console.print()
        console.print(Panel(
            f"[bold]{analysis.mitre_technique_id}[/bold] – {analysis.mitre_technique_name}\n\n"
            f"[italic]{analysis.attack_description}[/italic]\n\n"
            f"🎯 [bold]Niyet:[/bold] {analysis.attacker_intent}\n"
            f"💥 [bold]Etki:[/bold] {analysis.potential_impact}",
            title="[bold yellow]🔍 MITRE ATT&CK Analizi[/bold yellow]",
            border_style="yellow",
        ))

    if mitigation:
        console.print()
        mit_text = Text()
        mit_text.append("⚡ ACİL ÖNLEMLER\n", style="bold red")
        for a in mitigation.immediate_actions:
            mit_text.append(f"  • {a}\n")
        mit_text.append("\n🔧 KISA VADELİ\n", style="bold yellow")
        for a in mitigation.short_term_actions:
            mit_text.append(f"  • {a}\n")
        mit_text.append("\n🏗️  UZUN VADELİ\n", style="bold blue")
        for a in mitigation.long_term_actions:
            mit_text.append(f"  • {a}\n")
        if mitigation.example_commands:
            mit_text.append("\n💻 ÖRNEK KOMUTLAR\n", style="bold green")
            for cmd in mitigation.example_commands:
                mit_text.append(f"  $ {cmd}\n", style="dim green")
        console.print(Panel(mit_text, title="[bold green]🛠️  Mitigation Önerileri[/bold green]", border_style="green"))

    if state.errors:
        console.print(f"\n[dim yellow]⚠ Uyarılar: {'; '.join(state.errors)}[/dim yellow]")

    console.rule()


# ---------------------------------------------------------------------------
# Log kaynakları
# ---------------------------------------------------------------------------

def _run_on_events(security_events: list[SecurityEvent]) -> None:
    """SecurityEvent listesini graph'tan geçir ve raporları bas."""
    for event in security_events:
        console.print(f"\n[dim]▶ Olay işleniyor: {event.event_id[:8]}... | IP: {event.source_ip} | Başarısız: {event.failed_attempts}[/dim]")
        initial_state = AgentState(event=event).model_dump()
        result = soc_graph.invoke(initial_state)
        _print_report(result)


def run_file_mode(log_file: str) -> None:
    """Statik log dosyasını okuyup analiz et."""
    path = Path(log_file)
    if not path.exists():
        console.print(f"[red]Hata: Dosya bulunamadı: {log_file}[/red]")
        return

    console.print(f"[cyan]📂 Dosya modu: {path}[/cyan]")
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    console.print(f"[dim]{len(lines)} satır okundu.[/dim]")

    parsed = []
    raw_entries = []
    for line in lines:
        ev = parse_ssh_line(line)
        if ev:
            parsed.append(ev)
            raw_entries.append(LogEntry(source=str(path), raw_log=line, log_source_type=LogSource.FILE))

    if not parsed:
        console.print("[yellow]SSH ile ilgili log satırı bulunamadı.[/yellow]")
        return

    console.print(f"[dim]{len(parsed)} SSH olayı parse edildi.[/dim]")
    security_events = _group_events_from_parsed(parsed, raw_entries, str(path))
    _run_on_events(security_events)


def run_docker_mode(container_name: str | None = None) -> None:
    """Docker container'dan canlı log stream oku."""
    import docker as docker_sdk

    container_name = container_name or settings.ssh_container_name
    keywords = settings.ssh_keywords

    try:
        client = docker_sdk.from_env()
        container = client.containers.get(container_name)
    except Exception as e:
        console.print(f"[red]Docker hatası: {e}[/red]")
        console.print("[yellow]Docker çalışıyor mu? Container başlatıldı mı?[/yellow]")
        return

    console.print(f"[cyan]🐳 Docker modu: {container_name} dinleniyor...[/cyan]")
    console.print("[dim]Durdurmak için Ctrl+C[/dim]\n")

    # Pencere bazlı gruplama için buffer
    window_buffer: list[ParsedSSHEvent] = []
    raw_buffer: list[LogEntry] = []
    window_start = datetime.now()
    window_seconds = settings.triage_time_window_seconds

    try:
        for line_bytes in container.logs(stream=True, follow=True, tail=0):
            line = line_bytes.decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            if not any(kw in line.lower() for kw in keywords):
                continue

            ev = parse_ssh_line(line)
            if ev:
                window_buffer.append(ev)
                raw_buffer.append(LogEntry(source=container_name, raw_log=line))

            # Zaman penceresi dolduğunda işle
            if (datetime.now() - window_start).seconds >= window_seconds and window_buffer:
                security_events = _group_events_from_parsed(window_buffer, raw_buffer, container_name)
                _run_on_events(security_events)
                window_buffer.clear()
                raw_buffer.clear()
                window_start = datetime.now()

    except KeyboardInterrupt:
        console.print("\n[yellow]Durduruldu.[/yellow]")
        # Kalan buffer'ı işle
        if window_buffer:
            security_events = _group_events_from_parsed(window_buffer, raw_buffer, container_name)
            _run_on_events(security_events)
