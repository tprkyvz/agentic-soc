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
from ..utils.parsers import parse_ssh_line, ParsedSSHEvent, parse_web_line, ParsedWebEvent

console = Console()


# ---------------------------------------------------------------------------
# Olay oluşturma: Birden fazla ham log → tek SecurityEvent
# ---------------------------------------------------------------------------

def _group_ssh_events_from_parsed(
    parsed_events: list[ParsedSSHEvent],
    raw_entries: list[LogEntry],
    source: str,
) -> list[SecurityEvent]:
    """
    Parse edilmiş SSH olaylarını IP bazında grupla ve SecurityEvent listesi döndür.

    parsed_events ve raw_entries indeks bazında birebir eşleşir (aynı satırdan
    üretilirler); bu eşleşme IP'ye göre ham logları doğru olaya bağlamak için
    kullanılır (IP metnini ham log içinde arayarak eşleştirmek yanlış IP'lerin
    birbirine karışmasına yol açabiliyordu, örn. "10.0.0.5" ile "10.0.0.55").
    """
    # OpenSSH, olmayan bir kullanıcı için hem "Invalid user" hem de
    # "Failed password for invalid user" satırı basar – aynı deneme için iki
    # ayrı ParsedSSHEvent üretilir. Sadece "failed_password" sayılmalı, yoksa
    # başarısız giriş sayısı gerçek değerin ~2 katına çıkar (bkz. triage eşiği).
    by_ip: dict[str, list[ParsedSSHEvent]] = defaultdict(list)
    raw_by_ip: dict[str, list[LogEntry]] = defaultdict(list)
    for ev, raw in zip(parsed_events, raw_entries):
        if ev.event_type == "other":
            continue
        key = ev.ip_address or "unknown"
        by_ip[key].append(ev)
        raw_by_ip[key].append(raw)

    security_events = []
    for ip, events in by_ip.items():
        failed = sum(1 for e in events if e.event_type == "failed_password")
        success = sum(1 for e in events if e.event_type == "accepted")
        usernames = list(dict.fromkeys(e.username for e in events if e.username))  # sıralı unique

        # IP'ye ait ham loglar (indeks eşleşmesiyle doğru gruplanmış)
        ip_raw = raw_by_ip[ip]

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
                indicators=usernames,
                time_window_seconds=settings.triage_time_window_seconds,
                raw_log_entries=ip_raw,
                summary=summary,
            )
        )

    return security_events


def _group_web_events_from_parsed(
    parsed_events: list[ParsedWebEvent],
    raw_entries: list[LogEntry],
    source: str,
) -> list[SecurityEvent]:
    """
    Parse edilmiş web (SQLi/XSS) olaylarını IP bazında grupla ve SecurityEvent listesi döndür.

    SSH grubu ile aynı prensip: failed/success ayrık kategoriler (toplamı
    tüm kötü niyetli isteklere eşit). "success" burada SSH'teki gibi masum
    değil – bir SQLi/XSS payload'ının HTTP 200 ile (yani engellenmeden)
    sonuçlanması demektir. Hiç kötü niyetli imza taşımayan (tamamen temiz
    trafik üreten) IP'ler için hiçbir SecurityEvent oluşturulmaz.
    """
    by_ip: dict[str, list[ParsedWebEvent]] = defaultdict(list)
    raw_by_ip: dict[str, list[LogEntry]] = defaultdict(list)
    for ev, raw in zip(parsed_events, raw_entries):
        if ev.event_type == "benign":
            continue
        key = ev.ip_address or "unknown"
        by_ip[key].append(ev)
        raw_by_ip[key].append(raw)

    security_events = []
    for ip, events in by_ip.items():
        failed = sum(1 for e in events if e.status_code != 200)
        success = sum(1 for e in events if e.status_code == 200)
        indicators = list(dict.fromkeys(
            f"{e.event_type.replace('_attempt', '')}: {sig}"
            for e in events for sig in e.matched_signatures
        ))

        ip_raw = raw_by_ip[ip]

        summary = (
            f"{failed} engellenen, {success} başarılı (200) kötü niyetli istek – "
            f"IP: {ip} – göstergeler: {', '.join(indicators[:3])}"
        )

        security_events.append(
            SecurityEvent(
                event_id=str(uuid.uuid4()),
                source_ip=ip if ip != "unknown" else None,
                target_service="web",
                failed_attempts=failed,
                successful_attempts=success,
                indicators=indicators,
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
    t.add_row("Hedef Servis", state.event.target_service)
    t.add_row("Başarısız/Engellenen", str(state.event.failed_attempts))
    t.add_row("Başarılı", str(state.event.successful_attempts))
    t.add_row("Göstergeler", ", ".join(state.event.indicators[:5]) or "—")
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

def _parse_ssh_lines(lines: list[str], source: str) -> tuple[list[ParsedSSHEvent], list[LogEntry]]:
    """Ham SSH log satırlarını parse et; parsed ve raw_entries indeks bazında eşleşir."""
    parsed: list[ParsedSSHEvent] = []
    raw_entries: list[LogEntry] = []
    for line in lines:
        ev = parse_ssh_line(line)
        if ev:
            parsed.append(ev)
            raw_entries.append(LogEntry(source=source, raw_log=line, log_source_type=LogSource.FILE))
    return parsed, raw_entries


def _parse_web_lines(lines: list[str], source: str) -> tuple[list[ParsedWebEvent], list[LogEntry]]:
    """Ham web access log satırlarını parse et; parsed ve raw_entries indeks bazında eşleşir."""
    parsed: list[ParsedWebEvent] = []
    raw_entries: list[LogEntry] = []
    for line in lines:
        ev = parse_web_line(line)
        if ev:
            parsed.append(ev)
            raw_entries.append(LogEntry(source=source, raw_log=line, log_source_type=LogSource.FILE))
    return parsed, raw_entries


def analyze_log_text(text: str, source: str = "upload", log_type: str = "ssh") -> list[dict]:
    """
    Ham log metnini parse edip graph'tan geçir, AgentState dict listesi döndür.

    Konsola basmaz – CLI dışı çağıranlar (örn. dashboard API) için kullanılır.
    """
    lines = text.splitlines()
    if log_type == "web":
        parsed, raw_entries = _parse_web_lines(lines, source)
        if not parsed:
            return []
        security_events = _group_web_events_from_parsed(parsed, raw_entries, source)
    else:
        parsed, raw_entries = _parse_ssh_lines(lines, source)
        if not parsed:
            return []
        security_events = _group_ssh_events_from_parsed(parsed, raw_entries, source)

    return [soc_graph.invoke(AgentState(event=event).model_dump()) for event in security_events]


def _run_on_events(security_events: list[SecurityEvent]) -> None:
    """SecurityEvent listesini graph'tan geçir ve raporları bas."""
    for event in security_events:
        console.print(f"\n[dim]▶ Olay işleniyor: {event.event_id[:8]}... | IP: {event.source_ip} | Başarısız: {event.failed_attempts}[/dim]")
        initial_state = AgentState(event=event).model_dump()
        result = soc_graph.invoke(initial_state)
        _print_report(result)


def run_file_mode(log_file: str, log_type: str = "ssh") -> None:
    """Statik log dosyasını okuyup analiz et."""
    path = Path(log_file)
    if not path.exists():
        console.print(f"[red]Hata: Dosya bulunamadı: {log_file}[/red]")
        return

    console.print(f"[cyan]📂 Dosya modu ({log_type}): {path}[/cyan]")
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    console.print(f"[dim]{len(lines)} satır okundu.[/dim]")

    if log_type == "web":
        parsed, raw_entries = _parse_web_lines(lines, str(path))
        group_fn = _group_web_events_from_parsed
    else:
        parsed, raw_entries = _parse_ssh_lines(lines, str(path))
        group_fn = _group_ssh_events_from_parsed

    if not parsed:
        console.print("[yellow]İlgili log satırı bulunamadı.[/yellow]")
        return

    console.print(f"[dim]{len(parsed)} olay parse edildi.[/dim]")
    security_events = group_fn(parsed, raw_entries, str(path))
    _run_on_events(security_events)


def run_docker_mode(container_name: str | None = None, log_type: str = "ssh") -> None:
    """Docker container'dan canlı log stream oku."""
    import docker as docker_sdk

    is_web = log_type == "web"
    container_name = container_name or (settings.web_container_name if is_web else settings.ssh_container_name)
    keywords = settings.ssh_keywords

    try:
        client = docker_sdk.from_env()
        container = client.containers.get(container_name)
    except Exception as e:
        console.print(f"[red]Docker hatası: {e}[/red]")
        console.print("[yellow]Docker çalışıyor mu? Container başlatıldı mı?[/yellow]")
        return

    console.print(f"[cyan]🐳 Docker modu ({log_type}): {container_name} dinleniyor...[/cyan]")
    console.print("[dim]Durdurmak için Ctrl+C[/dim]\n")

    # Pencere bazlı gruplama için buffer
    window_buffer: list[ParsedSSHEvent] | list[ParsedWebEvent] = []
    raw_buffer: list[LogEntry] = []
    window_start = datetime.now()
    window_seconds = settings.triage_time_window_seconds
    group_fn = _group_web_events_from_parsed if is_web else _group_ssh_events_from_parsed

    def _flush() -> None:
        security_events = group_fn(window_buffer, raw_buffer, container_name)
        _run_on_events(security_events)
        window_buffer.clear()
        raw_buffer.clear()

    try:
        for line_bytes in container.logs(stream=True, follow=True, tail=0):
            line = line_bytes.decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            # Web access log'unda her satır gerçek bir istektir; SSH'in aksine
            # gürültü filtrelemeye gerek yok – parse_web_line'ın kendi
            # sınıflandırması (sqli/xss/benign) zaten filtre görevi görüyor.
            if not is_web and not any(kw in line.lower() for kw in keywords):
                continue

            ev = parse_web_line(line) if is_web else parse_ssh_line(line)
            if ev:
                window_buffer.append(ev)
                raw_buffer.append(LogEntry(source=container_name, raw_log=line))

            # Zaman penceresi dolduğunda işle
            if (datetime.now() - window_start).seconds >= window_seconds and window_buffer:
                _flush()
                window_start = datetime.now()

    except KeyboardInterrupt:
        console.print("\n[yellow]Durduruldu.[/yellow]")
        if window_buffer:
            _flush()
