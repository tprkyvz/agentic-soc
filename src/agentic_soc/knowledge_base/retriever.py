"""
knowledge_base/retriever.py – Yüksek seviyeli KB sorgu API'si.

SecurityEvent'i alır, benzer AttackCase listesi döndürür.
Bu modülü diğer katmanlar (agents, pipeline) kullanır.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .schemas import AttackCase
from .storage import query_similar

if TYPE_CHECKING:
    # Sadece tip kontrolcüsu için – runtime'da import etme (circular import önler)
    from ..engine.models import SecurityEvent


def _build_ssh_query_text(event: SecurityEvent) -> list[str]:
    parts = [
        "SSH authentication failure",
        f"failed login attempts: {event.failed_attempts}",
        f"service: {event.target_service}",
    ]

    if event.source_ip:
        parts.append(f"source IP: {event.source_ip}")

    if event.indicators:
        users = ", ".join(event.indicators[:5])
        parts.append(f"attempted usernames: {users}")

    if event.successful_attempts > 0:
        parts.append("successful login after failed attempts")

    if event.failed_attempts >= 20:
        parts.append("high volume brute force attack")
    elif event.failed_attempts >= 5:
        parts.append("suspicious login activity")

    return parts


def _build_web_query_text(event: SecurityEvent) -> list[str]:
    parts = [
        "web application attack attempt",
        f"blocked/not-found malicious requests: {event.failed_attempts}",
        f"service: {event.target_service}",
    ]

    if event.source_ip:
        parts.append(f"source IP: {event.source_ip}")

    if event.indicators:
        indicators = ", ".join(event.indicators[:5])
        parts.append(f"matched attack indicators: {indicators}")

    if event.successful_attempts > 0:
        parts.append("malicious request returned HTTP 200, not blocked")

    if any("sql" in i.lower() for i in event.indicators):
        parts.append("SQL injection")
    if any("xss" in i.lower() for i in event.indicators):
        parts.append("cross-site scripting XSS")

    return parts


def build_query_text(event: SecurityEvent) -> str:
    """
    SecurityEvent'ten semantik arama için optimal sorgu metni üret.
    Embedding kalitesini artırmak için en bilgi yoğun alanları kullan.

    Senaryoya (SSH/web) göre tamamen ayrı çerçevelenir – SSH'e özgü ifadeler
    ("successful login", "brute force") web olaylarının sorgu metnine
    karışıp benzerlik aramasının kalitesini düşürmesin diye.
    """
    if event.target_service == "web":
        parts = _build_web_query_text(event)
    else:
        parts = _build_ssh_query_text(event)

    return ". ".join(parts)


def find_similar_cases(
    event: SecurityEvent,
    n_results: int = 3,
    min_similarity: float = 0.3,
) -> list[tuple[AttackCase, float]]:
    """
    SecurityEvent için benzer geçmiş vakaları bul.

    Args:
        event:          Analiz edilecek güvenlik olayı
        n_results:      Maksimum sonuç sayısı
        min_similarity: Minimum benzerlik eşiği (bu değerin altındakiler atılır)

    Returns:
        (AttackCase, benzerlik_skoru) çiftleri, skora göre azalan sırada
    """
    query_text = build_query_text(event)
    results = query_similar(query_text, n_results=n_results)

    # Minimum eşiği uygula
    filtered = [(case, score) for case, score in results if score >= min_similarity]

    return filtered


def format_kb_context(cases: list[tuple[AttackCase, float]]) -> str:
    """
    Bulunan vakaları LLM prompt'una eklenecek metin bloğuna dönüştür.

    Returns:
        LLM'e gönderilecek bağlam metni, yoksa boş string
    """
    if not cases:
        return ""

    lines = ["RELEVANT PAST INCIDENTS FROM KNOWLEDGE BASE:"]
    for i, (case, score) in enumerate(cases, 1):
        lines.append(
            f"\n[Case {i}] {case.title} (similarity: {score:.0%})\n"
            f"  MITRE: {case.mitre_technique_id} – {case.mitre_technique_name}\n"
            f"  Severity: {case.severity.value.upper()}\n"
            f"  Description: {case.description}\n"
            f"  Key Indicators: {', '.join(case.indicators[:4])}\n"
            f"  Effective Mitigations: {', '.join(case.mitigations[:4])}"
            + (f"\n  Resolution Time: {case.resolution_time_hours}h" if case.resolution_time_hours else "")
        )

    return "\n".join(lines)
