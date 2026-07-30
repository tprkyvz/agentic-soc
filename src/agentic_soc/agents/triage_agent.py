"""
agents/triage_agent.py – Triage Agent.

İlk filtre: gelen SecurityEvent'i benign / suspicious / malicious
olarak sınıflandırır. Eşik değerler kural tabanlıdır (LLM çağrısı yok),
bu sayede hız ve deterministik davranış sağlanır.

Senaryoya göre (SSH / web) ayrı eşik ve gerekçe metinleri kullanılır –
SSH dalı davranışı değiştirmeden korunur, web dalı kendi eşiklerine göre karar verir.
"""

from ..engine.models import AgentState, SecurityEvent, ThreatLevel, TriageResult
from ..utils.config import settings


def _triage_ssh(event: SecurityEvent) -> TriageResult:
    """
    Karar mantığı:
    - failed_attempts >= MALICIOUS_THRESHOLD  → MALICIOUS
    - failed_attempts >= SUSPICIOUS_THRESHOLD → SUSPICIOUS
    - successful_attempts > 0 (önceki başarısız)→ MALICIOUS (brute-force başarılı)
    - diğer                                   → BENIGN
    """
    failed = event.failed_attempts
    success = event.successful_attempts

    mal_thresh = settings.triage_malicious_threshold
    sus_thresh = settings.triage_suspicious_threshold

    # Brute-force başarıya ulaştıysa – en ciddi durum
    if success > 0 and failed >= sus_thresh:
        return TriageResult(
            threat_level=ThreatLevel.MALICIOUS,
            reason=(
                f"Brute-force saldırısı BAŞARILI oldu! "
                f"{failed} başarısız denemeden sonra {success} başarılı giriş. "
                f"Kaynak IP: {event.source_ip}"
            ),
            confidence=0.99,
        )

    if failed >= mal_thresh:
        return TriageResult(
            threat_level=ThreatLevel.MALICIOUS,
            reason=(
                f"{failed} başarısız giriş denemesi tespit edildi "
                f"({settings.triage_time_window_seconds}s içinde). "
                f"Eşik: {mal_thresh}. Kaynak IP: {event.source_ip}. "
                f"Denenen kullanıcılar: {', '.join(event.indicators[:5])}"
            ),
            confidence=min(0.95, 0.70 + (failed - mal_thresh) * 0.01),
        )

    if failed >= sus_thresh:
        return TriageResult(
            threat_level=ThreatLevel.SUSPICIOUS,
            reason=(
                f"{failed} başarısız giriş denemesi – eşiği aştı ({sus_thresh}). "
                f"Kaynak IP: {event.source_ip}. "
                f"Denenen kullanıcılar: {', '.join(event.indicators[:3])}"
            ),
            confidence=0.75,
        )

    return TriageResult(
        threat_level=ThreatLevel.BENIGN,
        reason=(
            f"Yalnızca {failed} başarısız giriş – normal hata payı içinde "
            f"(eşik: {sus_thresh}). Kaynak IP: {event.source_ip}"
        ),
        confidence=0.85,
    )


def _triage_web(event: SecurityEvent) -> TriageResult:
    """
    Web (SQLi/XSS) karar mantığı.

    Not: bu fonksiyona gelen her SecurityEvent zaten en az bir SQLi/XSS imzası
    içerir (temiz trafik gruplama aşamasında elenir) – bu yüzden "successful_attempts"
    SSH'teki gibi masum bir olay değil, doğrudan HTTP 200 dönen bir kötü niyetli
    isteği ifade eder ve tek başına bile MALICIOUS için yeterlidir.
    """
    failed = event.failed_attempts       # engellenen/404 dönen kötü niyetli istekler
    success = event.successful_attempts  # 200 dönen (engellenmemiş) kötü niyetli istekler
    total = failed + success

    mal_thresh = settings.triage_web_malicious_threshold
    sus_thresh = settings.triage_web_suspicious_threshold

    if success > 0:
        return TriageResult(
            threat_level=ThreatLevel.MALICIOUS,
            reason=(
                f"{success} adet SQLi/XSS payload'ı HTTP 200 ile sonuçlandı (engellenmedi). "
                f"Toplam {total} kötü niyetli istek tespit edildi. Kaynak IP: {event.source_ip}. "
                f"Göstergeler: {', '.join(event.indicators[:5])}"
            ),
            confidence=0.97,
        )

    if total >= mal_thresh:
        return TriageResult(
            threat_level=ThreatLevel.MALICIOUS,
            reason=(
                f"{total} adet SQLi/XSS imzası tespit edildi (eşik: {mal_thresh}). "
                f"Kaynak IP: {event.source_ip}. Göstergeler: {', '.join(event.indicators[:5])}"
            ),
            confidence=min(0.95, 0.75 + (total - mal_thresh) * 0.03),
        )

    if total >= sus_thresh:
        return TriageResult(
            threat_level=ThreatLevel.SUSPICIOUS,
            reason=(
                f"{total} adet SQLi/XSS imzası tespit edildi (eşik: {sus_thresh}). "
                f"Kaynak IP: {event.source_ip}. Göstergeler: {', '.join(event.indicators[:3])}"
            ),
            confidence=0.80,
        )

    return TriageResult(
        threat_level=ThreatLevel.BENIGN,
        reason=f"Kayda değer SQLi/XSS aktivitesi yok. Kaynak IP: {event.source_ip}",
        confidence=0.85,
    )


def triage_node(state: AgentState) -> AgentState:
    """LangGraph düğümü: Triage. Senaryoya göre uygun kural setine yönlendirir."""
    event = state.event
    if event.target_service == "web":
        state.triage_result = _triage_web(event)
    else:
        state.triage_result = _triage_ssh(event)
    return state


def triage_router(state: AgentState) -> str:
    """
    LangGraph koşullu kenar: triage sonucuna göre sonraki düğümü belirle.

    Returns:
        "analyze"  – şüpheli veya kötü niyetli → analize devam et
        "discard"  – zararsız → pipeline'ı sonlandır
    """
    if state.triage_result is None:
        return "discard"

    level = state.triage_result.threat_level
    if level in (ThreatLevel.SUSPICIOUS, ThreatLevel.MALICIOUS):
        return "analyze"
    return "discard"
