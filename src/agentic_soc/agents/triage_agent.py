"""
agents/triage_agent.py – Triage Agent.

İlk filtre: gelen SecurityEvent'i benign / suspicious / malicious
olarak sınıflandırır. Eşik değerler kural tabanlıdır (LLM çağrısı yok),
bu sayede hız ve deterministik davranış sağlanır.
"""

from ..engine.models import AgentState, ThreatLevel, TriageResult
from ..utils.config import settings


def triage_node(state: AgentState) -> AgentState:
    """
    LangGraph düğümü: Triage.

    Karar mantığı:
    - failed_attempts >= MALICIOUS_THRESHOLD  → MALICIOUS
    - failed_attempts >= SUSPICIOUS_THRESHOLD → SUSPICIOUS
    - successful_attempts > 0 (önceki başarısız)→ MALICIOUS (brute-force başarılı)
    - diğer                                   → BENIGN
    """
    event = state.event
    failed = event.failed_attempts
    success = event.successful_attempts

    mal_thresh = settings.triage_malicious_threshold
    sus_thresh = settings.triage_suspicious_threshold

    # Brute-force başarıya ulaştıysa – en ciddi durum
    if success > 0 and failed >= sus_thresh:
        result = TriageResult(
            threat_level=ThreatLevel.MALICIOUS,
            reason=(
                f"Brute-force saldırısı BAŞARILI oldu! "
                f"{failed} başarısız denemeden sonra {success} başarılı giriş. "
                f"Kaynak IP: {event.source_ip}"
            ),
            confidence=0.99,
        )

    elif failed >= mal_thresh:
        result = TriageResult(
            threat_level=ThreatLevel.MALICIOUS,
            reason=(
                f"{failed} başarısız giriş denemesi tespit edildi "
                f"({settings.triage_time_window_seconds}s içinde). "
                f"Eşik: {mal_thresh}. Kaynak IP: {event.source_ip}. "
                f"Denenen kullanıcılar: {', '.join(event.attempted_usernames[:5])}"
            ),
            confidence=min(0.95, 0.70 + (failed - mal_thresh) * 0.01),
        )

    elif failed >= sus_thresh:
        result = TriageResult(
            threat_level=ThreatLevel.SUSPICIOUS,
            reason=(
                f"{failed} başarısız giriş denemesi – eşiği aştı ({sus_thresh}). "
                f"Kaynak IP: {event.source_ip}. "
                f"Denenen kullanıcılar: {', '.join(event.attempted_usernames[:3])}"
            ),
            confidence=0.75,
        )

    else:
        result = TriageResult(
            threat_level=ThreatLevel.BENIGN,
            reason=(
                f"Yalnızca {failed} başarısız giriş – normal hata payı içinde "
                f"(eşik: {sus_thresh}). Kaynak IP: {event.source_ip}"
            ),
            confidence=0.85,
        )

    state.triage_result = result
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
