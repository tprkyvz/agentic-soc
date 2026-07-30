"""
engine/models.py – Agentic SOC temel veri modelleri.

Pydantic v2 kullanılmaktadır.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field
from typing import Any


# ---------------------------------------------------------------------------
# Enum'lar
# ---------------------------------------------------------------------------

class ThreatLevel(str, Enum):
    """Bir olayın tehdit seviyesi."""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class LogSource(str, Enum):
    """Log kaynağı türü."""
    DOCKER_STREAM = "docker_stream"
    FILE = "file"
    STDIN = "stdin"


# ---------------------------------------------------------------------------
# Ham log
# ---------------------------------------------------------------------------

class LogEntry(BaseModel):
    """Tek bir ham log satırı – ingestor'dan çıkan ilk yapı."""
    timestamp: datetime = Field(default_factory=datetime.now)
    source: str = Field(description="Log kaynağı (container adı, dosya yolu vs.)")
    raw_log: str = Field(description="Ham log satırı")
    log_source_type: LogSource = Field(default=LogSource.DOCKER_STREAM)


# ---------------------------------------------------------------------------
# Normalize edilmiş güvenlik olayı
# ---------------------------------------------------------------------------

class SecurityEvent(BaseModel):
    """
    Birden fazla ham log satırının birleştirilip normalize edilmesiyle oluşan
    tek bir güvenlik olayı. Pipeline boyunca taşınan ana nesne.
    """
    event_id: str = Field(description="Olayın benzersiz kimliği (UUID)")
    detected_at: datetime = Field(default_factory=datetime.now)
    source_ip: str | None = Field(default=None, description="Saldırgan IP adresi")
    target_service: str = Field(default="ssh", description="Hedef servis")
    failed_attempts: int = Field(default=0, description="Başarısız/engellenen deneme sayısı")
    successful_attempts: int = Field(default=0, description="Başarılı (etkili olmuş) deneme sayısı")
    indicators: list[str] = Field(
        default_factory=list,
        description="Senaryoya göre değişen gösterge listesi (SSH: denenen kullanıcı adları, web: eşleşen saldırı imzaları)",
    )
    time_window_seconds: int = Field(default=60, description="Gözlem zaman penceresi")
    raw_log_entries: list[LogEntry] = Field(default_factory=list, description="Kaynak ham loglar")
    summary: str = Field(default="", description="İnsan okunabilir kısa özet")


# ---------------------------------------------------------------------------
# Ajan çıktıları
# ---------------------------------------------------------------------------

class TriageResult(BaseModel):
    """Triage Agent'ın çıktısı."""
    threat_level: ThreatLevel
    reason: str = Field(description="Karar gerekçesi")
    confidence: float = Field(ge=0.0, le=1.0, description="0-1 arası güven skoru")


class AnalysisResult(BaseModel):
    """Analyst Agent'ın çıktısı."""
    mitre_technique_id: str = Field(description="MITRE ATT&CK teknik ID'si, örn: T1110.001")
    mitre_technique_name: str = Field(description="Teknik adı")
    attack_description: str = Field(description="Saldırının LLM tarafından açıklanması")
    attacker_intent: str = Field(description="Tahmin edilen saldırgan niyeti")
    potential_impact: str = Field(description="Başarılı saldırının potansiyel etkisi")


class MitigationResult(BaseModel):
    """Mitigation Agent'ın çıktısı."""
    immediate_actions: list[str] = Field(description="Acil alınacak önlemler")
    short_term_actions: list[str] = Field(description="Kısa vadeli güvenlik iyileştirmeleri")
    long_term_actions: list[str] = Field(description="Uzun vadeli öneriler")
    example_commands: list[str] = Field(default_factory=list, description="Uygulanabilir komutlar")


# ---------------------------------------------------------------------------
# LangGraph State – graph boyunca taşınan durum
# ---------------------------------------------------------------------------

class AgentState(BaseModel):
    """
    LangGraph graph'ı boyunca her düğümden geçen durum nesnesi.
    Her ajan bu nesneyi okur, kendi sonucunu ekler ve iletir.
    """
    # Girdi
    event: SecurityEvent

    # Knowledge Base çıktısı (Triage sonrası, Analyst öncesi)
    kb_results: list[Any] = Field(default_factory=list, description="Benzer geçmiş vakalar (AttackCase nesneleri)")
    kb_context: str = Field(default="", description="LLM prompt'una eklenecek KB bağlamı")

    # Triage çıktısı
    triage_result: TriageResult | None = None

    # Analyst çıktısı
    analysis_result: AnalysisResult | None = None

    # Mitigation çıktısı
    mitigation_result: MitigationResult | None = None

    # Meta
    errors: list[str] = Field(default_factory=list)
    processing_completed: bool = False
