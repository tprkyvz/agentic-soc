"""
knowledge_base/schemas.py – Bilgi tabanı veri modelleri.

AttackCase: Sisteme öğretilecek / öğrenilecek bir saldırı vakasını temsil eder.
"""

from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, Field


class AttackType(str, Enum):
    """Saldırı kategorisi."""
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    PORT_SCAN = "port_scan"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackCase(BaseModel):
    """
    Bilgi tabanındaki tek bir saldırı vakası.

    ChromaDB'ye kaydedilir; yeni olaylarla semantik benzerlik için sorgulanır.
    """
    id: str = Field(description="Benzersiz vaka ID'si (örn: ssh-bf-001)")
    title: str = Field(description="Kısa başlık")
    attack_type: AttackType = Field(description="Saldırı kategorisi")
    mitre_technique_id: str = Field(description="MITRE ATT&CK teknik ID'si")
    mitre_technique_name: str = Field(description="MITRE ATT&CK teknik adı")
    severity: Severity = Field(description="Ciddiyet seviyesi")

    # Semantik arama için kullanılacak metin
    description: str = Field(description="Saldırının ayrıntılı açıklaması")
    log_sample: str = Field(description="Temsili log satırları")
    indicators: list[str] = Field(
        default_factory=list,
        description="Tehdit göstergeleri (IoC'ler)"
    )

    # Hafıza: geçmişte nasıl çözüldü?
    mitigations: list[str] = Field(
        default_factory=list,
        description="Bu vakada işe yarayan önlemler"
    )
    resolution_time_hours: float | None = Field(
        default=None,
        description="Olayın çözüm süresi (saat)"
    )

    # Embedding için birleşik metin (ChromaDB'ye bu gönderilir)
    @property
    def embedding_text(self) -> str:
        """Semantik arama için en bilgi yoğun metin."""
        return (
            f"{self.title}. "
            f"Attack type: {self.attack_type.value}. "
            f"MITRE: {self.mitre_technique_id} {self.mitre_technique_name}. "
            f"{self.description} "
            f"Indicators: {', '.join(self.indicators)}. "
            f"Log sample: {self.log_sample}"
        )
