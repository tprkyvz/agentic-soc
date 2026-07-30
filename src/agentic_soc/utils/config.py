"""
utils/config.py – Ortam değişkenlerinden konfigürasyon yükleme.
Pydantic Settings ile tip güvenli konfigürasyon yönetimi.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """
    Agentic SOC konfigürasyon modeli.
    .env dosyasından veya ortam değişkenlerinden otomatik okunur.
    """

    # Ollama
    ollama_base_url: str = Field(default="http://localhost:11434", description="Ollama API adresi")
    ollama_model: str = Field(default="llama3.2", description="Kullanılacak Ollama modeli")

    # Loglama
    log_level: str = Field(default="INFO", description="Log seviyesi")

    # Lab / Docker
    ssh_container_name: str = Field(
        default="victim_ssh_server", description="Dinlenecek Docker container adı (SSH senaryosu)"
    )
    ssh_log_filter_keywords: str = Field(
        default="sshd,failed,invalid,authentication",
        description="Log filtresi için anahtar kelimeler (virgülle ayrılmış)",
    )
    web_container_name: str = Field(
        default="victim_web_server", description="Dinlenecek Docker container adı (web senaryosu)"
    )

    # Triage eşikleri – SSH
    triage_suspicious_threshold: int = Field(
        default=5, description="Şüpheli kabul için minimum başarısız giriş sayısı"
    )
    triage_malicious_threshold: int = Field(
        default=20, description="Kesin saldırı kabul için minimum başarısız giriş sayısı"
    )
    triage_time_window_seconds: int = Field(
        default=60, description="Olay gruplama zaman penceresi (saniye)"
    )

    # Triage eşikleri – Web (SQLi/XSS)
    # Tek bir gerçek SQLi/XSS payload'ı, birkaç yanlış yazılmış SSH şifresinden
    # çok daha kasıtlı bir sinyaldir; bu yüzden eşikler SSH'e göre çok daha düşük.
    triage_web_suspicious_threshold: int = Field(
        default=1, description="Şüpheli kabul için minimum SQLi/XSS imza sayısı"
    )
    triage_web_malicious_threshold: int = Field(
        default=3, description="Kesin saldırı kabul için minimum SQLi/XSS imza sayısı"
    )

    @property
    def ssh_keywords(self) -> list[str]:
        """Filtre kelimelerini liste olarak döndür."""
        return [kw.strip().lower() for kw in self.ssh_log_filter_keywords.split(",")]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


# Singleton – tek bir settings nesnesi tüm modüllerde paylaşılır
settings = Settings()
