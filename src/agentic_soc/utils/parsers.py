"""
utils/parsers.py – Ham SSH log satırlarını yapılandırılmış nesnelere dönüştürme.

Desteklenen log formatları:
  - OpenSSH auth.log (syslog formatı)
  - Docker stream çıktısı (aynı format, prefix farklı olabilir)
"""

import re
from datetime import datetime
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Veri yapısı
# ---------------------------------------------------------------------------

@dataclass
class ParsedSSHEvent:
    """Tek bir SSH log satırından çıkarılan bilgiler."""

    raw: str                          # Orijinal ham log satırı
    timestamp: datetime               # Parse edilen zaman damgası (yoksa şimdiki zaman)
    event_type: str                   # "failed_password" | "invalid_user" | "accepted" | "other"
    ip_address: str | None = None     # Kaynak IP
    username: str | None = None       # Denenen kullanıcı adı
    port: str | None = None           # Bağlantı portu


# ---------------------------------------------------------------------------
# Regex kalıpları
# ---------------------------------------------------------------------------

# Örnek: "Failed password for root from 192.168.1.100 port 54321 ssh2"
_FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)",
    re.IGNORECASE,
)

# Örnek: "Invalid user admin from 192.168.1.100 port 54321"
_INVALID_USER = re.compile(
    r"Invalid user (\S+) from ([\d.]+) port (\d+)",
    re.IGNORECASE,
)

# Örnek: "Accepted password for bedian from 10.0.0.1 port 22 ssh2"
_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port (\d+)",
    re.IGNORECASE,
)

# Syslog timestamp: "Jun 23 14:05:01"
_SYSLOG_TS = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)


# ---------------------------------------------------------------------------
# Parse fonksiyonları
# ---------------------------------------------------------------------------

def _parse_timestamp(line: str) -> datetime:
    """Syslog tarih damgasını parse et; bulunamazsa şimdiki zamanı döndür."""
    m = _SYSLOG_TS.match(line)
    if m:
        try:
            ts_str = m.group(1)
            # Yıl bilgisi yok, mevcut yılı kullan
            return datetime.strptime(f"{datetime.now().year} {ts_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            pass
    return datetime.now()


def parse_ssh_line(raw_line: str) -> ParsedSSHEvent | None:
    """
    Tek bir SSH log satırını parse et.

    Args:
        raw_line: Ham log satırı (syslog formatı veya Docker stream çıktısı)

    Returns:
        ParsedSSHEvent nesnesi ya da ilgisiz bir satırsa None
    """
    line = raw_line.strip()
    if not line:
        return None

    timestamp = _parse_timestamp(line)

    # Başarısız şifre denemesi
    m = _FAILED_PASSWORD.search(line)
    if m:
        return ParsedSSHEvent(
            raw=line,
            timestamp=timestamp,
            event_type="failed_password",
            username=m.group(1),
            ip_address=m.group(2),
            port=m.group(3),
        )

    # Geçersiz kullanıcı
    m = _INVALID_USER.search(line)
    if m:
        return ParsedSSHEvent(
            raw=line,
            timestamp=timestamp,
            event_type="invalid_user",
            username=m.group(1),
            ip_address=m.group(2),
            port=m.group(3),
        )

    # Başarılı giriş
    m = _ACCEPTED.search(line)
    if m:
        return ParsedSSHEvent(
            raw=line,
            timestamp=timestamp,
            event_type="accepted",
            username=m.group(1),
            ip_address=m.group(2),
            port=m.group(3),
        )

    # SSH ile ilgili ama kategorize edilemeyen satır
    lower = line.lower()
    if any(kw in lower for kw in ("sshd", "ssh", "auth")):
        return ParsedSSHEvent(raw=line, timestamp=timestamp, event_type="other")

    return None


def parse_ssh_lines(lines: list[str]) -> list[ParsedSSHEvent]:
    """Birden fazla satırı parse et, None sonuçları filtrele."""
    results = []
    for line in lines:
        event = parse_ssh_line(line)
        if event is not None:
            results.append(event)
    return results
