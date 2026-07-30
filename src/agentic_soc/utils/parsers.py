"""
utils/parsers.py – Ham log satırlarını yapılandırılmış nesnelere dönüştürme.

Desteklenen log formatları:
  - OpenSSH auth.log (syslog formatı)
  - Nginx/Apache combined access log (web SQLi/XSS senaryosu)
  - Docker stream çıktısı (aynı format, prefix farklı olabilir)
"""

import re
import urllib.parse
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


# ---------------------------------------------------------------------------
# Web (Nginx/Apache combined access log) parse desteği
# ---------------------------------------------------------------------------

@dataclass
class ParsedWebEvent:
    """Tek bir web erişim log satırından çıkarılan bilgiler."""

    raw: str
    timestamp: datetime
    ip_address: str | None
    method: str | None
    path: str | None
    status_code: int | None
    event_type: str                                 # "sqli_attempt" | "xss_attempt" | "benign"
    matched_signatures: list[str] = field(default_factory=list)


# Nginx'in varsayılan "main" log_format'ı (Apache "combined" ile aynı yapıda):
#   $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
_ACCESS_LOG_LINE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>[^\s"]+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# nginx $time_local örneği: "30/Jul/2026:16:45:12 +0000" – SSH'in syslog
# formatından farklı, ayrı bir parser gerekiyor.
_WEB_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

_SEP = r"(?:\s|/\*.*?\*/)"  # SQL token ayırıcı: boşluk veya satır-içi yorum (/**/)

_SQLI_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("union_select", re.compile(rf"\bunion\b{_SEP}*\bselect\b", re.IGNORECASE)),
    # Tırnaksız (OR 1=1) ve tırnaklı (OR '1'='1') tautoloji biçimlerinin ikisini de yakalar.
    ("boolean_tautology", re.compile(
        rf"\b(?:or|and)\b{_SEP}+['\"]?\d+['\"]?{_SEP}*=\s*['\"]?\d+['\"]?", re.IGNORECASE
    )),
    ("sql_comment_terminator", re.compile(r"--\s|--$|/\*.*?\*/\s*--?", re.IGNORECASE)),
    ("stacked_query", re.compile(r";\s*(?:drop|delete|update|insert|alter)\b", re.IGNORECASE)),
    ("sleep_benchmark", re.compile(r"\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", re.IGNORECASE)),
    ("information_schema", re.compile(r"information_schema|sysobjects|syscolumns", re.IGNORECASE)),
    ("quote_injection", re.compile(rf"'{_SEP}*(?:or|and){_SEP}*'", re.IGNORECASE)),
]

_XSS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("script_tag", re.compile(r"<\s*script\b", re.IGNORECASE)),
    ("event_handler", re.compile(r"\bon(?:error|load|mouseover|focus|click)\s*=", re.IGNORECASE)),
    ("javascript_uri", re.compile(r"javascript\s*:", re.IGNORECASE)),
    ("html_vector_tag", re.compile(r"<\s*(?:img|svg|iframe)\b", re.IGNORECASE)),
    ("document_cookie", re.compile(r"document\.(?:cookie|location)", re.IGNORECASE)),
    ("alert_call", re.compile(r"\balert\s*\(", re.IGNORECASE)),
]


def _parse_web_timestamp(ts_str: str) -> datetime:
    """Nginx $time_local damgasını parse et; bulunamazsa şimdiki zamanı döndür."""
    try:
        return datetime.strptime(ts_str, _WEB_TS_FORMAT)
    except ValueError:
        return datetime.now()


def parse_web_line(raw_line: str) -> ParsedWebEvent | None:
    """
    Tek bir Nginx/Apache combined access log satırını parse et.

    Path+query bir kere decode edilip (urllib.parse.unquote) imza taraması
    tek bir geçişte yapılır – hem düz metin hem yüzde-kodlu (%27, %3Cscript%3E)
    payload'lar aynı desenlerle yakalanır. Çift kodlama (%2527 vb.) bu sürümde
    yakalanmaz, bilinen bir sınırlamadır.

    Returns:
        ParsedWebEvent nesnesi ya da satır formatı eşleşmiyorsa None.
    """
    line = raw_line.strip()
    if not line:
        return None

    m = _ACCESS_LOG_LINE.match(line)
    if not m:
        return None

    decoded_path = urllib.parse.unquote(m.group("path") or "", errors="replace")

    matched: list[str] = [name for name, pattern in _SQLI_PATTERNS if pattern.search(decoded_path)]
    event_type = "sqli_attempt" if matched else "benign"

    xss_matched = [name for name, pattern in _XSS_PATTERNS if pattern.search(decoded_path)]
    if xss_matched:
        matched = matched + xss_matched
        if event_type == "benign":
            event_type = "xss_attempt"

    status_str = m.group("status")
    return ParsedWebEvent(
        raw=line,
        timestamp=_parse_web_timestamp(m.group("ts")),
        ip_address=m.group("ip"),
        method=m.group("method"),
        path=m.group("path"),
        status_code=int(status_str) if status_str else None,
        event_type=event_type,
        matched_signatures=matched,
    )


def parse_web_lines(lines: list[str]) -> list[ParsedWebEvent]:
    """Birden fazla web log satırını parse et, None sonuçları filtrele."""
    results = []
    for line in lines:
        event = parse_web_line(line)
        if event is not None:
            results.append(event)
    return results
