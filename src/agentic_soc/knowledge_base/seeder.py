"""
knowledge_base/seeder.py – KB'yi başlangıç saldırı vakalarıyla doldurur.

Çalıştır:
    python -m src.agentic_soc.knowledge_base.seeder

MITRE ATT&CK framework'üne dayalı gerçekçi vakalar içerir.
"""

from rich.console import Console
from rich.progress import track

from .schemas import AttackCase, AttackType, Severity
from .storage import save_cases, count_cases

console = Console()

# ---------------------------------------------------------------------------
# Başlangıç vakası kataloğu
# ---------------------------------------------------------------------------

SEED_CASES: list[AttackCase] = [

    # ── SSH Saldırıları ──────────────────────────────────────────────────────

    AttackCase(
        id="ssh-bruteforce-001",
        title="SSH Password Brute-Force (Root Account)",
        attack_type=AttackType.BRUTE_FORCE,
        mitre_technique_id="T1110.001",
        mitre_technique_name="Brute Force: Password Guessing",
        severity=Severity.CRITICAL,
        description=(
            "Saldırgan, SSH servisi üzerinde root hesabına yönelik sistematik "
            "şifre tahminleri yaparak yetkisiz erişim elde etti. "
            "60 saniye içinde 28 başarısız denemeden sonra giriş başarılı oldu."
        ),
        log_sample=(
            "Failed password for root from 192.168.1.100 port 51242 ssh2\n"
            "Failed password for root from 192.168.1.100 port 51243 ssh2\n"
            "Accepted password for root from 192.168.1.100 port 51254 ssh2"
        ),
        indicators=[
            "high_failed_login_count",
            "single_source_ip",
            "root_account_targeted",
            "rapid_sequential_attempts",
            "successful_login_after_failures",
        ],
        mitigations=[
            "Block source IP with iptables/ufw immediately",
            "Install and configure fail2ban",
            "Disable root SSH login (PermitRootLogin no)",
            "Switch to key-based authentication only",
            "Change SSH port from default 22",
        ],
        resolution_time_hours=0.5,
    ),

    AttackCase(
        id="ssh-bruteforce-002",
        title="SSH Password Spraying (Multiple Usernames)",
        attack_type=AttackType.BRUTE_FORCE,
        mitre_technique_id="T1110.003",
        mitre_technique_name="Brute Force: Password Spraying",
        severity=Severity.HIGH,
        description=(
            "Saldırgan, tek bir IP'den çok sayıda farklı kullanıcı adı deneyerek "
            "şifre spreyi saldırısı gerçekleştirdi. "
            "admin, ubuntu, pi, test, oracle gibi yaygın hesaplar hedef alındı."
        ),
        log_sample=(
            "Invalid user admin from 10.0.0.55 port 44001\n"
            "Invalid user ubuntu from 10.0.0.55 port 44002\n"
            "Invalid user pi from 10.0.0.55 port 44003\n"
            "Failed password for invalid user admin from 10.0.0.55 port 44001 ssh2"
        ),
        indicators=[
            "multiple_invalid_usernames",
            "single_source_ip",
            "common_username_patterns",
            "moderate_attempt_rate",
        ],
        mitigations=[
            "Block source IP",
            "Enable fail2ban with low threshold",
            "Implement account lockout policy",
            "Monitor for distributed spraying from multiple IPs",
        ],
        resolution_time_hours=1.0,
    ),

    AttackCase(
        id="ssh-bruteforce-003",
        title="SSH Distributed Brute-Force (Botnet)",
        attack_type=AttackType.BRUTE_FORCE,
        mitre_technique_id="T1110.001",
        mitre_technique_name="Brute Force: Password Guessing",
        severity=Severity.HIGH,
        description=(
            "Çok sayıda farklı IP adresinden koordineli SSH brute-force saldırısı. "
            "Her IP düşük sayıda deneme yaparak fail2ban'dan kaçınmaya çalışıyor. "
            "Tipik botnet davranışı."
        ),
        log_sample=(
            "Failed password for root from 45.33.32.156 port 12345 ssh2\n"
            "Failed password for root from 23.239.9.246 port 23456 ssh2\n"
            "Failed password for admin from 198.199.121.200 port 34567 ssh2"
        ),
        indicators=[
            "multiple_source_ips",
            "low_attempts_per_ip",
            "coordinated_timing",
            "common_target_usernames",
        ],
        mitigations=[
            "Deploy GeoIP blocking for unused regions",
            "Implement rate limiting per /24 subnet",
            "Use CrowdSec or similar community threat intelligence",
            "Consider VPN/jump host for SSH access",
        ],
        resolution_time_hours=4.0,
    ),

    # ── Credential Saldırıları ───────────────────────────────────────────────

    AttackCase(
        id="default-creds-001",
        title="Default Credentials Login (IoT/Service Account)",
        attack_type=AttackType.CREDENTIAL_STUFFING,
        mitre_technique_id="T1078.001",
        mitre_technique_name="Valid Accounts: Default Accounts",
        severity=Severity.CRITICAL,
        description=(
            "Saldırgan, cihaz/servis için fabrika varsayılan kimlik bilgilerini "
            "(örn: admin:admin, pi:raspberry) kullanarak başarılı giriş yaptı. "
            "Minimal başarısız deneme sayısı saldırganın doğrudan varsayılan "
            "şifreyi bildiğini gösteriyor."
        ),
        log_sample=(
            "Failed password for pi from 185.220.101.45 port 55123 ssh2\n"
            "Accepted password for pi from 185.220.101.45 port 55124 ssh2"
        ),
        indicators=[
            "few_failed_attempts",
            "quick_success",
            "default_account_names",
            "external_ip_source",
        ],
        mitigations=[
            "Change all default passwords immediately",
            "Disable unused default accounts",
            "Audit all accounts for default credentials",
            "Implement password policy enforcement",
        ],
        resolution_time_hours=2.0,
    ),

    # ── Ağ Keşif Saldırıları ─────────────────────────────────────────────────

    AttackCase(
        id="port-scan-001",
        title="SSH Port Scanning / Service Enumeration",
        attack_type=AttackType.PORT_SCAN,
        mitre_technique_id="T1046",
        mitre_technique_name="Network Service Discovery",
        severity=Severity.LOW,
        description=(
            "Saldırgan SSH servisini keşfetmek amacıyla port taraması yaptı. "
            "Çok sayıda bağlantı girişimi ancak minimal kimlik doğrulama "
            "aktivitesi bu davranışı gösteriyor. Genellikle daha büyük "
            "bir saldırının öncüsüdür."
        ),
        log_sample=(
            "Connection closed by 203.0.113.42 port 44444 [preauth]\n"
            "Connection closed by 203.0.113.42 port 44445 [preauth]\n"
            "Did not receive identification string from 203.0.113.42"
        ),
        indicators=[
            "many_preauth_disconnects",
            "no_login_attempts",
            "rapid_connections",
            "recon_pattern",
        ],
        mitigations=[
            "Change SSH to non-standard port",
            "Enable port knocking",
            "Block scanning IPs",
            "Set MaxStartups to limit concurrent connections",
        ],
        resolution_time_hours=0.25,
    ),

    # ── Web Uygulama Saldırıları ─────────────────────────────────────────────

    AttackCase(
        id="sqli-001",
        title="SQL Injection via Search/ID Parameter (UNION-based)",
        attack_type=AttackType.SQL_INJECTION,
        mitre_technique_id="T1190",
        mitre_technique_name="Exploit Public-Facing Application",
        severity=Severity.CRITICAL,
        description=(
            "Saldırgan, web uygulamasının arama/ID parametresine UNION SELECT tabanlı "
            "SQL enjeksiyonu payload'ları göndererek veritabanından hassas veri "
            "(kullanıcı adı, şifre) sızdırmaya çalıştı. Kısa süre içinde birden fazla "
            "farklı SQLi tekniği (UNION SELECT, boolean tautoloji, yorum satırı "
            "sonlandırma) tek bir IP'den denendi."
        ),
        log_sample=(
            "203.0.113.77 - - [30/Jul/2026:16:45:11 +0000] \"GET /product?id=1'/**/OR/**/'1'='1 HTTP/1.1\" 404 162 \"-\" \"curl/8.14.1\"\n"
            "203.0.113.77 - - [30/Jul/2026:16:45:12 +0000] \"GET /product?id=1/**/UNION/**/SELECT/**/username,password/**/FROM/**/users-- HTTP/1.1\" 404 162 \"-\" \"curl/8.14.1\""
        ),
        indicators=[
            "union_select_pattern",
            "boolean_tautology",
            "information_schema_probe",
            "single_source_ip",
            "repeated_4xx_on_dynamic_paths",
        ],
        mitigations=[
            "Deploy a WAF with SQLi rule sets (e.g. ModSecurity CRS)",
            "Use parameterized queries/prepared statements exclusively",
            "Apply least-privilege DB accounts (no information_schema access for app user)",
            "Rate-limit/block source IP after repeated 4xx on dynamic endpoints",
        ],
        resolution_time_hours=1.5,
    ),

    AttackCase(
        id="xss-001",
        title="Reflected Cross-Site Scripting (XSS) via Query Parameter",
        attack_type=AttackType.XSS,
        mitre_technique_id="T1190",
        mitre_technique_name="Exploit Public-Facing Application",
        severity=Severity.HIGH,
        description=(
            "Saldırgan, web uygulamasının yorum/arama parametresine <script> etiketleri "
            "ve olay işleyicileri (onerror, javascript:) içeren yansıtılmış XSS "
            "payload'ları enjekte etmeye çalıştı. Amaç, diğer kullanıcıların "
            "tarayıcısında JavaScript çalıştırarak oturum çerezlerini (document.cookie) "
            "çalmak."
        ),
        log_sample=(
            "203.0.113.77 - - [30/Jul/2026:16:45:20 +0000] \"GET /comment?name=<script>alert(document.cookie)</script> HTTP/1.1\" 404 162 \"-\" \"curl/8.14.1\""
        ),
        indicators=[
            "script_tag_injection",
            "event_handler_injection",
            "javascript_uri_scheme",
            "cookie_theft_attempt",
            "single_source_ip",
        ],
        mitigations=[
            "Implement Content-Security-Policy (CSP) headers restricting inline scripts",
            "Contextually HTML-encode all user-supplied output before rendering",
            "Set HttpOnly and Secure flags on session cookies",
            "Deploy WAF rules for XSS signatures",
        ],
        resolution_time_hours=1.0,
    ),
]


# ---------------------------------------------------------------------------
# Seeder ana fonksiyonu
# ---------------------------------------------------------------------------

def seed_knowledge_base(force: bool = False) -> None:
    """
    KB'yi başlangıç vakaları ile doldur.

    Args:
        force: True ise zaten dolu olsa bile yeniden yükler
    """
    current_count = count_cases()

    if current_count > 0 and not force:
        console.print(
            f"[yellow]⚠ KB zaten {current_count} vaka içeriyor. "
            f"Yeniden yüklemek için --force kullan.[/yellow]"
        )
        return

    console.print(f"[cyan]🌱 Knowledge Base dolduruluyor ({len(SEED_CASES)} vaka)...[/cyan]")
    console.print("[dim]Her vaka için embedding hesaplanıyor (Ollama nomic-embed-text)...[/dim]\n")

    for case in track(SEED_CASES, description="Vakalar yükleniyor"):
        save_cases([case])

    final_count = count_cases()
    console.print(f"\n[green]✅ Tamamlandı! KB'de {final_count} vaka mevcut.[/green]")


if __name__ == "__main__":
    import sys
    force = "--force" in sys.argv
    seed_knowledge_base(force=force)
