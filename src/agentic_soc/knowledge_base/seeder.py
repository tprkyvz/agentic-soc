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
