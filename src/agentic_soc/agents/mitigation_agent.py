"""
agents/mitigation_agent.py – Mitigation Advisor Agent.

Analyst Agent'tan gelen MITRE ATT&CK analizine göre somut önlemler üretir.
SSH brute-force için pratik komutlar dahil öneriler verir.
"""

import json
import re

from ..engine.models import AgentState, MitigationResult
from ..utils.llm_client import quick_invoke


_SYSTEM_PROMPT = """\
You are a cybersecurity incident responder. Respond ONLY with a JSON object. No explanation, no markdown, no extra text.

Your response must be exactly this JSON structure:
{"immediate_actions": ["action1", "action2"], "short_term_actions": ["action1", "action2"], "long_term_actions": ["action1"], "example_commands": ["command1", "command2"]}

Rules:
- Output ONLY the JSON object, nothing else
- Start your response with { and end with }
- No markdown code blocks, no explanations before or after
- Each action must be a short string under 120 characters
- Use double quotes for all strings
- immediate_actions: 2-3 items (block IP, alert team)
- short_term_actions: 2-3 items (harden config, install fail2ban)
- long_term_actions: 2 items (policy, monitoring)
- example_commands: 2-3 real Linux bash commands
"""


def _build_ssh_user_message(state: AgentState) -> str:
    event = state.event
    analysis = state.analysis_result
    triage = state.triage_result

    return f"""
Provide mitigation recommendations for the following security incident:

**Threat Level:** {triage.threat_level.value.upper() if triage else "UNKNOWN"}

**MITRE ATT&CK:**
- Technique: {analysis.mitre_technique_id if analysis else "Unknown"} – {analysis.mitre_technique_name if analysis else "Unknown"}

**Attack Details:**
- Source IP: {event.source_ip or "unknown"}
- Target Service: SSH (port 22)
- Failed Attempts: {event.failed_attempts}
- Successful Logins: {event.successful_attempts}
- Attempted Usernames: {', '.join(event.indicators[:5]) if event.indicators else "unknown"}

**Analysis Summary:**
{analysis.attack_description if analysis else "No analysis available."}

Provide practical mitigation steps with real Linux commands where possible.
""".strip()


def _build_web_user_message(state: AgentState) -> str:
    event = state.event
    analysis = state.analysis_result
    triage = state.triage_result

    return f"""
Provide mitigation recommendations for the following security incident:

**Threat Level:** {triage.threat_level.value.upper() if triage else "UNKNOWN"}

**MITRE ATT&CK:**
- Technique: {analysis.mitre_technique_id if analysis else "Unknown"} – {analysis.mitre_technique_name if analysis else "Unknown"}

**Attack Details:**
- Source IP: {event.source_ip or "unknown"}
- Target Service: Web application (HTTP)
- Malicious Requests Blocked/Not-Found: {event.failed_attempts}
- Malicious Requests That Returned HTTP 200: {event.successful_attempts}
- Matched Attack Indicators: {', '.join(event.indicators[:5]) if event.indicators else "unknown"}

**Analysis Summary:**
{analysis.attack_description if analysis else "No analysis available."}

Provide practical mitigation steps for a web application (WAF rules, input
validation/parameterized queries, output encoding, security headers) with
real example commands/config snippets where possible.
""".strip()


def _build_user_message(state: AgentState) -> str:
    """Mitigation prompt'unu senaryoya göre doldur (SSH vs web)."""
    if state.event.target_service == "web":
        return _build_web_user_message(state)
    return _build_ssh_user_message(state)


def _parse_llm_response(response_text: str) -> dict:
    """LLM yanıtından JSON'ı çıkar."""
    cleaned = re.sub(r"```(?:json)?\s*", "", response_text)
    cleaned = cleaned.replace("```", "").strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}") + 1
    if start == -1 or end == 0:
        raise ValueError(f"JSON bulunamadı: {response_text[:200]}")
    return json.loads(cleaned[start:end])


def _ssh_bruteforce_fallback(source_ip: str | None) -> MitigationResult:
    """SSH brute-force için statik fallback önerileri."""
    ip = source_ip or "<KAYNAK_IP>"
    return MitigationResult(
        immediate_actions=[
            f"Saldırgan IP'yi derhal güvenlik duvarında engelle: {ip}",
            "SSH servisini mevcut aktif oturumlar için kontrol et",
            "Güvenlik ekibini olay hakkında bilgilendir",
        ],
        short_term_actions=[
            "fail2ban kur ve SSH için yapılandır",
            "SSH root girişini devre dışı bırak (PermitRootLogin no)",
            "Şifre tabanlı girişi devre dışı bırak, SSH anahtar kimlik doğrulamasına geç",
            "SSH portunu standart 22'den değiştir",
        ],
        long_term_actions=[
            "Tüm sunucular için merkezi SSH anahtar yönetimi uygula",
            "IDS/IPS kurallarını SSH brute-force tespiti için güncelle",
            "Düzenli güvenlik denetimleri ve penetrasyon testleri planla",
        ],
        example_commands=[
            f"sudo ufw deny from {ip} to any",
            "sudo apt-get install -y fail2ban && sudo systemctl enable --now fail2ban",
            "sudo sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
            "sudo journalctl -u ssh --since '1 hour ago' | grep 'Accepted'",
        ],
    )


def _web_attack_fallback(source_ip: str | None) -> MitigationResult:
    """SQLi/XSS için statik fallback önerileri."""
    ip = source_ip or "<KAYNAK_IP>"
    return MitigationResult(
        immediate_actions=[
            f"Saldırgan IP'yi derhal engelle/rate-limit uygula: {ip}",
            "Etkilenen endpoint'i geçici olarak devre dışı bırak veya WAF kuralı ekle",
            "Güvenlik ekibini olay hakkında bilgilendir",
        ],
        short_term_actions=[
            "Tüm veritabanı sorgularını parametreli sorgulara/prepared statement'lara geçir",
            "Kullanıcı girdisini bağlama göre HTML/SQL için encode et",
            "ModSecurity gibi bir WAF kur ve OWASP CRS kurallarını etkinleştir",
            "Session cookie'lere HttpOnly ve Secure bayraklarını ekle",
        ],
        long_term_actions=[
            "Content-Security-Policy (CSP) header'ları ile inline script'leri kısıtla",
            "Uygulama veritabanı hesabına en az yetki (least privilege) prensibini uygula",
            "Düzenli güvenlik denetimleri ve penetrasyon testleri planla",
        ],
        example_commands=[
            f"sudo ufw deny from {ip} to any",
            "sudo apt-get install -y libapache2-mod-security2 && sudo a2enmod security2",
            "curl -I http://localhost | grep -i content-security-policy",
        ],
    )


def mitigation_node(state: AgentState) -> AgentState:
    """
    LangGraph düğümü: Mitigation.

    LLM'den somut önlem listesi alır.
    """
    try:
        user_message = _build_user_message(state)
        response_text = quick_invoke(
            system_prompt=_SYSTEM_PROMPT,
            user_message=user_message,
            temperature=0.2,
        )

        data = _parse_llm_response(response_text)
        state.mitigation_result = MitigationResult(**data)

    except (json.JSONDecodeError, Exception) as e:
        state.errors.append(f"Mitigation: {e} – Fallback kullanıldı")
        if state.event.target_service == "web":
            state.mitigation_result = _web_attack_fallback(state.event.source_ip)
        else:
            state.mitigation_result = _ssh_bruteforce_fallback(state.event.source_ip)

    state.processing_completed = True
    return state
