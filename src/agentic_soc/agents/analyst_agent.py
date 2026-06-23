"""
agents/analyst_agent.py – Analyst Agent.

Triage'dan SUSPICIOUS veya MALICIOUS etiketiyle gelen olayları LLM ile
derinlemesine analiz eder. MITRE ATT&CK haritalama ve saldırı açıklaması üretir.
"""

import json
import re

from ..engine.models import AgentState, AnalysisResult
from ..utils.llm_client import quick_invoke


_SYSTEM_PROMPT = """\
You are a cybersecurity analyst. Respond ONLY with a JSON object. No explanation, no markdown, no extra text.

Your response must be exactly this JSON structure:
{"mitre_technique_id": "T1110.001", "mitre_technique_name": "Brute Force: Password Guessing", "attack_description": "...", "attacker_intent": "...", "potential_impact": "..."}

Rules:
- Output ONLY the JSON object, nothing else
- Start your response with { and end with }
- No markdown code blocks, no explanations before or after
- Keep all string values under 150 characters
- Use double quotes for all strings
"""


def _build_user_message(state: AgentState) -> str:
    """Analyst prompt'unu state verisiyle doldur."""
    event = state.event
    triage = state.triage_result

    usernames_str = ", ".join(event.attempted_usernames[:10]) if event.attempted_usernames else "unknown"

    # KB bağlamı varsa ekle
    kb_section = ""
    if state.kb_context:
        kb_section = f"""

{state.kb_context}

Use the above past incidents as additional context for your analysis.
"""

    return f"""
Analyze the following SSH security event:{kb_section}
**Event Summary:**
- Source IP: {event.source_ip or "unknown"}
- Target Service: {event.target_service}
- Failed Login Attempts: {event.failed_attempts}
- Successful Logins: {event.successful_attempts}
- Time Window: {event.time_window_seconds} seconds
- Attempted Usernames: {usernames_str}
- Threat Level (pre-classified): {triage.threat_level.value if triage else "unknown"}
- Triage Reason: {triage.reason if triage else "N/A"}

**Raw Log Sample (first 3 entries):**
{chr(10).join(e.raw_log for e in event.raw_log_entries[:3]) if event.raw_log_entries else "No raw logs available"}

Provide your analysis as JSON.
""".strip()


def _parse_llm_response(response_text: str) -> dict:
    """LLM yanıtından JSON'ı çıkar (markdown code fence'leri temizle)."""
    # ```json ... ``` bloğunu temizle
    cleaned = re.sub(r"```(?:json)?\s*", "", response_text)
    cleaned = cleaned.replace("```", "").strip()

    # İlk { ile son } arasını al
    start = cleaned.find("{")
    end = cleaned.rfind("}") + 1
    if start == -1 or end == 0:
        raise ValueError(f"JSON bulunamadı. LLM yanıtı: {response_text[:200]}")

    return json.loads(cleaned[start:end])


def analyst_node(state: AgentState) -> AgentState:
    """
    LangGraph düğümü: Analyst.

    LLM'e olayı gönderir, MITRE ATT&CK haritalı analiz alır.
    """
    try:
        user_message = _build_user_message(state)
        response_text = quick_invoke(
            system_prompt=_SYSTEM_PROMPT,
            user_message=user_message,
            temperature=0.1,
        )

        data = _parse_llm_response(response_text)
        state.analysis_result = AnalysisResult(**data)

    except json.JSONDecodeError as e:
        state.errors.append(f"Analyst: JSON parse hatası – {e}")
        # Fallback: SSH brute-force için bilinen tekniği kullan
        state.analysis_result = AnalysisResult(
            mitre_technique_id="T1110.001",
            mitre_technique_name="Brute Force: Password Guessing",
            attack_description=(
                "Saldırgan, SSH servisi üzerinde sistematik şifre tahminleri yaparak "
                "yetkisiz erişim elde etmeye çalışmaktadır."
            ),
            attacker_intent="SSH üzerinden yetkisiz sistem erişimi elde etmek.",
            potential_impact=(
                "Başarılı bir brute-force saldırısı tam sistem erişimine, "
                "veri sızıntısına veya pivot saldırılarına yol açabilir."
            ),
        )

    except Exception as e:
        state.errors.append(f"Analyst: Beklenmeyen hata – {e}")
        state.analysis_result = AnalysisResult(
            mitre_technique_id="T1110",
            mitre_technique_name="Brute Force",
            attack_description="Analiz sırasında hata oluştu. Manuel inceleme gerekli.",
            attacker_intent="Bilinmiyor",
            potential_impact="Bilinmiyor",
        )

    return state
