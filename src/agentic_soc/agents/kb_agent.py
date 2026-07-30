"""
agents/kb_agent.py – Knowledge Base Agent.

İki rolü var:
  1. kb_query_node  – Analiz öncesi: benzer geçmiş vakaları bul, state'e ekle
  2. kb_save_node   – Analiz sonrası: tamamlanan vakayı KB'ye kaydet (sistem öğrenir)
"""

from __future__ import annotations

from ..engine.models import AgentState, AnalysisResult, ThreatLevel
from ..knowledge_base.retriever import find_similar_cases, format_kb_context
from ..knowledge_base.schemas import AttackCase, AttackType, Severity
from ..knowledge_base.storage import save_case, count_cases

# MITRE ATT&CK teknik ID öneki → AttackType eşlemesi.
# Prefix, alt teknikleri de kapsayacak şekilde eşleşir (örn. "T1110" → "T1110.001").
_MITRE_PREFIX_TO_ATTACK_TYPE: dict[str, AttackType] = {
    "T1110": AttackType.BRUTE_FORCE,             # Brute Force
    "T1078": AttackType.CREDENTIAL_STUFFING,      # Valid Accounts (seed verisiyle tutarlı)
    "T1046": AttackType.PORT_SCAN,                # Network Service Discovery
    # T1190 (Exploit Public-Facing Application) kasıtlı olarak burada YOK:
    # hem SQLi hem XSS bu tekniğe eşleniyor, MITRE ATT&CK'te bu ikisi için ayrı
    # alt-teknik yok. Bu yüzden T1190 durumunda aşağıdaki anahtar kelime
    # eşlemesine düşülür. Not: bu, LLM'in açıklama metninde "sql injection"/
    # "xss" gibi kelimeler kullanmasına bağlı olduğundan garantili değildir –
    # bilinen bir sınırlama.
    "T1068": AttackType.PRIVILEGE_ESCALATION,     # Exploitation for Privilege Escalation
    "T1548": AttackType.PRIVILEGE_ESCALATION,     # Abuse Elevation Control Mechanism
    "T1021": AttackType.LATERAL_MOVEMENT,         # Remote Services
    "T1570": AttackType.LATERAL_MOVEMENT,         # Lateral Tool Transfer
    "T1041": AttackType.EXFILTRATION,             # Exfiltration Over C2 Channel
    "T1048": AttackType.EXFILTRATION,             # Exfiltration Over Alternative Protocol
}

# Teknik ID eşleşmezse açıklama metnindeki anahtar kelimelere göre ikinci tahmin.
_KEYWORD_TO_ATTACK_TYPE: list[tuple[str, AttackType]] = [
    ("sql injection", AttackType.SQL_INJECTION),
    ("cross-site scripting", AttackType.XSS),
    ("xss", AttackType.XSS),
    ("privilege escalation", AttackType.PRIVILEGE_ESCALATION),
    ("lateral movement", AttackType.LATERAL_MOVEMENT),
    ("exfiltrat", AttackType.EXFILTRATION),
    ("port scan", AttackType.PORT_SCAN),
    ("port taraması", AttackType.PORT_SCAN),
    ("credential stuffing", AttackType.CREDENTIAL_STUFFING),
    ("default credential", AttackType.CREDENTIAL_STUFFING),
    ("brute force", AttackType.BRUTE_FORCE),
    ("brute-force", AttackType.BRUTE_FORCE),
]


def _infer_attack_type(analysis: AnalysisResult) -> AttackType:
    """
    Analyst'in ürettiği MITRE teknik ID'sinden (ve gerekirse açıklama
    metninden) en uygun AttackType'ı çıkar. Hiçbiri eşleşmezse UNKNOWN döner.
    """
    technique_id = analysis.mitre_technique_id or ""
    for prefix, attack_type in _MITRE_PREFIX_TO_ATTACK_TYPE.items():
        if technique_id.startswith(prefix):
            return attack_type

    haystack = f"{analysis.mitre_technique_name} {analysis.attack_description}".lower()
    for keyword, attack_type in _KEYWORD_TO_ATTACK_TYPE:
        if keyword in haystack:
            return attack_type

    return AttackType.UNKNOWN


def kb_query_node(state: AgentState) -> AgentState:
    """
    LangGraph düğümü: KB Sorgu.

    Gelen olaya semantik olarak benzer geçmiş vakaları KB'den çeker
    ve AgentState'e ekler. Analyst Agent bu bağlamı kullanır.
    """
    # KB boşsa atla
    if count_cases() == 0:
        state.kb_results = []
        state.kb_context = ""
        return state

    try:
        results = find_similar_cases(state.event, n_results=3, min_similarity=0.25)
        state.kb_results = [case for case, _ in results]
        state.kb_context = format_kb_context(results)
    except Exception as e:
        # KB hatası tüm pipeline'ı durdurmamalı
        state.errors.append(f"KB Query: {e}")
        state.kb_results = []
        state.kb_context = ""

    return state


def kb_save_node(state: AgentState) -> AgentState:
    """
    LangGraph düğümü: KB Kaydet.

    Tamamlanmış analizi (triage + analyst + mitigation sonuçları) KB'ye yazar.
    Bu sayede sistem her yeni olaydan öğrenir.
    Sadece SUSPICIOUS veya MALICIOUS olaylar kaydedilir (benign'i kaydetmiyoruz).
    """
    triage = state.triage_result
    analysis = state.analysis_result

    # Kaydetmeye değer mi?
    if triage is None or analysis is None:
        return state
    if triage.threat_level == ThreatLevel.BENIGN:
        return state

    try:
        # Severity haritalama
        severity_map = {
            ThreatLevel.SUSPICIOUS: Severity.MEDIUM,
            ThreatLevel.MALICIOUS: Severity.CRITICAL,
        }

        # Mitigation listesi
        mitigations: list[str] = []
        if state.mitigation_result:
            mitigations = (
                state.mitigation_result.immediate_actions[:2]
                + state.mitigation_result.short_term_actions[:2]
            )

        # SSH'te göstergeler çıplak kullanıcı adı ("admin"); "username:" öneki
        # burada eklenir. Web'de göstergeler zaten kendini açıklayan, hazır
        # metinlerdir (örn. "sql_injection: union_select") – tekrar
        # öneklemek "username:sql_injection: ..." gibi anlamsız bir sonuç verirdi.
        if state.event.target_service == "web":
            scenario_indicators = list(state.event.indicators[:3])
        else:
            scenario_indicators = [f"username:{u}" for u in state.event.indicators[:3]]

        new_case = AttackCase(
            id=f"learned-{state.event.event_id[:8]}",
            title=f"{analysis.mitre_technique_name} from {state.event.source_ip or 'unknown'}",
            attack_type=_infer_attack_type(analysis),
            mitre_technique_id=analysis.mitre_technique_id,
            mitre_technique_name=analysis.mitre_technique_name,
            severity=severity_map.get(triage.threat_level, Severity.HIGH),
            description=analysis.attack_description,
            log_sample="\n".join(
                e.raw_log for e in state.event.raw_log_entries[:3]
            ),
            indicators=[
                f"failed_attempts:{state.event.failed_attempts}",
                f"source_ip:{state.event.source_ip}",
                *scenario_indicators,
            ],
            mitigations=mitigations,
        )

        save_case(new_case)

    except Exception as e:
        state.errors.append(f"KB Save: {e}")

    return state
