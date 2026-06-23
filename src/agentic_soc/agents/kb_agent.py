"""
agents/kb_agent.py – Knowledge Base Agent.

İki rolü var:
  1. kb_query_node  – Analiz öncesi: benzer geçmiş vakaları bul, state'e ekle
  2. kb_save_node   – Analiz sonrası: tamamlanan vakayı KB'ye kaydet (sistem öğrenir)
"""

from __future__ import annotations

import uuid

from ..engine.models import AgentState, ThreatLevel
from ..knowledge_base.retriever import find_similar_cases, format_kb_context
from ..knowledge_base.schemas import AttackCase, AttackType, Severity
from ..knowledge_base.storage import save_case, count_cases


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

        new_case = AttackCase(
            id=f"learned-{state.event.event_id[:8]}",
            title=f"{analysis.mitre_technique_name} from {state.event.source_ip or 'unknown'}",
            attack_type=AttackType.BRUTE_FORCE,   # Şimdilik sabit, ilerleyen sürümde LLM belirleyecek
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
                *[f"username:{u}" for u in state.event.attempted_usernames[:3]],
            ],
            mitigations=mitigations,
        )

        save_case(new_case)

    except Exception as e:
        state.errors.append(f"KB Save: {e}")

    return state
