"""
webapp/app.py – Agentic SOC için localde çalışan FastAPI dashboard.

Mevcut pipeline/knowledge_base koduna doğrudan import ile bağlanır; ayrı bir
sunucu süreci veya kalıcı katman eklemez. İşlenen olayların geçmişi (recent
events) sadece bellekte tutulur, sunucu yeniden başlayınca sıfırlanır.

Çalıştır:
    python -m src.agentic_soc.webapp
Sonra tarayıcıda: http://127.0.0.1:8000
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ..engine.models import AgentState
from ..engine.pipeline import analyze_log_text
from ..knowledge_base.storage import count_cases, list_cases
from ..utils.config import settings
from ..utils.llm_client import check_ollama_connection

app = FastAPI(title="Agentic SOC Dashboard")

# webapp/ -> agentic_soc/ -> src/ -> proje kökü
_REPO_ROOT = Path(__file__).resolve().parents[3]
_LAB_LOGS_DIR = _REPO_ROOT / "lab" / "logs"
_TEMPLATE_PATH = Path(__file__).parent / "templates" / "dashboard.html"

# Oturum boyunca bellekte tutulan analiz geçmişi – kalıcı değil.
_recent_events: list[dict] = []
_MAX_RECENT = 50


class AnalyzeRequest(BaseModel):
    log_file: str | None = None
    log_text: str | None = None


def _summarize(result: dict) -> dict:
    """AgentState dict'inden dashboard'a gönderilecek küçük JSON özeti çıkar."""
    state = AgentState(**result)
    triage = state.triage_result
    analysis = state.analysis_result
    mitigation = state.mitigation_result

    return {
        "event_id": state.event.event_id,
        "source_ip": state.event.source_ip,
        "failed_attempts": state.event.failed_attempts,
        "successful_attempts": state.event.successful_attempts,
        "attempted_usernames": state.event.attempted_usernames,
        "threat_level": triage.threat_level.value if triage else None,
        "confidence": triage.confidence if triage else None,
        "triage_reason": triage.reason if triage else None,
        "mitre_technique_id": analysis.mitre_technique_id if analysis else None,
        "mitre_technique_name": analysis.mitre_technique_name if analysis else None,
        "attack_description": analysis.attack_description if analysis else None,
        "attacker_intent": analysis.attacker_intent if analysis else None,
        "potential_impact": analysis.potential_impact if analysis else None,
        "immediate_actions": mitigation.immediate_actions if mitigation else [],
        "short_term_actions": mitigation.short_term_actions if mitigation else [],
        "long_term_actions": mitigation.long_term_actions if mitigation else [],
        "example_commands": mitigation.example_commands if mitigation else [],
        "errors": state.errors,
    }


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return _TEMPLATE_PATH.read_text(encoding="utf-8")


@app.get("/api/status")
def api_status() -> dict:
    connected, message = check_ollama_connection()
    return {
        "ollama_connected": connected,
        "ollama_message": message,
        "ollama_model": settings.ollama_model,
        "kb_case_count": count_cases(),
    }


@app.get("/api/kb/cases")
def api_kb_cases() -> list[dict]:
    return [case.model_dump() for case in list_cases()]


@app.get("/api/kb/stats")
def api_kb_stats() -> dict:
    cases = list_cases()
    by_severity: dict[str, int] = {}
    by_attack_type: dict[str, int] = {}
    for case in cases:
        by_severity[case.severity.value] = by_severity.get(case.severity.value, 0) + 1
        by_attack_type[case.attack_type.value] = by_attack_type.get(case.attack_type.value, 0) + 1
    return {"total": len(cases), "by_severity": by_severity, "by_attack_type": by_attack_type}


@app.get("/api/logs/samples")
def api_log_samples() -> list[str]:
    if not _LAB_LOGS_DIR.exists():
        return []
    return sorted(
        str(p.relative_to(_REPO_ROOT)) for p in _LAB_LOGS_DIR.rglob("*.log")
    )


@app.get("/api/events/recent")
def api_recent_events() -> list[dict]:
    return _recent_events


@app.post("/api/analyze")
def api_analyze(req: AnalyzeRequest) -> list[dict]:
    if req.log_file:
        path = (_REPO_ROOT / req.log_file) if not Path(req.log_file).is_absolute() else Path(req.log_file)
        try:
            path = path.resolve()
            path.relative_to(_REPO_ROOT)  # proje dışına çıkışı engelle
        except ValueError:
            raise HTTPException(status_code=400, detail="log_file proje dizini dışında olamaz")
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"Log dosyası bulunamadı: {req.log_file}")
        text = path.read_text(encoding="utf-8", errors="ignore")
        source = req.log_file
    elif req.log_text:
        text = req.log_text
        source = "manual-input"
    else:
        raise HTTPException(status_code=400, detail="log_file veya log_text belirtilmeli")

    raw_results = analyze_log_text(text, source=source)
    if not raw_results:
        raise HTTPException(status_code=422, detail="SSH ile ilgili log satırı bulunamadı")

    summaries = [_summarize(r) for r in raw_results]
    _recent_events[:0] = summaries
    del _recent_events[_MAX_RECENT:]
    return summaries
