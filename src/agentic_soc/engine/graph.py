"""
engine/graph.py – LangGraph ajan grafı tanımı (KB destekli).

Akış:
  START → triage → kb_query → analyst → mitigation → kb_save → END
                       ↑
                  (benign ise discard)
"""

from langgraph.graph import StateGraph, START, END

from .models import AgentState
from ..agents.triage_agent import triage_node, triage_router
from ..agents.analyst_agent import analyst_node
from ..agents.mitigation_agent import mitigation_node
from ..agents.kb_agent import kb_query_node, kb_save_node


def _discard_node(state: AgentState) -> AgentState:
    """Benign olaylar için terminal düğüm."""
    state.processing_completed = True
    return state


def _wrap(fn):
    """AgentState ↔ dict dönüşümü için wrapper fabrikası."""
    def wrapper(state: dict) -> dict:
        agent_state = AgentState(**state)
        result = fn(agent_state)
        return result.model_dump()
    return wrapper


def build_graph():
    """
    Agentic SOC LangGraph grafını oluştur ve derle.

    Düğümler:
        triage     – Kural tabanlı ilk filtre
        kb_query   – Benzer geçmiş vakaları KB'den çek (RAG)
        analyst    – LLM ile derin analiz (KB bağlamıyla)
        mitigation – LLM ile önlem önerileri
        kb_save    – Tamamlanan vakayı KB'ye kaydet (öğrenme)
        discard    – Benign olaylar için erken çıkış

    Akış:
        START → triage → (benign) discard → END
                       → (suspicious/malicious) kb_query → analyst → mitigation → kb_save → END
    """
    graph = StateGraph(dict)

    graph.add_node("triage", _wrap(triage_node))
    graph.add_node("kb_query", _wrap(kb_query_node))
    graph.add_node("analyst", _wrap(analyst_node))
    graph.add_node("mitigation", _wrap(mitigation_node))
    graph.add_node("kb_save", _wrap(kb_save_node))
    graph.add_node("discard", _wrap(_discard_node))

    graph.add_edge(START, "triage")

    graph.add_conditional_edges(
        "triage",
        lambda state: triage_router(AgentState(**state)),
        {
            "analyze": "kb_query",
            "discard": "discard",
        },
    )

    graph.add_edge("kb_query", "analyst")
    graph.add_edge("analyst", "mitigation")
    graph.add_edge("mitigation", "kb_save")
    graph.add_edge("kb_save", END)
    graph.add_edge("discard", END)

    return graph.compile()


soc_graph = build_graph()
