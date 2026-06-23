"""
engine/graph.py – LangGraph ajan grafı tanımı.

Akış:
  START → triage → [benign: END] | [suspicious/malicious: analyst → mitigation → END]
"""

from langgraph.graph import StateGraph, START, END

from .models import AgentState
from ..agents.triage_agent import triage_node, triage_router
from ..agents.analyst_agent import analyst_node
from ..agents.mitigation_agent import mitigation_node


def _discard_node(state: AgentState) -> AgentState:
    """Benign olaylar için terminal düğüm. Sadece işaret koyar."""
    state.processing_completed = True
    return state


def build_graph() -> StateGraph:
    """
    Agentic SOC LangGraph grafını oluştur ve derle.

    Düğümler:
        triage    – Kural tabanlı ilk filtre
        analyst   – LLM ile derin analiz
        mitigation – LLM ile önlem önerileri
        discard   – Benign olaylar için erken çıkış

    Kenarlar:
        START → triage
        triage → (koşullu) analyst | discard
        analyst → mitigation
        mitigation → END
        discard → END
    """
    # Dict tabanlı state için graph'ı dict ile tanımla
    # AgentState Pydantic modeli olduğu için dict wrapper kullanıyoruz
    graph = StateGraph(dict)

    # Pydantic nesnelerini dict'e saran wrapper'lar
    def triage_wrapper(state: dict) -> dict:
        agent_state = AgentState(**state)
        result = triage_node(agent_state)
        return result.model_dump()

    def analyst_wrapper(state: dict) -> dict:
        agent_state = AgentState(**state)
        result = analyst_node(agent_state)
        return result.model_dump()

    def mitigation_wrapper(state: dict) -> dict:
        agent_state = AgentState(**state)
        result = mitigation_node(agent_state)
        return result.model_dump()

    def discard_wrapper(state: dict) -> dict:
        agent_state = AgentState(**state)
        result = _discard_node(agent_state)
        return result.model_dump()

    def router_wrapper(state: dict) -> str:
        agent_state = AgentState(**state)
        return triage_router(agent_state)

    # Düğümleri ekle
    graph.add_node("triage", triage_wrapper)
    graph.add_node("analyst", analyst_wrapper)
    graph.add_node("mitigation", mitigation_wrapper)
    graph.add_node("discard", discard_wrapper)

    # Kenarları ekle
    graph.add_edge(START, "triage")
    graph.add_conditional_edges(
        "triage",
        router_wrapper,
        {
            "analyze": "analyst",
            "discard": "discard",
        },
    )
    graph.add_edge("analyst", "mitigation")
    graph.add_edge("mitigation", END)
    graph.add_edge("discard", END)

    return graph.compile()


# Singleton – modül import edildiğinde hazır
soc_graph = build_graph()
