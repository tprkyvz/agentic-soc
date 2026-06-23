"""
utils/llm_client.py – Ollama LLM istemcisi.

LangChain-Ollama üzerinden ChatOllama sarıcısı.
Bağlantı kontrolü ve retry mantığı içerir.
"""

import httpx
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage

from .config import settings


def check_ollama_connection() -> tuple[bool, str]:
    """
    Ollama API'nin erişilebilir olup olmadığını kontrol et.

    Returns:
        (True, model_listesi) veya (False, hata_mesajı)
    """
    try:
        resp = httpx.get(f"{settings.ollama_base_url}/api/tags", timeout=5.0)
        resp.raise_for_status()
        models = [m["name"] for m in resp.json().get("models", [])]
        return True, f"Bağlı. Modeller: {models}"
    except httpx.ConnectError:
        return False, f"Ollama API erişilemiyor: {settings.ollama_base_url}"
    except Exception as e:
        return False, f"Beklenmeyen hata: {e}"


def get_llm(temperature: float = 0.1) -> ChatOllama:
    """
    Yapılandırılmış ChatOllama nesnesi döndür.

    Args:
        temperature: Üretkenlik (0=deterministik, 1=yaratıcı).
                     Güvenlik analizi için düşük tutuyoruz.
    """
    return ChatOllama(
        model=settings.ollama_model,
        base_url=settings.ollama_base_url,
        temperature=temperature,
    )


def quick_invoke(system_prompt: str, user_message: str, temperature: float = 0.1) -> str:
    """
    Tek seferlik LLM çağrısı için yardımcı fonksiyon.

    Args:
        system_prompt: Sistem rolü / talimatları
        user_message:  Kullanıcı sorusu / içeriği
        temperature:   Üretkenlik parametresi

    Returns:
        Modelin metin yanıtı
    """
    llm = get_llm(temperature=temperature)
    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_message),
    ]
    response = llm.invoke(messages)
    return response.content
