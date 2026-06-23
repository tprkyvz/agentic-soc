"""
knowledge_base/embeddings.py – Metin → vektör dönüşümü.

Ollama'nın nomic-embed-text modelini kullanır.
İnternet bağlantısı gerekmez, tamamen yerel çalışır.
"""

import httpx
from ..utils.config import settings

# Embedding için kullanılacak model
EMBEDDING_MODEL = "nomic-embed-text"
_OLLAMA_EMBED_URL = f"{settings.ollama_base_url}/api/embeddings"


def embed_text(text: str) -> list[float]:
    """
    Verilen metni Ollama nomic-embed-text ile vektöre dönüştür.

    Args:
        text: Embed edilecek metin

    Returns:
        Float listesi (vektör boyutu: 768)

    Raises:
        RuntimeError: Ollama erişilemez veya model yüklü değilse
    """
    try:
        resp = httpx.post(
            _OLLAMA_EMBED_URL,
            json={"model": EMBEDDING_MODEL, "prompt": text},
            timeout=30.0,
        )
        resp.raise_for_status()
        return resp.json()["embedding"]
    except httpx.ConnectError:
        raise RuntimeError(
            f"Ollama API erişilemiyor: {settings.ollama_base_url}\n"
            "Ollama çalışıyor mu? 'ollama serve'"
        )
    except KeyError:
        raise RuntimeError(
            f"Embedding yanıtı beklenmeyen formatta: {resp.text[:200]}"
        )
    except httpx.HTTPStatusError as e:
        if "model" in resp.text.lower() and "not found" in resp.text.lower():
            raise RuntimeError(
                f"'{EMBEDDING_MODEL}' modeli bulunamadı.\n"
                f"Yüklemek için: ollama pull {EMBEDDING_MODEL}"
            )
        raise RuntimeError(f"Ollama HTTP hatası: {e}")


def embed_texts(texts: list[str]) -> list[list[float]]:
    """Birden fazla metni sırayla embed et."""
    return [embed_text(t) for t in texts]


def check_embedding_model() -> tuple[bool, str]:
    """nomic-embed-text modelinin kullanılabilir olup olmadığını kontrol et."""
    try:
        vec = embed_text("test")
        return True, f"Embedding modeli hazır (boyut: {len(vec)})"
    except RuntimeError as e:
        return False, str(e)
