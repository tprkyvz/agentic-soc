"""
knowledge_base/storage.py – ChromaDB bağlantısı ve CRUD operasyonları.

Koleksiyon: "attack_cases"
Her döküman bir AttackCase'i temsil eder.
"""

from __future__ import annotations

import json
from pathlib import Path

import chromadb
from chromadb.config import Settings as ChromaSettings

from .schemas import AttackCase
from .embeddings import embed_text

# ChromaDB kalıcı depolama yolu – proje kökünde data/chroma_db/
# parents[0] = knowledge_base/, [1] = agentic_soc/, [2] = src/, [3] = proje kökü
_DB_PATH = Path(__file__).resolve().parents[3] / "data" / "chroma_db"
_COLLECTION_NAME = "attack_cases"

# ---------------------------------------------------------------------------
# Client ve koleksiyon (process başına tek seferlik, cache'lenmiş)
# ---------------------------------------------------------------------------

_client: chromadb.PersistentClient | None = None
_collection: chromadb.Collection | None = None


def _get_client() -> chromadb.PersistentClient:
    """Kalıcı ChromaDB istemcisini döndür (bir kere oluşturulur, tekrar kullanılır)."""
    global _client
    if _client is None:
        _DB_PATH.mkdir(parents=True, exist_ok=True)
        _client = chromadb.PersistentClient(
            path=str(_DB_PATH),
            settings=ChromaSettings(anonymized_telemetry=False),
        )
    return _client


def get_collection() -> chromadb.Collection:
    """attack_cases koleksiyonunu al (yoksa oluştur, sonra cache'ten döndür)."""
    global _collection
    if _collection is None:
        client = _get_client()
        _collection = client.get_or_create_collection(
            name=_COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},  # Cosine similarity
        )
    return _collection


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def save_case(case: AttackCase) -> None:
    """
    Bir AttackCase'i ChromaDB'ye kaydet.
    Aynı ID zaten varsa günceller.
    """
    collection = get_collection()
    embedding = embed_text(case.embedding_text)

    collection.upsert(
        ids=[case.id],
        embeddings=[embedding],
        documents=[case.embedding_text],
        metadatas=[{
            "title": case.title,
            "attack_type": case.attack_type.value,
            "mitre_technique_id": case.mitre_technique_id,
            "mitre_technique_name": case.mitre_technique_name,
            "severity": case.severity.value,
            "indicators": json.dumps(case.indicators),
            "mitigations": json.dumps(case.mitigations),
            "resolution_time_hours": case.resolution_time_hours or -1,
            # Tam nesneyi JSON olarak da sakla
            "full_json": case.model_dump_json(),
        }],
    )


def save_cases(cases: list[AttackCase]) -> None:
    """Birden fazla vakayı toplu kaydet."""
    for case in cases:
        save_case(case)


def get_case(case_id: str) -> AttackCase | None:
    """ID'ye göre tek vaka getir."""
    collection = get_collection()
    result = collection.get(ids=[case_id], include=["metadatas"])
    if not result["ids"]:
        return None
    return AttackCase.model_validate_json(result["metadatas"][0]["full_json"])


def list_cases() -> list[AttackCase]:
    """KB'deki tüm vakaları döndür (dashboard ve toplu görünümler için)."""
    collection = get_collection()
    if collection.count() == 0:
        return []
    result = collection.get(include=["metadatas"])
    return [AttackCase.model_validate_json(m["full_json"]) for m in result["metadatas"]]


def count_cases() -> int:
    """Koleksiyondaki toplam vaka sayısı."""
    return get_collection().count()


def query_similar(
    query_text: str,
    n_results: int = 3,
) -> list[tuple[AttackCase, float]]:
    """
    Semantik benzerlik araması.

    Args:
        query_text: Aranacak metin
        n_results:  Döndürülecek maksimum sonuç sayısı

    Returns:
        (AttackCase, benzerlik_skoru) çiftlerinin listesi
        Skor: 0.0 (farklı) → 1.0 (aynı)
    """
    collection = get_collection()

    if collection.count() == 0:
        return []

    query_embedding = embed_text(query_text)

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=min(n_results, collection.count()),
        include=["metadatas", "distances"],
    )

    cases_with_scores = []
    for metadata, distance in zip(
        results["metadatas"][0],
        results["distances"][0],
    ):
        case = AttackCase.model_validate_json(metadata["full_json"])
        # Cosine distance → similarity: 1 - distance
        similarity = round(1.0 - distance, 4)
        cases_with_scores.append((case, similarity))

    return cases_with_scores
