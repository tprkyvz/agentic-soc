
# `src/knowledge_base` – Knowledge Base and RAG

This directory will hold everything related to the **attack knowledge base**:

- Storage and schema for past attacks and incidents.
- Vector database / embedding logic.
- Retrieval-augmented generation (RAG) to enrich LLM prompts.

At the moment this folder is intentionally empty of implementation,
serving only as a placeholder for future work.

## Planned Components

- **Data Models**
  - Representation of an “attack case” (logs, description, labels).
  - Links to CVEs, MITRE ATT&CK techniques, or custom taxonomies.

- **Storage Layer**
  - A simple relational DB or document store (e.g., SQLite, PostgreSQL, or a cloud DB).
  - Migrations / seed scripts (can live here or under `docs` / `lab`).

- **Vector Store / Index**
  - Embedding and indexing of attack descriptions and key log snippets.
  - Support semantic similarity search over past incidents.

- **RAG Integration**
  - Utilities to build LLM prompts enriched with retrieved context.
  - Interfaces used primarily by the `KnowledgeBaseAgent` in `src/agents`.

## Suggested File Layout

```text
src/knowledge_base/
  schemas.py        # Pydantic/ORM models for attacks, cases, etc.
  storage.py        # CRUD operations for the underlying DB
  embeddings.py     # Functions to embed and index data
  retriever.py      # High-level search / retrieval API
```

This layout is only a starting point; you can refine it as you learn more
from research and early prototypes.
