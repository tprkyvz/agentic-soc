## Agentic SOC – Multi-Agent LLM-Driven Security Operations Center


> Agentic SOC: a multi-agent system that sends complex logs to an LLM and answers:
> *Is this an attack? Which vulnerability does it target? How can I mitigate it?*

A working prototype is implemented end-to-end for the **SSH brute-force** scenario:
log ingestion (file or live Docker stream) → rule-based triage → KB similarity
lookup (RAG) → LLM-based MITRE ATT&CK analysis → LLM-based mitigation advice →
learning the new case back into the knowledge base. See
[Running the Project](#running-the-project) below.

### High-Level Goals

- Build a **multi-agent** system (Triage Agent, Analyst Agent, Knowledge-Base Agent, etc.).
- Ingest and normalize **heterogeneous security logs** (web server, system, IDS, application).
- Use LLMs plus a **knowledge base of past attacks** to:
  - Decide whether an event is likely an attack.
  - Map it to **attack techniques / vulnerabilities**.
  - Suggest **mitigation / containment** steps.
- Provide a **reproducible lab** where you can generate attacks, collect logs, and evaluate the system.

---

## Project Structure Overview

```text
agentic-soc/
  .gitignore
  README.md
  requirements.txt

  src/agentic_soc/      # Main application code (installable package)
    agents/            # Triage / Analyst / Mitigation / KB agent nodes
    engine/            # Pydantic models, LangGraph graph, pipeline, CLI entry (main.py)
    knowledge_base/     # RAG: ChromaDB storage, embeddings, retriever, seeder
    utils/             # Config, Ollama LLM client, log parsers

  lab/                  # Experimental lab (attack generation)
    victims/           # Vulnerable services / apps in Docker
    logs/              # Sample / recorded logs for experiments

  data/                 # Generated at runtime: ChromaDB vector store (gitignored)

  notebooks/            # Jupyter experiments and quick prototypes

  research/             # Papers, notes, and literature review

  docs/                 # Documentation and thesis materials
    reports/           # Monthly progress reports
    architecture/      # Architecture diagrams and design documents
```

Each major directory also has its own `README` to explain its role in the project.

---

## Running the Project

Prerequisites:

- Python 3.10+, `pip install -r requirements.txt`
- [Ollama](https://ollama.com) running locally with `llama3.2` and `nomic-embed-text` pulled
  (`ollama pull llama3.2 && ollama pull nomic-embed-text`)
- Docker, only if you want to run the live lab scenario
- Copy `.env.example` to `.env` and adjust if needed

Seed the knowledge base once (loads a handful of MITRE-mapped SSH attack cases):

```bash
python -m src.agentic_soc.main --seed
```

Analyze a static log file (works without Docker, uses the bundled sample):

```bash
python -m src.agentic_soc.main --source file --log-file lab/logs/ssh_bruteforce/sample_auth.log
```

Analyze a live attack against the lab's vulnerable SSH container:

```bash
docker compose -f lab/victims/ssh-bruteforce/docker-compose.yml up -d
python -m src.agentic_soc.main --source docker   # in one terminal
bash lab/victims/ssh-bruteforce/attack.sh          # in another terminal
```

---

## Long-Term Milestones (Very High Level)

- **Milestone 1 – Concept & Research** ✅
  - Clarify requirements: threat model, log sources, target users.
  - Select LLM provider(s) and vector DB technology (Ollama local models + ChromaDB).
  - Study SOC workflows and attack categorizations (e.g., MITRE ATT&CK).

- **Milestone 2 – Lab & Data** ✅ (SSH brute-force scenario only)
  - Spin up a vulnerable SSH service in `lab/victims`.
  - Generate attacks (`attack.sh`) and collect a sample log into `lab/logs`.
  - Define log formats and normalization strategy in `src/agentic_soc/utils/parsers.py`.
  - Still open: additional log sources (web server, IDS, application logs).

- **Milestone 3 – Core Engine & Single-Agent Prototype** ✅
  - Log ingestion pipeline in `src/agentic_soc/engine/pipeline.py` (file + live Docker modes).
  - LLM-based analyst agent that explains/classifies events.

- **Milestone 4 – Multi-Agent Architecture** ✅
  - Roles split into Triage (rule-based) / Analyst / Mitigation / Knowledge-Base agents.
  - Orchestrated as a LangGraph state graph in `src/agentic_soc/engine/graph.py`.

- **Milestone 5 – Knowledge Base & RAG** ✅
  - `knowledge_base/` seeded with MITRE-mapped attack cases, embedded via `nomic-embed-text`.
  - Analyst agent retrieval-augmented with similar past cases; new cases are learned back (`kb_save_node`).

- **Milestone 6 – Evaluation & Thesis** ⬜ (not started)
  - Design quantitative and qualitative evaluation scenarios.
  - Document findings in `docs/reports` and `docs/architecture`.

This file should remain a **living document** that you refine as the project evolves.