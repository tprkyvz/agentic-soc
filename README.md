## Agentic SOC – Multi-Agent LLM-Driven Security Operations Center

This repository contains the **clean, long-lived skeleton** of your graduation project:

> Agentic SOC: a multi-agent system that sends complex logs to an LLM and answers:
> *Is this an attack? Which vulnerability does it target? How can I mitigate it?*

 At this point, **no real logic is implemented**; 
only folders, placeholder files, and documentation stubs exist.

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

  src/                  # Main application code
    agents/            # Agent definitions (triage, analyst, KB, etc.)
    engine/            # Orchestration, pipelines, and message routing
    knowledge_base/    # RAG, vector DB, and attack history
    utils/             # Shared helpers (config, logging, parsing)

  lab/                  # Experimental lab (attack generation)
    victims/           # Vulnerable services / apps in Docker
    logs/              # Sample / recorded logs for experiments

  notebooks/            # Jupyter experiments and quick prototypes

  research/             # Papers, notes, and literature review

  docs/                 # Documentation and thesis materials
    reports/           # Monthly progress reports
    architecture/      # Architecture diagrams and design documents
```

Each major directory also has its own `README` to explain its role in the project.

---

## Running the Project (Placeholder)

At this stage, there is intentionally **no runnable application**. As you progress, you will:

- Define a minimal CLI or API entry point in `src/engine/` (e.g. FastAPI or a CLI script).
- Add installers and environment setup instructions here.

Until then, you can treat this repository as a **design and documentation container**.

---

## Long-Term Milestones (Very High Level)

- **Milestone 1 – Concept & Research**
  - Clarify requirements: threat model, log sources, target users.
  - Select LLM provider(s) and vector DB technology.
  - Study SOC workflows and attack categorizations (e.g., MITRE ATT&CK).

- **Milestone 2 – Lab & Data**
  - Spin up vulnerable services in `lab/victims`.
  - Generate attacks and collect logs into `lab/logs`.
  - Define log formats and normalization strategy in `src/utils`.

- **Milestone 3 – Core Engine & Single-Agent Prototype**
  - Implement a simple log ingestion pipeline in `src/engine`.
  - Add a single “monolithic” LLM agent in `src/agents` that explains logs.

- **Milestone 4 – Multi-Agent Architecture**
  - Split roles into Triage / Analyst / KB Agent.
  - Implement message passing and orchestration in the engine.

- **Milestone 5 – Knowledge Base & RAG**
  - Populate `knowledge_base` with past attacks and patterns.
  - Integrate retrieval-augmented generation over this data.

- **Milestone 6 – Evaluation & Thesis**
  - Design quantitative and qualitative evaluation scenarios.
  - Document findings in `docs/reports` and `docs/architecture`.

This file should remain a **living document** that you refine as the project evolves.