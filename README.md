# Agentic SOC: Multi-Agent LLM Driven Security Operations Center

This repository contains the **initial skeleton** for the project:

> Agentic SOC: Multi-Agent LLM Driven Security Operations Center

The long-term goal of this project is to explore how multi-agent systems
powered by Large Language Models (LLMs) can support Security Operations Center (SOC)
workflows, especially around log analysis and incident triage.

At this stage, the repository only includes a minimal, clean structure and
a very simple Python entry point. No real log parsing, LLM calls, or
security logic is implemented yet.

## Current Project Structure

```text
agentic-soc/
  README.md         # Project overview (this file)
  .gitignore        # Ignore venv, cache, models, etc.
  requirements.txt  # Python dependencies (currently minimal)

  src/
    agentic_soc/    # Python package root for the project
      __init__.py
      main.py       # Simple entry point (placeholder)
      agents/       # Future agent definitions (triage, analyst, KB, etc.)
        __init__.py
      engine/       # Future orchestration and log processing engine
        __init__.py
      knowledge_base/  # Future RAG / vector DB integration
        __init__.py
      utils/        # Future utility helpers (config, parsing, etc.)
        __init__.py
```

## How to Run (draft)

From the project root:

```bash
python -m src.agentic_soc.main
```

Right now this will only execute a minimal placeholder `main()` function.

## Roadmap (high-level, subject to change)

This project is intended as a long-term graduation project and will likely
evolve roughly along these lines:

- **Phase 1** – Research, requirements, and simple prototypes
- **Phase 2** – Basic log ingestion and single-agent LLM analysis
- **Phase 3** – Multi-agent orchestration (triage, analyst, KB, recommendations)
- **Phase 4** – Knowledge base (past attacks, patterns, RAG)
- **Phase 5** – Evaluation, simple UI, and final report

For now, the focus is on keeping the structure clean and ready
for iterative development.

