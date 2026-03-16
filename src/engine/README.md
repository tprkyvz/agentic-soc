
# `src/engine` – Orchestration and Log Processing Engine

This directory will contain the **core engine** that:

- Ingests and normalizes logs from different sources.
- Coordinates the conversation between agents in `src/agents`.
- Manages state and workflows for each incident or investigation.

No concrete implementation is provided yet; this folder is intended
to stay clean and ready for incremental development throughout the project.

## Responsibilities (Planned)

- **Log Ingestion**
  - Connect to files, streams, or APIs (e.g., `lab/logs` during development).
  - Apply normalization and pre-processing (delegating parsing to `src/utils`).

- **Session / Case Management**
  - Group related log entries into a single “case” or “incident”.
  - Track the lifecycle of an incident: observed → triaged → analyzed → closed.

- **Agent Orchestration**
  - Decide which agent to call next based on the current state.
  - Manage prompts, contexts, and responses to/from LLM-based agents.

- **Interfaces**
  - Provide a simple API (CLI, REST, or gRPC) for external tools or UI.
  - Optionally log decisions and explanations for later evaluation.

## Suggested File Layout

```text
src/engine/
  pipeline.py      # High-level log processing pipeline
  router.py        # Routing logic between agents
  models.py        # Core data models for incidents, alerts, etc.
  config.py        # Engine-specific configuration loading
```

As the design stabilizes, you can adjust this layout and keep this README in sync.
