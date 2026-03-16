
# `src/agents` – Agent Definitions

This directory will contain the **multi-agent components** of the Agentic SOC system.
Each agent focuses on a specific role in the SOC workflow.

> **Note:** At this stage, this folder only documents intended structure.
> No production code is implemented yet.

## Planned Agents (Example)

- **TriageAgent**
  - First contact for incoming logs or alerts.
  - Decides whether an event looks benign, suspicious, or clearly malicious.
  - Routes the case to other agents or discards noise.

- **AnalystAgent**
  - Performs deeper investigation on suspicious events.
  - Asks the Knowledge Base for related past incidents.
  - Summarizes likely attack scenario and impact.

- **KnowledgeBaseAgent**
  - Interfaces with the RAG / vector database in `src/knowledge_base`.
  - Retrieves similar attacks, vulnerabilities, and mitigations.
  - Provides structured context back to other agents.

- **MitigationAdvisorAgent (optional)**
  - Focuses on containment, eradication, and hardening recommendations.

## Suggested File Layout

You can evolve towards a structure like:

```text
src/agents/
  base.py              # Abstract base classes / shared tools
  triage_agent.py      # TriageAgent implementation
  analyst_agent.py     # AnalystAgent implementation
  kb_agent.py          # KnowledgeBaseAgent implementation
  mitigation_agent.py  # MitigationAdvisorAgent implementation (optional)
```

Keep this README updated as the agent design becomes more concrete.
