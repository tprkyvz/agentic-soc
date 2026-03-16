
# `src/utils` – Shared Utilities

This directory will contain **reusable helper modules** that do not belong
to a single agent or engine component.

Centralizing utilities here helps keep other modules focused and simpler.

## Typical Responsibilities

- **Configuration & Environment**
  - Loading configuration from environment variables or files.
  - Common constants (e.g., log paths, model names).

- **Logging**
  - Shared logging configuration for the whole project.
  - Helpers for structured logs (e.g., JSON logs for debugging).

- **Parsing and Normalization**
  - Functions to parse raw log lines into structured objects.
  - Source-specific adapters (e.g., web server logs vs. system logs).

- **LLM / API Helpers**
  - Thin wrappers around LLM providers (OpenAI, local models, etc.).
  - Retry / backoff logic, telemetry, and simple rate limiting.

## Suggested File Layout

```text
src/utils/
  config.py       # Load and validate configuration
  logging.py      # Project-wide logging setup
  parsers.py      # Log parsing helpers
  llm_client.py   # Simple client wrapper for LLM calls
```

Only add utilities that are truly shared; avoid placing core business logic here.
