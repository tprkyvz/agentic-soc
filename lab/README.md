
# `lab` – Experimental Security Lab

The `lab` directory is a **controlled playground** where you will:

- Deploy vulnerable services or applications.
- Launch attacks against them.
- Collect the resulting logs as realistic input for the Agentic SOC.

Nothing here is production-ready; it is meant purely for experimentation,
data generation, and reproducibility of your research.

## Subdirectories

- `lab/victims/` – Contains **Docker-based vulnerable environments**.
- `lab/logs/` – Stores **generated or curated log files** used for testing.

Keep all lab-related configuration and artifacts under this folder to
avoid mixing lab experiments with core application code.
