
# `lab/logs` – Sample and Generated Logs

This directory is intended for **log data used during development and evaluation**.

Examples of what may live here:

- Logs collected from the `lab/victims` environments.
- Anonymized or synthetic logs from public datasets.
- Manually crafted log files to reproduce specific attack patterns.

## Suggested Conventions

- Use subfolders per scenario, such as:

  ```text
  lab/logs/
    webapp_sql_injection/
      access.log
      error.log

    ssh_bruteforce/
      auth.log
  ```

- Clearly mark whether a log file is:
  - **Benign**
  - **Suspicious**
  - **Confirmed attack**

This labeling will later help you evaluate the Agentic SOC’s performance.
