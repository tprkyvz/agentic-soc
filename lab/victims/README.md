
# `lab/victims` – Vulnerable Targets

This directory will host **vulnerable services or applications** used to
generate realistic attack traffic and logs.

Typical content might include:

- `docker-compose.yml` files for different scenarios.
- Configuration for web apps, databases, or intentionally vulnerable tools.
- Short scenario descriptions (e.g., SQL injection demo, brute-force login).

## Example Structure (Future)

```text
lab/victims/
  webapp_sql_injection/
    docker-compose.yml
    README.md

  ssh_bruteforce/
    docker-compose.yml
    README.md
```

For each scenario, describe:

- What the service does.
- Which vulnerability or attack vector is demonstrated.
- How to start and stop the environment safely.
