# Scenario: Web SQL Injection / XSS Attack

### Description
This scenario simulates SQL injection and cross-site scripting (XSS) attempts
against a web application. The target is a plain Nginx server serving static
files — the point isn't to run a real vulnerable backend (the SOC detects
attack *patterns* in the access log, not real exploitation), it's to generate
realistic Nginx combined-format access logs containing SQLi/XSS payloads.

### Vulnerability / Attack Vector
- **SQL Injection:** UNION SELECT, boolean tautologies (`' OR '1'='1`), stacked
  queries, `information_schema` probing.
- **Cross-Site Scripting (XSS):** `<script>` tags, event-handler injection
  (`onerror=`), `javascript:` URIs, cookie theft attempts.

### How to Run
1. **Start the environment:**
   ```bash
   docker-compose up -d
   ```
2. **Run the attack (in another terminal):**
   ```bash
   bash attack.sh [target_ip] [target_port] [delay]
   # defaults: 127.0.0.1 8080 0.3
   ```
3. **Watch it live with Agentic SOC:**
   ```bash
   python -m src.agentic_soc.main --source docker --log-type web
   ```

### Notes
- Most payloads hit nonexistent paths (→ HTTP 404, "blocked/not found");
  two hit the real `search.html` page (→ HTTP 200, "not blocked") to give the
  triage logic a "successful" signal analogous to the SSH scenario's
  "accepted login after failures".
- `docker logs victim_web_server` streams the same access log Nginx writes to
  stdout by default — no custom `nginx.conf` needed.
