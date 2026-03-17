# Scenario: SSH Brute-Force Attack

### Description
This scenario simulates a brute-force attack against an SSH server. The target is an Ubuntu-based SSH server with a weak root password.

### Vulnerability / Attack Vector
- **Weak Credentials:** The root account uses a predictable password (`root`).
- **Brute-Force:** An attacker can attempt hundreds of login combinations per minute.

### How to Run
1. **Start the environment:**
   ```bash
   docker-compose up -d