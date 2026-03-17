import docker
import json
from datetime import datetime

def start_ingestor(container_name="victim_ssh_server"):
    client = docker.from_env()
    try:
        container = client.containers.get(container_name)
        print(f"[*] {container_name} Docker akışı üzerinden dinleniyor...")

        # stream=True Docker'ın kendi log mekanizmasını dinler
        for line in container.logs(stream=True, follow=True, tail=0):
            log_entry = line.decode('utf-8').strip()
            
            # Logun içinde 'sshd' veya 'Failed' geçiyorsa alalım
            if "sshd" in log_entry.lower() or "failed" in log_entry.lower():
                normalized_data = {
                    "timestamp": datetime.now().isoformat(),
                    "source": container_name,
                    "raw_log": log_entry
                }
                print(f"[NEW LOG] {json.dumps(normalized_data, indent=2)}")

    except Exception as e:
        print(f"[!] Hata: {e}")

if __name__ == "__main__":
    start_ingestor()