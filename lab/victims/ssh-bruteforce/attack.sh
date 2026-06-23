#!/usr/bin/env bash
# lab/victims/ssh-bruteforce/attack.sh
# SSH brute-force saldırısını simüle eder.
# Kullanım: bash attack.sh [hedef_port] [hedef_ip]

TARGET_IP="${1:-127.0.0.1}"
TARGET_PORT="${2:-2222}"
DELAY="${3:-0.3}"   # Denemeler arası bekleme (saniye)

# Deneme yapılacak kullanıcı adları
USERNAMES=("root" "admin" "ubuntu" "pi" "test" "user" "postgres" "oracle" "guest" "support")

# Yanlış şifreler (başarısız deneme için)
PASSWORDS=("wrong1" "wrong2" "wrong3" "badpass" "letmein" "qwerty" "12345" "password" "abc123" "test")

echo "=============================================="
echo "  Agentic SOC – SSH Brute-Force Simülasyonu"
echo "  Hedef: ${TARGET_IP}:${TARGET_PORT}"
echo "  Gecikme: ${DELAY}s / deneme"
echo "=============================================="
echo ""

# Gerekli araçları kontrol et
if ! command -v ssh &>/dev/null; then
    echo "[!] ssh komutu bulunamadı. OpenSSH client kur:"
    echo "    sudo apt-get install -y openssh-client"
    exit 1
fi

ATTEMPT=0
FAIL=0

echo "[*] Brute-force başlıyor..."
echo ""

for USER in "${USERNAMES[@]}"; do
    for PASS in "${PASSWORDS[@]}"; do
        ATTEMPT=$((ATTEMPT + 1))
        FAIL=$((FAIL + 1))

        # SSH bağlantısı dene (batchmode = şifre sorusu yok, hata ver)
        ssh -o BatchMode=yes \
            -o ConnectTimeout=2 \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -p "${TARGET_PORT}" \
            "${USER}@${TARGET_IP}" \
            exit 2>/dev/null

        STATUS=$?
        if [ $STATUS -eq 0 ]; then
            echo "[!!!] BAŞARILI GİRİŞ: ${USER}@${TARGET_IP}:${TARGET_PORT}"
        else
            printf "[✗] Deneme #%d: %s / %s – Başarısız\n" "$ATTEMPT" "$USER" "$PASS"
        fi

        sleep "${DELAY}"
    done
done

echo ""
echo "=============================================="
echo "  Simülasyon tamamlandı."
echo "  Toplam deneme: ${ATTEMPT} | Başarısız: ${FAIL}"
echo "  Agentic SOC konsolunu kontrol et!"
echo "=============================================="
