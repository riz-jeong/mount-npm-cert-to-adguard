#!/usr/bin/env bash
set -e

echo "=== NPM Plus 인증서 → AdGuard Home 자동 마운트 ==="
echo

read -p "NPM Plus LXC 번호: " NPMID
read -p "AdGuard Home LXC 번호: " ADGID

echo
echo "인증서 종류 선택"
echo "  1) certbot"
echo "  2) custom"
read -p "선택 [1-2]: " TYPESEL

case "$TYPESEL" in
    1) CERTTYPE="certbot" ;;
    2) CERTTYPE="custom" ;;
    *)
        echo "잘못된 선택"
        exit 1
        ;;
esac

read -p "인증서 번호 (예: 1): " CERTNUM

if [ "$CERTTYPE" = "certbot" ]; then
    CERTPATH="/var/lib/lxc/${NPMID}/rootfs/opt/npmplus/tls/certbot/live/npm-${CERTNUM}"
else
    CERTPATH="/var/lib/lxc/${NPMID}/rootfs/opt/npmplus/tls/custom/npm-${CERTNUM}"
fi

if [ ! -d "$CERTPATH" ]; then
    echo
    echo "[오류] 인증서 경로 없음:"
    echo "$CERTPATH"
    exit 1
fi

CONF="/etc/pve/lxc/${ADGID}.conf"

sed -i '/^mp9:/d' "$CONF" 2>/dev/null || true

echo "mp9: ${CERTPATH},mp=/certs/npm-${CERTNUM},ro=1" >> "$CONF"

echo
echo "[완료] 마운트 설정 추가됨"

if pct status "$ADGID" | grep -q running; then
    echo "AdGuard Home LXC 재시작 중..."
    pct reboot "$ADGID"
fi

echo
echo "=================================================="
echo "AdGuard Home → Settings → Encryption"
echo
echo "Certificate Path:"
echo "/certs/npm-${CERTNUM}/fullchain.pem"
echo
echo "Private Key Path:"
echo "/certs/npm-${CERTNUM}/privkey.pem"
echo
echo "복사용:"
echo "/certs/npm-${CERTNUM}/fullchain.pem"
echo "/certs/npm-${CERTNUM}/privkey.pem"
echo "=================================================="
EOF
