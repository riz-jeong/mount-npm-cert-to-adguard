#!/usr/bin/env bash
set -euo pipefail

echo
echo "=================================================="
echo " NPM Plus → AdGuard Home 인증서 자동 연동"
echo "=================================================="
echo

if [[ $EUID -ne 0 ]]; then
    echo "[오류] Proxmox Host의 root로 실행하세요."
    exit 1
fi

command -v pct >/dev/null 2>&1 || {
    echo "[오류] pct 명령을 찾을 수 없습니다."
    exit 1
}

# --------------------------------------------------
# LXC 선택
# --------------------------------------------------

read -rp "NPM Plus LXC 번호: " NPMID
read -rp "AdGuard Home LXC 번호: " ADGID

if ! pct status "$NPMID" >/dev/null 2>&1; then
    echo "[오류] NPM Plus LXC $NPMID 를 찾을 수 없습니다."
    exit 1
fi

if ! pct status "$ADGID" >/dev/null 2>&1; then
    echo "[오류] AdGuard Home LXC $ADGID 를 찾을 수 없습니다."
    exit 1
fi

# --------------------------------------------------
# 인증서 종류
# --------------------------------------------------

echo
echo "인증서 종류"
echo "  1) certbot"
echo "  2) custom"
echo

read -rp "선택 [1-2]: " TYPE

case "$TYPE" in
    1)
        TYPE_NAME="certbot"
        ;;
    2)
        TYPE_NAME="custom"
        ;;
    *)
        echo "[오류] 1 또는 2를 선택하세요."
        exit 1
        ;;
esac

read -rp "인증서 번호 (예: 1): " CERTNUM

if ! [[ "$CERTNUM" =~ ^[0-9]+$ ]]; then
    echo "[오류] 인증서 번호는 숫자여야 합니다."
    exit 1
fi

CERTNAME="npm-${CERTNUM}"

if [[ "$TYPE_NAME" == "certbot" ]]; then
    NPM_CERT="/opt/npmplus/tls/certbot/live/${CERTNAME}"
else
    NPM_CERT="/opt/npmplus/tls/custom/${CERTNAME}"
fi

echo
echo "=================================================="
echo "설정 확인"
echo "=================================================="
echo "NPM Plus LXC : $NPMID"
echo "AdGuard LXC  : $ADGID"
echo "종류         : $TYPE_NAME"
echo "인증서       : $CERTNAME"
echo "경로         : $NPM_CERT"
echo "=================================================="
echo

# --------------------------------------------------
# 인증서 존재 확인
# --------------------------------------------------

if ! pct exec "$NPMID" -- test -f "$NPM_CERT/fullchain.pem"; then
    echo "[오류] fullchain.pem을 찾을 수 없습니다:"
    echo "$NPM_CERT/fullchain.pem"
    exit 1
fi

if ! pct exec "$NPMID" -- test -f "$NPM_CERT/privkey.pem"; then
    echo "[오류] privkey.pem을 찾을 수 없습니다:"
    echo "$NPM_CERT/privkey.pem"
    exit 1
fi

echo "[OK] NPM Plus 인증서 확인"

# --------------------------------------------------
# AdGuard 인증서 디렉터리
# --------------------------------------------------

ADG_CERT_DIR="/etc/adguardhome/certs"

echo
echo "[1/7] AdGuard Home 인증서 디렉터리 생성..."

pct exec "$ADGID" -- mkdir -p "$ADG_CERT_DIR"

# --------------------------------------------------
# SSH 서버 확인
# --------------------------------------------------

echo
echo "[2/7] AdGuard Home SSH 서버 확인..."

if ! pct exec "$ADGID" -- sh -c 'command -v sshd >/dev/null 2>&1'; then
    echo "[INFO] AdGuard Home에 OpenSSH Server 설치..."

    pct exec "$ADGID" -- apk add --no-cache openssh

    pct exec "$ADGID" -- ssh-keygen -A

    pct exec "$ADGID" -- rc-update add sshd default 2>/dev/null || true
    pct exec "$ADGID" -- rc-service sshd start 2>/dev/null || true
else
    pct exec "$ADGID" -- rc-service sshd start 2>/dev/null || true
fi

# --------------------------------------------------
# NPM Plus SSH client
# --------------------------------------------------

echo
echo "[3/7] NPM Plus SSH client 확인..."

if ! pct exec "$NPMID" -- sh -c 'command -v ssh >/dev/null 2>&1 && command -v scp >/dev/null 2>&1'; then
    echo "[INFO] NPM Plus에 OpenSSH client 설치..."

    pct exec "$NPMID" -- apk add --no-cache openssh-client
fi

# --------------------------------------------------
# SSH Key 생성
# --------------------------------------------------

echo
echo "[4/7] NPM Plus → AdGuard SSH 인증 설정..."

NPM_SSH_DIR="/root/.ssh"

pct exec "$NPMID" -- mkdir -p "$NPM_SSH_DIR"
pct exec "$NPMID" -- chmod 700 "$NPM_SSH_DIR"

if ! pct exec "$NPMID" -- test -f \
    "${NPM_SSH_DIR}/id_ed25519_adguard"; then

    pct exec "$NPMID" -- ssh-keygen \
        -t ed25519 \
        -N "" \
        -f "${NPM_SSH_DIR}/id_ed25519_adguard" \
        -C "npmplus-to-adguard"
fi

PUBKEY="$(pct exec "$NPMID" -- cat \
    "${NPM_SSH_DIR}/id_ed25519_adguard.pub")"

pct exec "$ADGID" -- mkdir -p /root/.ssh
pct exec "$ADGID" -- chmod 700 /root/.ssh

# 기존 동일 키 제거 후 추가
pct exec "$ADGID" -- sh -c \
    "touch /root/.ssh/authorized_keys && \
     sed -i '/npmplus-to-adguard/d' /root/.ssh/authorized_keys && \
     printf '%s\n' '$PUBKEY' >> /root/.ssh/authorized_keys && \
     chmod 600 /root/.ssh/authorized_keys"

# --------------------------------------------------
# AdGuard SSH 주소
# --------------------------------------------------

ADG_IP="$(pct config "$ADGID" | sed -n 's/.*ip=\([^,\/]*\).*/\1/p')"

if [[ -z "$ADG_IP" ]]; then
    echo "[오류] AdGuard Home LXC IP를 자동으로 찾지 못했습니다."
    echo
    echo "현재 네트워크 설정:"
    pct config "$ADGID" | grep '^net'
    exit 1
fi

echo
echo "AdGuard Home IP: $ADG_IP"

# --------------------------------------------------
# SSH known_hosts
# --------------------------------------------------

pct exec "$NPMID" -- mkdir -p /root/.ssh

pct exec "$NPMID" -- sh -c \
    "ssh-keyscan -H '$ADG_IP' >> /root/.ssh/known_hosts 2>/dev/null || true"

# --------------------------------------------------
# 최초 인증서 복사
# --------------------------------------------------

echo
echo "[5/7] 최초 인증서 복사..."

pct exec "$NPMID" -- sh -c "
    scp \
    -i /root/.ssh/id_ed25519_adguard \
    -q \
    '$NPM_CERT/fullchain.pem' \
    root@'$ADG_IP':'$ADG_CERT_DIR'/fullchain.pem
"

pct exec "$NPMID" -- sh -c "
    scp \
    -i /root/.ssh/id_ed25519_adguard \
    -q \
    '$NPM_CERT/privkey.pem' \
    root@'$ADG_IP':'$ADG_CERT_DIR'/privkey.pem
"

pct exec "$ADGID" -- chmod 644 \
    "${ADG_CERT_DIR}/fullchain.pem"

pct exec "$ADGID" -- chmod 600 \
    "${ADG_CERT_DIR}/privkey.pem"

echo "[OK] 최초 인증서 복사 완료"

# --------------------------------------------------
# Deploy Hook
# --------------------------------------------------

echo
echo "[6/7] Certbot deploy hook 설치..."

if [[ "$TYPE_NAME" == "certbot" ]]; then

    HOOK_DIR="/opt/npmplus/tls/certbot/renewal-hooks/deploy"

    pct exec "$NPMID" -- mkdir -p "$HOOK_DIR"

    HOOK="${HOOK_DIR}/99-adguard-${ADGID}-${CERTNUM}.sh"

    pct exec "$NPMID" -- sh -c "cat > '$HOOK' <<'HOOKEOF'
#!/bin/sh

ADGUARD_IP='$ADG_IP'
ADGUARD_CERT_DIR='$ADG_CERT_DIR'
CERTNAME='$CERTNAME'

# Certbot이 실제로 갱신한 인증서인지 확인
if [ -n \"\$RENEWED_LINEAGE\" ] && \
   [ \"\$RENEWED_LINEAGE\" = \"/opt/npmplus/tls/certbot/live/\$CERTNAME\" ]; then

    scp \
        -i /root/.ssh/id_ed25519_adguard \
        -q \
        \"\$RENEWED_LINEAGE/fullchain.pem\" \
        root@\$ADGUARD_IP:\$ADGUARD_CERT_DIR/fullchain.pem || exit 1

    scp \
        -i /root/.ssh/id_ed25519_adguard \
        -q \
        \"\$RENEWED_LINEAGE/privkey.pem\" \
        root@\$ADGUARD_IP:\$ADGUARD_CERT_DIR/privkey.pem || exit 1

    ssh \
        -i /root/.ssh/id_ed25519_adguard \
        root@\$ADGUARD_IP \
        'chmod 644 /etc/adguardhome/certs/fullchain.pem && chmod 600 /etc/adguardhome/certs/privkey.pem'

    ssh \
        -i /root/.ssh/id_ed25519_adguard \
        root@\$ADGUARD_IP \
        'systemctl reload AdGuardHome 2>/dev/null || systemctl restart AdGuardHome'

fi
HOOKEOF
chmod 700 '$HOOK'"

    echo "[OK] Deploy hook 설치:"
    echo "$HOOK"

else

    echo "[INFO] custom 인증서는 Certbot 자동 갱신 Hook을 설치하지 않습니다."

fi

# --------------------------------------------------
# 테스트
# --------------------------------------------------

echo
echo "[7/7] SSH 연결 테스트..."

pct exec "$NPMID" -- sh -c \
    "ssh \
     -i /root/.ssh/id_ed25519_adguard \
     -o BatchMode=yes \
     root@'$ADG_IP' \
     'echo SSH_OK'"

echo
echo "=============================================================="
echo "                  설정 완료"
echo "=============================================================="
echo
echo "NPM Plus LXC       : $NPMID"
echo "AdGuard Home LXC   : $ADGID"
echo "인증서 종류        : $TYPE_NAME"
echo "인증서 번호        : $CERTNAME"
echo
echo "AdGuard Home 인증서:"
echo "$ADG_CERT_DIR/fullchain.pem"
echo
echo "AdGuard Home 개인키:"
echo "$ADG_CERT_DIR/privkey.pem"
echo
echo "=============================================================="
echo
echo "자동 갱신:"
echo "NPM Plus Certbot → Deploy Hook → AdGuard Home"
echo
echo "주기적 polling 없음"
echo "LXC bind mount 없음"
echo "NPM Plus 인증서 저장소 변경 없음"
echo "=============================================================="
echo
