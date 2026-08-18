#!/usr/bin/env bash
set -euo pipefail

BASE="/mnt/bindmounts/npmplus-cert"
SERVICE="/etc/systemd/system/npmplus-cert-adguard.service"

echo
echo "=================================================="
echo " NPM Plus 인증서 → AdGuard Home 연결"
echo "=================================================="
echo

if [[ $EUID -ne 0 ]]; then
    echo "[오류] Proxmox Host의 root로 실행하세요."
    exit 1
fi

command -v pct >/dev/null || {
    echo "[오류] pct 명령을 찾을 수 없습니다."
    exit 1
}

read -rp "NPM Plus LXC 번호: " NPMID
read -rp "AdGuard Home LXC 번호: " ADGID

pct status "$NPMID" >/dev/null 2>&1 || {
    echo "[오류] NPM Plus LXC $NPMID 를 찾을 수 없습니다."
    exit 1
}

pct status "$ADGID" >/dev/null 2>&1 || {
    echo "[오류] AdGuard Home LXC $ADGID 를 찾을 수 없습니다."
    exit 1
}

echo
echo "인증서 종류"
echo "  1) certbot"
echo "  2) custom"
echo

read -rp "선택 [1-2]: " TYPE

case "$TYPE" in
    1)
        TYPE_NAME="certbot"
        NPM_CERT_ROOT="/opt/npmplus/tls/certbot"
        ;;
    2)
        TYPE_NAME="custom"
        NPM_CERT_ROOT="/opt/npmplus/tls/custom"
        ;;
    *)
        echo "[오류] 1 또는 2를 선택하세요."
        exit 1
        ;;
esac

read -rp "인증서 번호 (예: 1): " CERTNUM

[[ "$CERTNUM" =~ ^[0-9]+$ ]] || {
    echo "[오류] 인증서 번호는 숫자여야 합니다."
    exit 1
}

CERTNAME="npm-${CERTNUM}"
NPM_CERT_DIR="${NPM_CERT_ROOT}/${CERTNAME}"

echo
echo "[확인]"
echo "NPM Plus : $NPMID"
echo "AdGuard  : $ADGID"
echo "종류     : $TYPE_NAME"
echo "인증서   : $CERTNAME"
echo

# --------------------------------------------------
# 현재 NPM Plus의 인증서 확인
# --------------------------------------------------

if ! pct exec "$NPMID" -- test -f \
    "${NPM_CERT_DIR}/fullchain.pem"; then

    echo "[오류] fullchain.pem을 찾을 수 없습니다:"
    echo "${NPM_CERT_DIR}/fullchain.pem"
    exit 1
fi

if ! pct exec "$NPMID" -- test -f \
    "${NPM_CERT_DIR}/privkey.pem"; then

    echo "[오류] privkey.pem을 찾을 수 없습니다:"
    echo "${NPM_CERT_DIR}/privkey.pem"
    exit 1
fi

echo "[OK] 인증서 확인"

# --------------------------------------------------
# Host 전용 bind mount 디렉터리
# --------------------------------------------------

HOST_ROOT="${BASE}/${TYPE_NAME}"

mkdir -p "$HOST_ROOT"

echo
echo "[1/6] NPM Plus 인증서 저장소를 Host로 복사..."

# LXC가 실행 중이어도 pct exec로 파일을 읽는다.
# tar를 이용해 권한/심볼릭 링크/디렉터리 구조를 그대로 가져온다.

TMP="${HOST_ROOT}.tmp"

rm -rf "$TMP"
mkdir -p "$TMP"

pct exec "$NPMID" -- tar \
    -C "$NPM_CERT_ROOT" \
    -cpf - . \
    | tar -C "$TMP" -xpf -

rm -rf "$HOST_ROOT"
mv "$TMP" "$HOST_ROOT"

echo "[OK] Host 인증서 저장소 생성"

# --------------------------------------------------
# NPM Plus의 기존 인증서 저장소를 Host mount로 변경
# --------------------------------------------------

echo
echo "[2/6] NPM Plus 인증서 저장소 연결..."

NPM_MP=""

for i in $(seq 0 255); do
    if ! pct config "$NPMID" | grep -q "^mp${i}:"; then
        NPM_MP="mp${i}"
        break
    fi
done

if [[ -z "$NPM_MP" ]]; then
    echo "[오류] NPM Plus에서 사용 가능한 mount point가 없습니다."
    exit 1
fi

pct set "$NPMID" \
    "-${NPM_MP}" "${HOST_ROOT},mp=${NPM_CERT_ROOT}"

echo "[OK] NPM Plus → Host bind mount"
echo "     $HOST_ROOT"
echo "       ↓"
echo "     $NPM_CERT_ROOT"

# --------------------------------------------------
# AdGuard mount
# --------------------------------------------------

echo
echo "[3/6] AdGuard Home 인증서 mount 설정..."

ADG_MP=""

for i in $(seq 0 255); do
    if ! pct config "$ADGID" | grep -q "^mp${i}:"; then
        ADG_MP="mp${i}"
        break
    fi
done

if [[ -z "$ADG_MP" ]]; then
    echo "[오류] AdGuard Home에서 사용 가능한 mount point가 없습니다."
    exit 1
fi

ADG_PATH="/certs/${TYPE_NAME}"

pct set "$ADGID" \
    "-${ADG_MP}" "${HOST_ROOT},mp=${ADG_PATH},ro=1"

echo "[OK] Host → AdGuard bind mount"
echo "     $HOST_ROOT"
echo "       ↓"
echo "     $ADG_PATH"

# --------------------------------------------------
# NPM / AdGuard 재시작
# --------------------------------------------------

echo
echo "[4/6] 컨테이너 재시작..."

pct reboot "$NPMID" || pct restart "$NPMID"

sleep 5

pct reboot "$ADGID" || pct restart "$ADGID"

sleep 5

# --------------------------------------------------
# 실제 파일 확인
# --------------------------------------------------

echo
echo "[5/6] AdGuard에서 인증서 파일 확인..."

if ! pct exec "$ADGID" -- test -f \
    "${ADG_PATH}/${CERTNAME}/fullchain.pem"; then

    echo "[오류] AdGuard에서 fullchain.pem을 찾지 못했습니다."
    exit 1
fi

if ! pct exec "$ADGID" -- test -f \
    "${ADG_PATH}/${CERTNAME}/privkey.pem"; then

    echo "[오류] AdGuard에서 privkey.pem을 찾지 못했습니다."
    exit 1
fi

echo "[OK] 인증서 파일 확인"

# --------------------------------------------------
# NPM 갱신 후 AdGuard reload
# --------------------------------------------------

echo
echo "[6/6] NPM Plus 갱신 Hook 설정..."

HOOK_DIR="${HOST_ROOT}/renewal-hooks/deploy"
mkdir -p "$HOOK_DIR"

HOOK="${HOOK_DIR}/99-adguard-reload.sh"

cat > "$HOOK" <<EOF
#!/usr/bin/env bash

ADGID="${ADGID}"
CERTNAME="${CERTNAME}"

# 이 Hook은 NPM Plus Certbot이 인증서를 실제 배포한 경우에만 실행됩니다.

if [[ -n "\${RENEWED_LINEAGE:-}" ]] && \
   [[ "\${RENEWED_LINEAGE}" == *"/${CERTNAME}" ]]; then

    if pct status "\$ADGID" 2>/dev/null | grep -q "status: running"; then
        pct exec "\$ADGID" -- systemctl reload AdGuardHome 2>/dev/null || \
        pct exec "\$ADGID" -- systemctl restart AdGuardHome 2>/dev/null || true
    fi
fi
EOF

chmod 700 "$HOOK"

echo "[OK] 갱신 Hook 생성"

# --------------------------------------------------
# 최종 정보
# --------------------------------------------------

echo
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
echo "NPM Plus 인증서 원본:"
echo "${NPM_CERT_ROOT}/${CERTNAME}/"
echo
echo "AdGuard Home 입력값:"
echo
echo "Certificate Path:"
echo "${ADG_PATH}/${CERTNAME}/fullchain.pem"
echo
echo "Private Key Path:"
echo "${ADG_PATH}/${CERTNAME}/privkey.pem"
echo
echo "=============================================================="
echo
echo "인증서 갱신:"
echo "  NPM Plus Certbot이 자동 처리"
echo
echo "인증서 공유:"
echo "  Host bind mount로 동일 파일 사용"
echo
echo "AdGuard 갱신:"
echo "  Certbot deploy hook에서 자동 reload"
echo
echo "주기적인 인증서 복사/동기화:"
echo "  없음"
echo "=============================================================="
