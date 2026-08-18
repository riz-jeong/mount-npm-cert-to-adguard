#!/usr/bin/env bash
set -euo pipefail

BASE="/mnt/bindmounts/npmplus-cert"

echo
echo "=================================================="
echo " NPM Plus 인증서 → AdGuard Home 자동 연결"
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
        CERT_ROOT="/opt/npmplus/tls/certbot"
        ;;
    2)
        TYPE_NAME="custom"
        CERT_ROOT="/opt/npmplus/tls/custom"
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

# --------------------------------------------------
# 인증서 실제 경로
# --------------------------------------------------

if [[ "$TYPE_NAME" == "certbot" ]]; then
    CERT_DIR="${CERT_ROOT}/live/${CERTNAME}"
else
    CERT_DIR="${CERT_ROOT}/${CERTNAME}"
fi

echo
echo "[확인]"
echo "NPM Plus : $NPMID"
echo "AdGuard  : $ADGID"
echo "종류     : $TYPE_NAME"
echo "인증서   : $CERTNAME"
echo "경로     : $CERT_DIR"
echo

if ! pct exec "$NPMID" -- test -f "${CERT_DIR}/fullchain.pem"; then
    echo "[오류] fullchain.pem을 찾을 수 없습니다:"
    echo "${CERT_DIR}/fullchain.pem"
    exit 1
fi

if ! pct exec "$NPMID" -- test -f "${CERT_DIR}/privkey.pem"; then
    echo "[오류] privkey.pem을 찾을 수 없습니다:"
    echo "${CERT_DIR}/privkey.pem"
    exit 1
fi

echo "[OK] 인증서 확인"

# --------------------------------------------------
# Host 저장 위치
# --------------------------------------------------

HOST_CERT_DIR="${BASE}/${TYPE_NAME}"

echo
echo "[1/6] NPM Plus 인증서 저장소를 Host로 복사..."

TMP_DIR="${HOST_CERT_DIR}.tmp"

rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

if [[ "$TYPE_NAME" == "certbot" ]]; then

    # certbot은 live → archive 심볼릭 링크 구조이므로
    # certbot 전체를 복사한다.
    pct exec "$NPMID" -- tar \
        -C "$CERT_ROOT" \
        -cpf - . \
        | tar -C "$TMP_DIR" -xpf -

else

    # custom은 해당 인증서 하나만 복사
    mkdir -p "${TMP_DIR}/${CERTNAME}"

    pct exec "$NPMID" -- tar \
        -C "$CERT_ROOT" \
        -cpf - "${CERTNAME}" \
        | tar -C "$TMP_DIR" -xpf -

fi

rm -rf "$HOST_CERT_DIR"
mv "$TMP_DIR" "$HOST_CERT_DIR"

echo "[OK] Host 저장소 생성:"
echo "$HOST_CERT_DIR"

# --------------------------------------------------
# 실제 인증서 파일 재확인
# --------------------------------------------------

if [[ "$TYPE_NAME" == "certbot" ]]; then
    HOST_CERT_DIR_FOR_CHECK="${HOST_CERT_DIR}/live/${CERTNAME}"
else
    HOST_CERT_DIR_FOR_CHECK="${HOST_CERT_DIR}/${CERTNAME}"
fi

if [[ ! -f "${HOST_CERT_DIR_FOR_CHECK}/fullchain.pem" ]]; then
    echo "[오류] Host에서 fullchain.pem을 찾을 수 없습니다."
    exit 1
fi

if [[ ! -f "${HOST_CERT_DIR_FOR_CHECK}/privkey.pem" ]]; then
    echo "[오류] Host에서 privkey.pem을 찾을 수 없습니다."
    exit 1
fi

# --------------------------------------------------
# NPM Plus mount
# --------------------------------------------------

echo
echo "[2/6] NPM Plus 인증서 저장소 bind mount..."

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
    "-${NPM_MP}" "${HOST_CERT_DIR},mp=${CERT_ROOT}"

echo "[OK] NPM Plus:"
echo "  ${HOST_CERT_DIR}"
echo "       ↓"
echo "  ${CERT_ROOT}"

# --------------------------------------------------
# AdGuard mount
# --------------------------------------------------

echo
echo "[3/6] AdGuard Home bind mount..."

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
    "-${ADG_MP}" "${HOST_CERT_DIR},mp=${ADG_PATH},ro=1"

echo "[OK] AdGuard Home:"
echo "  ${HOST_CERT_DIR}"
echo "       ↓"
echo "  ${ADG_PATH}"

# --------------------------------------------------
# NPM 갱신 후 AdGuard 자동 reload
# --------------------------------------------------

echo
echo "[4/6] NPM Plus 인증서 갱신 Hook 설정..."

if [[ "$TYPE_NAME" == "certbot" ]]; then

    HOOK_DIR="${HOST_CERT_DIR}/renewal-hooks/deploy"
    mkdir -p "$HOOK_DIR"

    HOOK="${HOOK_DIR}/99-adguard-${ADGID}.sh"

    cat > "$HOOK" <<EOF
#!/usr/bin/env bash

ADGID="${ADGID}"
CERTNAME="${CERTNAME}"

if [[ -n "\${RENEWED_LINEAGE:-}" ]] && \
   [[ "\${RENEWED_LINEAGE}" == *"/\${CERTNAME}" ]]; then

    if pct status "\$ADGID" 2>/dev/null | grep -q "status: running"; then
        pct exec "\$ADGID" -- systemctl reload AdGuardHome 2>/dev/null || \
        pct exec "\$ADGID" -- systemctl restart AdGuardHome 2>/dev/null || true
    fi
fi
EOF

    chmod 700 "$HOOK"

    echo "[OK] Certbot deploy hook 생성:"
    echo "$HOOK"

else

    echo "[INFO] custom 인증서는 자동 갱신 Hook을 만들지 않습니다."
    echo "       custom 인증서가 외부에서 갱신되는 경우 해당 시스템에서"
    echo "       AdGuardHome reload가 필요합니다."

fi

# --------------------------------------------------
# 컨테이너 재시작
# --------------------------------------------------

echo
echo "[5/6] 컨테이너 재시작..."

if pct status "$NPMID" | grep -q "status: running"; then
    pct reboot "$NPMID"
    sleep 5
fi

if pct status "$ADGID" | grep -q "status: running"; then
    pct reboot "$ADGID"
    sleep 5
fi

# --------------------------------------------------
# AdGuard에서 실제 파일 확인
# --------------------------------------------------

echo
echo "[6/6] AdGuard Home 인증서 확인..."

if [[ "$TYPE_NAME" == "certbot" ]]; then
    ADG_CERT_DIR="${ADG_PATH}/live/${CERTNAME}"
else
    ADG_CERT_DIR="${ADG_PATH}/${CERTNAME}"
fi

if ! pct exec "$ADGID" -- test -f \
    "${ADG_CERT_DIR}/fullchain.pem"; then

    echo "[오류] AdGuard Home에서 fullchain.pem을 찾지 못했습니다:"
    echo "${ADG_CERT_DIR}/fullchain.pem"
    exit 1
fi

if ! pct exec "$ADGID" -- test -f \
    "${ADG_CERT_DIR}/privkey.pem"; then

    echo "[오류] AdGuard Home에서 privkey.pem을 찾지 못했습니다:"
    echo "${ADG_CERT_DIR}/privkey.pem"
    exit 1
fi

echo "[OK] AdGuard Home에서 인증서 확인"

# --------------------------------------------------
# 최종 출력
# --------------------------------------------------

echo
echo
echo "=============================================================="
echo "                    설정 완료"
echo "=============================================================="
echo
echo "NPM Plus LXC       : $NPMID"
echo "AdGuard Home LXC   : $ADGID"
echo "인증서 종류        : $TYPE_NAME"
echo "인증서 번호        : $CERTNAME"
echo
echo "AdGuard Home → Settings → Encryption"
echo

echo "Certificate Path:"
echo "${ADG_CERT_DIR}/fullchain.pem"
echo

echo "Private Key Path:"
echo "${ADG_CERT_DIR}/privkey.pem"
echo
echo "=============================================================="
echo
echo "인증서는 NPM Plus와 AdGuard Home이 동일 파일을 사용합니다."
echo "Certbot 갱신 시 AdGuard Home도 자동 reload 됩니다."
echo "주기적인 인증서 복사 작업은 사용하지 않습니다."
echo "=============================================================="
echo
