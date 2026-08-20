#!/usr/bin/env bash
set -euo pipefail

# NPM Plus Certbot deploy hook -> AdGuard Home
# bind mount, polling, cron을 사용하지 않으며 NPM 인증서 파일을 변경하지 않습니다.

HOOK_DIR=/opt/npmplus/tls/certbot/renewal-hooks/deploy
ADG_CERT_DIR=/etc/adguardhome/certs
SSH_KEY=/root/.ssh/id_ed25519_adguard

line() { printf '%s\n' '--------------------------------------------------'; }
section() { echo; line; echo " $1"; line; }
field() { printf ' %-16s %s\n' "$1:" "$2"; }
die() { echo "[오류] $*" >&2; exit 1; }
check_ct() {
    [[ $1 =~ ^[0-9]+$ ]] || die "LXC 번호는 숫자여야 합니다."
    pct status "$1" >/dev/null 2>&1 || die "LXC $1 를 찾을 수 없습니다."
}
check_env() {
    [[ $EUID -eq 0 ]] || die "Proxmox Host의 root로 실행하세요."
    command -v pct >/dev/null 2>&1 || die "pct 명령을 찾을 수 없습니다."
}
get_ip() {
    local ip
    ip="$(pct config "$1" | sed -n 's/.*ip=\([^,\/]*\).*/\1/p' | head -n 1)"
    [[ -n $ip ]] || die "AdGuard Home LXC IP를 자동으로 찾지 못했습니다."
    printf '%s\n' "$ip"
}

# 출력 형식: Hook파일명|AdGuard LXC|인증서 번호
# 파일명: 99-adguard-NPMID-ADGID-CERTNUM.sh
hook_lines() {
    local npm=$1 file a b c d e cert
    while IFS= read -r file; do
        IFS=- read -r a b c d e <<< "$file"
        if [[ $e == *.sh && $a == 99 && $b == adguard && $c == "$npm" && $d =~ ^[0-9]+$ ]]; then
            cert="$(printf '%s' "$e" | sed 's/\.sh$//')"
            [[ $cert =~ ^[0-9]+$ ]] && printf '%s|%s|%s\n' "$file" "$d" "$cert"
        fi
    done < <(pct exec "$npm" -- sh -c '
        for f in /opt/npmplus/tls/certbot/renewal-hooks/deploy/99-adguard-*.sh; do
            [ -f "$f" ] && basename "$f"
        done
    ' 2>/dev/null | sort)
}
show_hooks() {
    local npm=$1 line hook adg cert i=0
    while IFS='|' read -r hook adg cert; do
        i=$((i + 1))
        printf '%2d) NPM LXC: %s | AdGuard LXC: %s | 인증서: npm-%s\n' "$i" "$npm" "$adg" "$cert"
        printf '    Hook: %s/%s\n' "$HOOK_DIR" "$hook"
    done < <(hook_lines "$npm")
    (( i > 0 )) || { echo "[INFO] AdGuard Deploy Hook이 없습니다."; return 1; }
}
select_hook() {
    local npm pick count line
    read -rp "NPM Plus LXC 번호: " npm; check_ct "$npm"
    show_hooks "$npm" || return 1
    count="$(hook_lines "$npm" | wc -l | tr -d ' ')"
    read -rp "Hook 번호 선택: " pick
    [[ $pick =~ ^[0-9]+$ ]] && (( pick >= 1 && pick <= count )) || {
        echo "[오류] 목록에 없는 Hook 번호입니다."; return 1;
    }
    line="$(hook_lines "$npm" | sed -n "$pick"p)"
    IFS='|' read -r SEL_HOOK SEL_ADG SEL_CERT <<< "$line"
    SEL_NPM=$npm
}

setup_ssh() {
    local npm=$1 adg=$2 pub
    echo "[2/7] AdGuard Home SSH 서버 확인..."
    if ! pct exec "$adg" -- sh -c 'command -v sshd >/dev/null 2>&1'; then
        echo "[INFO] AdGuard Home에 OpenSSH Server 설치..."
        pct exec "$adg" -- apk add --no-cache openssh
        pct exec "$adg" -- ssh-keygen -A
        pct exec "$adg" -- rc-update add sshd default 2>/dev/null || true
    fi
    pct exec "$adg" -- rc-service sshd start 2>/dev/null || true
    echo "[3/7] NPM Plus SSH client 확인..."
    if ! pct exec "$npm" -- sh -c 'command -v ssh >/dev/null 2>&1 && command -v scp >/dev/null 2>&1'; then
        pct exec "$npm" -- apk add --no-cache openssh-client
    fi
    echo "[4/7] NPM Plus → AdGuard SSH 인증 설정..."
    pct exec "$npm" -- mkdir -p /root/.ssh
    pct exec "$npm" -- chmod 700 /root/.ssh
    if ! pct exec "$npm" -- test -f "$SSH_KEY"; then
        pct exec "$npm" -- ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -C npmplus-to-adguard
    fi
    pub="$(pct exec "$npm" -- cat "$SSH_KEY.pub")"
    pct exec "$adg" -- mkdir -p /root/.ssh
    pct exec "$adg" -- chmod 700 /root/.ssh
    pct exec "$adg" -- sh -c "touch /root/.ssh/authorized_keys &&
        sed -i '/npmplus-to-adguard/d' /root/.ssh/authorized_keys &&
        printf '%s\n' '$pub' >> /root/.ssh/authorized_keys &&
        chmod 600 /root/.ssh/authorized_keys"
}

# 두 파일을 .tmp로 전송한 뒤에만 원격에서 교체·권한 변경·reload합니다.
copy_atomic() {
    local npm=$1 source=$2 ip=$3
    pct exec "$npm" -- sh -c "
        set -eu
        scp -i '$SSH_KEY' -q '$source/fullchain.pem' root@'$ip':'$ADG_CERT_DIR'/fullchain.pem.tmp
        scp -i '$SSH_KEY' -q '$source/privkey.pem' root@'$ip':'$ADG_CERT_DIR'/privkey.pem.tmp
        ssh -i '$SSH_KEY' root@'$ip' \"set -eu;
          mv '$ADG_CERT_DIR/fullchain.pem.tmp' '$ADG_CERT_DIR/fullchain.pem';
          mv '$ADG_CERT_DIR/privkey.pem.tmp' '$ADG_CERT_DIR/privkey.pem';
          chmod 644 '$ADG_CERT_DIR/fullchain.pem';
          chmod 600 '$ADG_CERT_DIR/privkey.pem';
          if command -v systemctl >/dev/null 2>&1; then
            systemctl reload AdGuardHome 2>/dev/null || systemctl restart AdGuardHome;
          elif [ -x /etc/init.d/adguardhome ]; then
            rc-service adguardhome reload 2>/dev/null || rc-service adguardhome restart;
          elif [ -x /etc/init.d/AdGuardHome ]; then
            rc-service AdGuardHome reload 2>/dev/null || rc-service AdGuardHome restart;
          else
            echo 'AdGuardHome 서비스 관리 명령을 찾을 수 없습니다.' >&2; exit 1;
          fi\"
    "
}
reload_adguard() {
    pct exec "$1" -- sh -c '
        set -eu
        if command -v systemctl >/dev/null 2>&1; then
            systemctl reload AdGuardHome 2>/dev/null || systemctl restart AdGuardHome
        elif [ -x /etc/init.d/adguardhome ]; then
            rc-service adguardhome reload 2>/dev/null || rc-service adguardhome restart
        elif [ -x /etc/init.d/AdGuardHome ]; then
            rc-service AdGuardHome reload 2>/dev/null || rc-service AdGuardHome restart
        else
            echo "AdGuardHome 서비스 관리 명령을 찾을 수 없습니다." >&2
            exit 1
        fi
    '
}
find_adguard_config() {
    pct exec "$1" -- sh -c '
        for config in \
            /opt/AdGuardHome/AdGuardHome.yaml \
            /opt/adguardhome/AdGuardHome.yaml \
            /etc/adguardhome/AdGuardHome.yaml; do
            [ -f "$config" ] && { printf "%s\n" "$config"; exit 0; }
        done
        exit 1
    ' 2>/dev/null || true
}
register_tls_paths() {
    local adg=$1 config
    config="$(find_adguard_config "$adg")"
    [[ -n $config ]] || die "AdGuardHome.yaml을 자동으로 찾지 못했습니다. 수동 등록을 선택하세요."
    pct exec "$adg" -- sh -c "
        grep -q '^tls:' '$config' &&
        grep -q '^[[:space:]]*certificate_chain:' '$config' &&
        grep -q '^[[:space:]]*private_key:' '$config' &&
        grep -q '^[[:space:]]*certificate_path:' '$config' &&
        grep -q '^[[:space:]]*private_key_path:' '$config'
    " || die "AdGuardHome.yaml의 tls/certificate_chain/private_key/certificate_path/private_key_path 항목을 찾지 못했습니다. 수동 등록을 선택하세요."
    pct exec "$adg" -- sh -c '
        config=$1 cert=$2 key=$3
        cp "$config" "$config.before-npm-adguard.bak"
        sed -i "s|^\([[:space:]]*certificate_chain:[[:space:]]*\).*|\1\"\"|" "$config"
        sed -i "s|^\([[:space:]]*private_key:[[:space:]]*\).*|\1\"\"|" "$config"
        sed -i "s|^\([[:space:]]*certificate_path:[[:space:]]*\).*|\1\"$cert\"|" "$config"
        sed -i "s|^\([[:space:]]*private_key_path:[[:space:]]*\).*|\1\"$key\"|" "$config"
    ' sh "$config" "$ADG_CERT_DIR/fullchain.pem" "$ADG_CERT_DIR/privkey.pem"
    reload_adguard "$adg"
    echo "[OK] AdGuard Home TLS 경로를 자동 등록했습니다: $config"
}
write_hook() {
    local npm=$1 ip=$2 cert=$3 target=$4 content b64
    content="#!/bin/sh
set -eu
IP='$ip'
DEST='$ADG_CERT_DIR'
LINEAGE='/opt/npmplus/tls/certbot/live/npm-$cert'
KEY='$SSH_KEY'
[ \"\$RENEWED_LINEAGE\" = \"\$LINEAGE\" ] 2>/dev/null || exit 0
scp -i \"\$KEY\" -q \"\$LINEAGE/fullchain.pem\" root@\"\$IP\":\"\$DEST\"/fullchain.pem.tmp
scp -i \"\$KEY\" -q \"\$LINEAGE/privkey.pem\" root@\"\$IP\":\"\$DEST\"/privkey.pem.tmp
ssh -i \"\$KEY\" root@\"\$IP\" \"set -eu;
  mv '\$DEST/fullchain.pem.tmp' '\$DEST/fullchain.pem';
  mv '\$DEST/privkey.pem.tmp' '\$DEST/privkey.pem';
  chmod 644 '\$DEST/fullchain.pem';
  chmod 600 '\$DEST/privkey.pem';
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload AdGuardHome 2>/dev/null || systemctl restart AdGuardHome;
  elif [ -x /etc/init.d/adguardhome ]; then
    rc-service adguardhome reload 2>/dev/null || rc-service adguardhome restart;
  elif [ -x /etc/init.d/AdGuardHome ]; then
    rc-service AdGuardHome reload 2>/dev/null || rc-service AdGuardHome restart;
  else
    echo 'AdGuardHome 서비스 관리 명령을 찾을 수 없습니다.' >&2; exit 1;
  fi\"
"
    b64="$(printf '%s' "$content" | base64 | tr -d '\n')"
    pct exec "$npm" -- sh -c "printf '%s' '$b64' | base64 -d > '$target' && chmod 700 '$target'"
}

install() {
    local npm adg type cert base source ip answer tls_mode line hook old_adg old_cert duplicates=""
    read -rp "NPM Plus LXC 번호: " npm; check_ct "$npm"
    read -rp "AdGuard Home LXC 번호: " adg; check_ct "$adg"
    echo "인증서 종류: 1) certbot  2) custom"
    read -rp "선택 [1-2]: " type
    case "$type" in 1) base=/opt/npmplus/tls/certbot/live;; 2) base=/opt/npmplus/tls/custom;; *) echo "[오류] 1 또는 2를 선택하세요."; return 1;; esac
    read -rp "인증서 번호 (예: 1): " cert
    [[ $cert =~ ^[0-9]+$ ]] || { echo "[오류] 인증서 번호는 숫자여야 합니다."; return 1; }
    source="$base/npm-$cert"
    pct exec "$npm" -- test -f "$source/fullchain.pem" || { echo "[오류] fullchain.pem을 찾을 수 없습니다."; return 1; }
    pct exec "$npm" -- test -f "$source/privkey.pem" || { echo "[오류] privkey.pem을 찾을 수 없습니다."; return 1; }
    if [[ $type == 1 ]]; then
        while IFS='|' read -r hook old_adg old_cert; do
            [[ $old_adg == "$adg" && $old_cert == "$cert" ]] && duplicates="$duplicates$hook"$'\n'
        done < <(hook_lines "$npm")
        if [[ -n $duplicates ]]; then
            echo "[INFO] 동일한 NPM $npm / AdGuard $adg / npm-$cert Hook이 이미 존재합니다."
            while IFS= read -r hook; do [[ -n $hook ]] && echo "  $HOOK_DIR/$hook"; done <<< "$duplicates"
            read -rp "덮어쓸까요? (Y/N): " answer
            [[ $answer =~ ^[Yy]$ ]] || { echo "[INFO] 설치를 취소했습니다."; return 0; }
        fi
    fi
    echo "[1/7] AdGuard Home 인증서 디렉터리 생성..."
    pct exec "$adg" -- mkdir -p "$ADG_CERT_DIR"
    setup_ssh "$npm" "$adg"
    ip="$(get_ip "$adg")"; echo "AdGuard Home IP: $ip"
    pct exec "$npm" -- sh -c "ssh-keyscan -H '$ip' >> /root/.ssh/known_hosts 2>/dev/null || true"
    echo
    echo "AdGuard Home TLS 인증서 경로 등록"
    echo "  1) 자동 등록 (certificate_chain/private_key 비움, *_path 경로 등록)"
    echo "  2) 수동 등록"
    read -rp "선택 [1-2]: " tls_mode
    case "$tls_mode" in
        1|2) ;;
        *) echo "[오류] 1 또는 2를 선택하세요."; return 1 ;;
    esac
    echo "[5/7] 최초 인증서 Atomic Copy..."
    copy_atomic "$npm" "$source" "$ip"
    if [[ $tls_mode == 1 ]]; then
        register_tls_paths "$adg"
    else
        echo "[INFO] TLS 경로는 수동 등록으로 선택했습니다."
    fi
    echo "[6/7] Certbot deploy hook 설치..."
    if [[ $type == 1 ]]; then
        pct exec "$npm" -- mkdir -p "$HOOK_DIR"
        if [[ -n $duplicates ]]; then
            while IFS= read -r hook; do [[ -n $hook ]] && write_hook "$npm" "$ip" "$cert" "$HOOK_DIR/$hook"; done <<< "$duplicates"
        else
            write_hook "$npm" "$ip" "$cert" "$HOOK_DIR/99-adguard-$npm-$adg-$cert.sh"
        fi
        echo "[OK] Deploy hook 설치 완료"
    else
        echo "[INFO] custom 인증서는 기존 동작과 같이 Certbot Hook을 만들지 않습니다."
    fi
    echo "[7/7] SSH 연결 테스트..."
    pct exec "$npm" -- sh -c "ssh -i '$SSH_KEY' -o BatchMode=yes root@'$ip' 'echo SSH_OK'"
    echo "[완료] polling, cron, bind mount 없이 자동 연동을 설정했습니다."
    echo "AdGuard Home 인증서 경로: $ADG_CERT_DIR/fullchain.pem"
    echo "AdGuard Home 개인키 경로:   $ADG_CERT_DIR/privkey.pem"
    if [[ $tls_mode == 2 ]]; then
        echo "수동 등록: TLS certificate_chain/private_key는 비우고, certificate_path/private_key_path에 위 경로를 입력하세요."
    fi
}
status() { local npm; read -rp "NPM Plus LXC 번호: " npm; check_ct "$npm"; show_hooks "$npm" || true; }
remove_hook() {
    local answer
    select_hook || return 0
    echo "삭제 대상: $HOOK_DIR/$SEL_HOOK"
    read -rp "이 Hook만 삭제할까요? (Y/N): " answer
    [[ $answer =~ ^[Yy]$ ]] || { echo "[INFO] 제거를 취소했습니다."; return 0; }
    pct exec "$SEL_NPM" -- rm -f "$HOOK_DIR/$SEL_HOOK"
    echo "[OK] Hook만 삭제했습니다. 인증서, SSH Key, authorized_keys는 유지했습니다."
}
test_hook() {
    select_hook || return 0
    echo "[TEST] $HOOK_DIR/$SEL_HOOK 강제 실행..."
    pct exec "$SEL_NPM" -- env "RENEWED_LINEAGE=/opt/npmplus/tls/certbot/live/npm-$SEL_CERT" sh "$HOOK_DIR/$SEL_HOOK"
    echo "[OK] Hook 실행 완료"
}
main() {
    local choice
    check_env
    while true; do
        echo; echo "=================================================="
        echo " NPM Plus → AdGuard Home 인증서 자동 연동"
        echo "=================================================="
        echo "1) 설치"; echo "2) 상태 조회"; echo "3) 제거"; echo "4) 테스트"; echo "5) 종료"
        read -rp "선택 [1-5]: " choice
        case "$choice" in
            1) install;; 2) status;; 3) remove_hook;; 4) test_hook;;
            5) echo "종료합니다."; exit 0;;
            *) echo "[오류] 1부터 5 사이의 번호를 선택하세요.";;
        esac
    done
}
main "$@"
