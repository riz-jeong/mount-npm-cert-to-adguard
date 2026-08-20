#!/usr/bin/env bash
set -euo pipefail

# =====================================================================
# NPM Plus -> AdGuard Home 인증서 실시간 연동
# =====================================================================
# bind mount, cron, 원격 polling을 사용하지 않음
# =====================================================================

ADG_CERT_DIR=/etc/adguardhome/certs
SSH_KEY=/root/.ssh/id_ed25519_adguard
SYNC_DIR=/opt/npmplus/tls/.adguard-sync
MAP_FILE_REMOTE="$SYNC_DIR/mappings.conf"
LOG_REMOTE=/var/log/npmplus-adguard-deploy.log

# ------------------------------- 출력 도우미 -------------------------------
if [[ -t 1 ]] && [[ -z ${NO_COLOR:-} ]]; then
    C_RESET=$'\033[0m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'
else
    C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""
fi
line() { printf '%s\n' '--------------------------------------------------'; }
section() { echo; printf '%s' "$C_CYAN"; line; printf ' %s\n' "$1"; line; printf '%s' "$C_RESET"; }
field() { printf ' %-16s %s\n' "$1:" "$2"; }
ok()   { printf '%s[OK]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
info() { printf '%s[INFO]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()  { printf '%s[오류]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

# 원격 sh -c 의 단일따옴표 문자열에 안전하게 삽입하기 위한 이스케이프
# (예: Let's → Let'\''s 로 변환하여 따옴표 깨짐 방지)
sq_escape() {
    printf '%s' "${1//\'/\'\\\'\'}"
}

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
file_digest() {
    local ctid=$1 path=$2
    pct exec "$ctid" -- sh -c "
        if [ -f '$path' ]; then
            (sha256sum '$path' 2>/dev/null || busybox sha256sum '$path') | awk '{print \$1}'
        else
            printf '%s' '없음'
        fi
    "
}

# ------------------------------- 인증서 탐색/선택 -------------------------------
cert_domain() {
    local ctid=$1 path=$2 out num pem
    num=$(basename "$(dirname "$path")")
    num=${num#npm-}

    # 1) LXC에 openssl이 없는 경우가 많음 → 인증서 내용을 Host openssl로 파싱
    if command -v openssl >/dev/null 2>&1; then
        pem="$(pct exec "$ctid" -- cat "$path" 2>/dev/null || true)"
        if [[ -z $pem ]]; then
            pem="$(pct exec "$ctid" -- cat "/data/tls/certbot/live/npm-${num}/fullchain.pem" 2>/dev/null || true)"
        fi
        if [[ -n $pem ]]; then
            out="$(printf '%s\n' "$pem" | openssl x509 -noout -subject 2>/dev/null |
                sed -n -e 's/.*[Cc][Nn][[:space:]]*=[[:space:]]*//p' | sed 's/,.*//' | head -n1)"
            out="${out//$'\r'/}"; out="$(printf '%s' "$out" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
            if [[ -z $out || $out == *"="* ]]; then
                out="$(printf '%s\n' "$pem" | openssl x509 -noout -text 2>/dev/null |
                    sed -n 's/.*DNS:\([^, ]*\).*/\1/p' | head -n1)"
                out="${out//$'\r'/}"; out="$(printf '%s' "$out" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
            fi
        fi
    fi

    # 2) NPM DB (certificate.domain_names) — DNS 인증서도 여기에 기록됨
    if [[ -z $out ]]; then
        out="$(pct exec "$ctid" -- sh -c "
            for db in \
                /opt/npmplus/npmplus/database.sqlite \
                /opt/npmplus/data/npmplus/database.sqlite \
                /data/npmplus/database.sqlite \
                /data/database.sqlite; do
                [ -f \"\$db\" ] || continue
                if command -v sqlite3 >/dev/null 2>&1; then
                    sqlite3 \"\$db\" \"SELECT domain_names FROM certificate WHERE id=${num} LIMIT 1;\" 2>/dev/null
                fi
            done
        " 2>/dev/null | head -n1 || true)"
        out="$(printf '%s' "$out" | sed -e 's/^\["*//' -e 's/"*\].*$//' -e 's/".*//' -e 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    fi

    # 3) renewal conf webroot_map (HTTP 인증서용, DNS면 비어 있을 수 있음)
    if [[ -z $out ]]; then
        out="$(pct exec "$ctid" -- sh -c "
            for c in /opt/npmplus/tls/certbot/renewal/npm-${num}.conf /data/tls/certbot/renewal/npm-${num}.conf; do
                [ -f \"\$c\" ] || continue
                sed -n '/^\[\[webroot_map\]\]/,/^\[/p' \"\$c\" 2>/dev/null |
                    sed -n 's/^[[:space:]]*\([^[:space:]=]\+\)[[:space:]]*=.*/\1/p' | head -n1
            done
        " 2>/dev/null | head -n1 || true)"
        out="$(printf '%s' "$out" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    fi

    [[ -n $out ]] && printf '%s\n' "$out" || printf '%s\n' "(도메인 확인 불가)"
}
list_certs() {
    local npm=$1
    pct exec "$npm" -- sh -c '
        for d in /opt/npmplus/tls/certbot/live/npm-*; do
            [ -d "$d" ] || continue
            n=$(basename "$d"); n=${n#npm-}
            [ -f "$d/fullchain.pem" ] && printf "certbot|%s|%s\n" "$n" "$d"
        done
        for d in /opt/npmplus/tls/custom/npm-*; do
            [ -d "$d" ] || continue
            n=$(basename "$d"); n=${n#npm-}
            [ -f "$d/fullchain.pem" ] && printf "custom|%s|%s\n" "$n" "$d"
        done
        true
    ' 2>/dev/null | sort -t'|' -k2 -n
}
# 선택 결과: PICK_TYPE / PICK_NUM / PICK_PATH / PICK_DOMAIN
pick_cert() {
    local npm=$1 lines n=0 type num path pick
    section "인증서 선택 · NPM LXC $npm"
    lines="$(list_certs "$npm")"
    if [[ -z $lines ]]; then
        warn "자동으로 검색된 인증서가 없습니다. 번호를 직접 입력합니다."
        echo "  1) Certbot / Let's Encrypt · 자동 갱신"
        echo "  2) Custom · 최초 복사만"
        read -rp "선택 [1-2]: " t
        case "$t" in 1) PICK_TYPE=certbot;; 2) PICK_TYPE=custom;; *) die "1 또는 2를 선택하세요.";; esac
        read -rp "인증서 번호 (예: 1): " num
        [[ $num =~ ^[0-9]+$ ]] || die "인증서 번호는 숫자여야 합니다."
        if [[ $PICK_TYPE == certbot ]]; then path="/opt/npmplus/tls/certbot/live/npm-$num"; else path="/opt/npmplus/tls/custom/npm-$num"; fi
        pct exec "$npm" -- test -f "$path/fullchain.pem" || die "$path/fullchain.pem을 찾을 수 없습니다."
        PICK_NUM=$num; PICK_PATH=$path; PICK_DOMAIN="(자동 확인 안 함)"
        return 0
    fi
    echo "감지된 인증서:"
    local -a arr_type=() arr_num=() arr_path=() arr_domain=()
    while IFS='|' read -r type num path; do
        [[ -n $type ]] || continue
        n=$((n + 1))
        local domain; domain="$(cert_domain "$npm" "$path/fullchain.pem")"
        arr_type[$n]=$type; arr_num[$n]=$num; arr_path[$n]=$path; arr_domain[$n]=$domain
        if [[ $type == certbot ]]; then
            printf '%2d) [Let'\''s Encrypt] npm-%s · %s\n' "$n" "$num" "$domain"
        else
            printf '%2d) [Custom]         npm-%s · %s\n' "$n" "$num" "$domain"
        fi
    done <<< "$lines"
    echo " 0) 목록에 없음 · 번호 직접 입력"
    read -rp "선택: " pick
    if [[ $pick == 0 ]]; then
        echo "  1) Certbot / Let's Encrypt · 자동 갱신"
        echo "  2) Custom · 최초 복사만"
        read -rp "선택 [1-2]: " t
        case "$t" in 1) PICK_TYPE=certbot;; 2) PICK_TYPE=custom;; *) die "1 또는 2를 선택하세요.";; esac
        read -rp "인증서 번호 (예: 1): " num
        [[ $num =~ ^[0-9]+$ ]] || die "인증서 번호는 숫자여야 합니다."
        if [[ $PICK_TYPE == certbot ]]; then path="/opt/npmplus/tls/certbot/live/npm-$num"; else path="/opt/npmplus/tls/custom/npm-$num"; fi
        pct exec "$npm" -- test -f "$path/fullchain.pem" || die "$path/fullchain.pem을 찾을 수 없습니다."
        PICK_NUM=$num; PICK_PATH=$path; PICK_DOMAIN="(자동 확인 안 함)"
        return 0
    fi
    [[ $pick =~ ^[0-9]+$ ]] && (( pick >= 1 && pick <= n )) || die "목록에 없는 번호입니다."
    PICK_TYPE=${arr_type[$pick]}; PICK_NUM=${arr_num[$pick]}; PICK_PATH=${arr_path[$pick]}; PICK_DOMAIN=${arr_domain[$pick]}
}

# ------------------------------- SSH 설정 -------------------------------
setup_ssh() {
    local npm=$1 adg=$2 pub
    echo "[2/7] AdGuard Home SSH 서버 확인..."
    if ! pct exec "$adg" -- sh -c 'command -v sshd >/dev/null 2>&1'; then
        info "AdGuard Home에 OpenSSH Server 설치..."
        pct exec "$adg" -- apk add --no-cache openssh
        pct exec "$adg" -- ssh-keygen -A
    fi
    # 최신 scp는 SFTP를 사용합니다. 외부 sftp-server 패키지에 의존하지 않는
    # OpenSSH 내장 internal-sftp를 명시해 Alpine에서 전송 프로토콜을 보장
    pct exec "$adg" -- sh -c '
        config=/etc/ssh/sshd_config
        if grep -q "^[[:space:]]*Subsystem[[:space:]][[:space:]]*sftp[[:space:]]" "$config"; then
            sed -i "s|^[[:space:]]*Subsystem[[:space:]][[:space:]]*sftp[[:space:]].*|Subsystem sftp internal-sftp|" "$config"
        else
            printf "\nSubsystem sftp internal-sftp\n" >> "$config"
        fi
    '
    pct exec "$adg" -- rc-update add sshd default >/dev/null 2>&1 || true
    if pct exec "$adg" -- rc-service sshd status >/dev/null 2>&1; then
        pct exec "$adg" -- rc-service sshd restart
    else
        pct exec "$adg" -- rc-service sshd start
    fi
    pct exec "$adg" -- rc-service sshd status >/dev/null ||
        die "AdGuard Home SSH 서버(sshd)를 시작하지 못했습니다. LXC $adg 에서 'rc-service sshd start'와 'sshd -t' 결과를 확인하세요."
    echo "[3/7] NPM Plus SSH client 확인..."
    if ! pct exec "$npm" -- sh -c 'command -v ssh >/dev/null 2>&1 && command -v scp >/dev/null 2>&1'; then
        pct exec "$npm" -- apk add --no-cache openssh-client
    fi
    echo "[4/7] NPM Plus -> AdGuard SSH 인증 설정..."
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

# 두 파일을 .tmp로 전송한 뒤에만 원격에서 교체·권한 변경·reload
copy_atomic() {
    local npm=$1 source=$2 ip=$3
    pct exec "$npm" -- sh -c "
        set -eu
        scp -i '$SSH_KEY' -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -q '$source/fullchain.pem' root@'$ip':'$ADG_CERT_DIR'/fullchain.pem.tmp
        scp -i '$SSH_KEY' -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -q '$source/privkey.pem' root@'$ip':'$ADG_CERT_DIR'/privkey.pem.tmp
        ssh -i '$SSH_KEY' -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new root@'$ip' \"set -eu;
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
    ok "AdGuard Home TLS 경로를 자동 등록했습니다: $config"
}

# ------------------------------- 실시간 감시 서비스 -------------------------------
ensure_inotify() {
    local npm=$1
    pct exec "$npm" -- sh -c 'command -v inotifywait >/dev/null 2>&1' ||
        pct exec "$npm" -- apk add --no-cache inotify-tools
}
gen_watch_script() {
    cat > "$1" <<'WATCHEOF'
#!/bin/sh
# adguard-cert-sync watch.sh
# NPM Plus 인증서 디렉터리를 inotify로 실시간 감시하다가 변경이 감지되면
# mappings.conf에 등록된 AdGuard Home 대상으로 즉시 반영합니다.
# certbot이 renew/certonly 어느 쪽으로 갱신하든, custom 인증서를
# 교체하든 파일 변경 자체를 감지하므로 항상 동작합니다.
set -eu

SYNC_DIR=/opt/npmplus/tls/.adguard-sync
MAP_FILE="$SYNC_DIR/mappings.conf"
STATE_DIR="$SYNC_DIR/state"
SSH_KEY=/root/.ssh/id_ed25519_adguard
ADG_CERT_DIR=/etc/adguardhome/certs
LOG=/var/log/npmplus-adguard-deploy.log
WATCH_A=/opt/npmplus/tls/certbot/live
WATCH_B=/opt/npmplus/tls/custom

mkdir -p "$STATE_DIR" "$WATCH_A" "$WATCH_B"
touch "$MAP_FILE"

log() { printf '%s | %s\n' "$(date '+%F %T')" "$*" >> "$LOG"; }

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        busybox sha256sum "$1" | awk '{print $1}'
    fi
}
state_key() { printf '%s' "$1" | tr '/ ' '__'; }

do_push() {
    src=$1; ip=$2
    scp -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -q \
        "$src/fullchain.pem" root@"$ip":"$ADG_CERT_DIR"/fullchain.pem.tmp 2>>"$LOG" || return 1
    scp -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -q \
        "$src/privkey.pem" root@"$ip":"$ADG_CERT_DIR"/privkey.pem.tmp 2>>"$LOG" || return 1
    ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new root@"$ip" "set -eu;
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
        fi" 2>>"$LOG" || return 1
    return 0
}

push_if_changed() {
    src=$1; ctid=$2; ip=$3; label=$4; force=$5
    if [ ! -f "$src/fullchain.pem" ] || [ ! -f "$src/privkey.pem" ]; then
        log "[WARN] $label: 소스 인증서 파일을 찾을 수 없습니다 ($src)"
        return 1
    fi
    newd="$(hash_file "$src/fullchain.pem")"
    sf="$STATE_DIR/$(state_key "$label").digest"
    oldd=""
    [ -f "$sf" ] && oldd="$(cat "$sf")"
    if [ "$force" != "1" ] && [ "$newd" = "$oldd" ]; then
        return 0
    fi
    log "[SYNC] $label 변경 감지, AdGuard $ip 로 반영 시도"
    if do_push "$src" "$ip"; then
        printf '%s' "$newd" > "$sf"
        log "[OK] $label -> $ip 반영 완료"
    else
        log "[FAIL] $label -> $ip 반영 실패 (다음 감지 시 재시도)"
        return 1
    fi
}

reconcile() {
    force=$1
    [ -s "$MAP_FILE" ] || return 0
    while IFS='|' read -r src ctid ip label; do
        case "$src" in ''|'#'*) continue;; esac
        push_if_changed "$src" "$ctid" "$ip" "$label" "$force" || true
    done < "$MAP_FILE"
}

case "${1:-}" in
    --once)
        reconcile 1
        ;;
    *)
        log "[START] adguard-cert-sync 감시 서비스 시작"
        reconcile 0
        while true; do
            inotifywait -q -t 21600 -r -e close_write,moved_to,create,delete \
                --format '%w%f' "$WATCH_A" "$WATCH_B" >/dev/null 2>>"$LOG" || true
            # fullchain/privkey가 연달아 쓰여지는 순간을 흡수하기 위해 짧게 한번 더 흘려보냅니다.
            while inotifywait -q -t 2 -r -e close_write,moved_to,create,delete \
                --format '%w%f' "$WATCH_A" "$WATCH_B" >/dev/null 2>>"$LOG"; do :; done
            reconcile 0
        done
        ;;
esac
WATCHEOF
    chmod 644 "$1"
}
gen_service_file() {
    cat > "$1" <<'SVCEOF'
#!/sbin/openrc-run
name="adguard-cert-sync"
description="NPM Plus -> AdGuard Home 인증서 실시간 동기화 (inotify)"
command="/opt/npmplus/tls/.adguard-sync/watch.sh"
command_background="yes"
pidfile="/run/${RC_SVCNAME}.pid"

depend() {
    need net
    after firewall
}
SVCEOF
    chmod 644 "$1"
}
deploy_watcher() {
    local npm=$1 tmp
    info "inotify-tools 설치 확인..."
    ensure_inotify "$npm"
    tmp="$(mktemp -d)"
    gen_watch_script "$tmp/watch.sh"
    gen_service_file "$tmp/adguard-cert-sync"
    pct exec "$npm" -- mkdir -p "$SYNC_DIR/state"
    pct push "$npm" "$tmp/watch.sh" "$SYNC_DIR/watch.sh"
    pct exec "$npm" -- chmod 700 "$SYNC_DIR/watch.sh"
    pct push "$npm" "$tmp/adguard-cert-sync" /etc/init.d/adguard-cert-sync
    pct exec "$npm" -- chmod 755 /etc/init.d/adguard-cert-sync
    pct exec "$npm" -- touch "$MAP_FILE_REMOTE"
    pct exec "$npm" -- rc-update add adguard-cert-sync default >/dev/null 2>&1 || true
    if pct exec "$npm" -- rc-service adguard-cert-sync status >/dev/null 2>&1; then
        pct exec "$npm" -- rc-service adguard-cert-sync restart
    else
        pct exec "$npm" -- rc-service adguard-cert-sync start
    fi
    pct exec "$npm" -- rc-service adguard-cert-sync status >/dev/null ||
        die "adguard-cert-sync 서비스를 시작하지 못했습니다. LXC $npm 에서 'rc-service adguard-cert-sync start'를 확인하세요."
    rm -rf "$tmp"
}
add_mapping() {
    # 같은 인증서(src)를 여러 AdGuard(ctid)에 연결 가능
    # 고유 키: src|ctid|
    local npm=$1 src=$2 ctid=$3 ip=$4 label=$5
    local esrc ectid eip elabel
    esrc=$(sq_escape "$src")
    ectid=$(sq_escape "$ctid")
    eip=$(sq_escape "$ip")
    elabel=$(sq_escape "$label")
    pct exec "$npm" -- sh -c "
        touch '$MAP_FILE_REMOTE'
        grep -vF '$esrc|$ectid|' '$MAP_FILE_REMOTE' > '$MAP_FILE_REMOTE.new' 2>/dev/null || true
        printf '%s|%s|%s|%s\n' '$esrc' '$ectid' '$eip' '$elabel' >> '$MAP_FILE_REMOTE.new'
        mv '$MAP_FILE_REMOTE.new' '$MAP_FILE_REMOTE'
    "
}

# ------------------------------- 매핑 목록 -------------------------------
MAP_LINES=""
fetch_mappings() {
    pct exec "$1" -- sh -c "cat '$MAP_FILE_REMOTE' 2>/dev/null || true"
}
# 성공 시 MAP_LINES 채움, 0 반환. 없으면 1 반환.
list_mappings_menu() {
    local npm=$1 i=0 src ctid ip label
    MAP_LINES="$(fetch_mappings "$npm")"
    [[ -n $MAP_LINES ]] || { info "등록된 연동이 없습니다."; return 1; }
    while IFS='|' read -r src ctid ip label; do
        [[ -n $src ]] || continue
        i=$((i + 1))
        printf '%2d) %s\n' "$i" "$label"
        printf '     원본 경로: %s\n' "$src"
        printf '     대상: AdGuard LXC %s (%s)\n' "$ctid" "$ip"
    done <<< "$MAP_LINES"
    return 0
}

# ------------------------------- 메인 동작 -------------------------------
install() {
    local npm adg tls_mode answer existing ip label
    section "연결 정보 입력"
    read -rp "NPM Plus LXC 번호: " npm; check_ct "$npm"
    read -rp "AdGuard Home LXC 번호: " adg; check_ct "$adg"

    pick_cert "$npm" || return 1

    section "선택한 연결 정보"
    field "NPM Plus LXC" "$npm"
    field "AdGuard Home LXC" "$adg"
    if [[ $PICK_TYPE == certbot ]]; then field "인증서 종류" "Let's Encrypt (자동 갱신)"; else field "인증서 종류" "Custom"; fi
    field "인증서" "npm-$PICK_NUM ($PICK_DOMAIN)"
    field "원본 경로" "$PICK_PATH"

    # 같은 인증서+같은 AdGuard만 중복으로 취급 (다른 AdGuard로의 연동은 허용)
    existing="$(pct exec "$npm" -- sh -c "grep -F '$PICK_PATH|$adg|' '$MAP_FILE_REMOTE' 2>/dev/null || true")"
    if [[ -n $existing ]]; then
        info "이미 이 인증서→AdGuard LXC $adg 연동이 등록되어 있습니다: $existing"
        read -rp "덮어쓸까요? (Y/N): " answer
        [[ $answer =~ ^[Yy]$ ]] || { info "설치를 취소했습니다."; return 0; }
    fi
    other="$(pct exec "$npm" -- sh -c "grep -F '$PICK_PATH|' '$MAP_FILE_REMOTE' 2>/dev/null | grep -vF '$PICK_PATH|$adg|' || true")"
    if [[ -n $other ]]; then
        info "같은 인증서가 다른 AdGuard에도 연결되어 있습니다 (병행 가능):"
        printf '%s\n' "$other" | while IFS= read -r line; do info "  $line"; done
    fi

    section "설치 진행"
    echo "[1/7] AdGuard Home 인증서 디렉터리 생성"
    pct exec "$adg" -- mkdir -p "$ADG_CERT_DIR"
    setup_ssh "$npm" "$adg"
    ip="$(get_ip "$adg")"; field "AdGuard Home IP" "$ip"
    pct exec "$npm" -- sh -c "ssh-keyscan -H '$ip' >> /root/.ssh/known_hosts 2>/dev/null || true"

    echo
    echo "AdGuard Home TLS 인증서 경로 등록"
    echo "  1) 자동 등록 (certificate_chain/private_key 비움, *_path 경로 등록)"
    echo "  2) 수동 등록"
    read -rp "선택 [1-2]: " tls_mode
    case "$tls_mode" in 1|2) ;; *) die "1 또는 2를 선택하세요.";; esac

    echo "[5/7] 최초 인증서 Atomic Copy"
    copy_atomic "$npm" "$PICK_PATH" "$ip"

    if [[ $tls_mode == 1 ]]; then
        register_tls_paths "$adg"
    else
        info "TLS 경로는 수동 등록으로 선택했습니다."
    fi

    echo "[6/7] 실시간 감시 서비스 설치 (inotify, cron/polling 없음)"
    deploy_watcher "$npm"
    if [[ $PICK_TYPE == certbot ]]; then
        label="npm-$PICK_NUM(Let's Encrypt: $PICK_DOMAIN) -> LXC $adg"
    else
        label="npm-$PICK_NUM(Custom: $PICK_DOMAIN) -> LXC $adg"
    fi
    add_mapping "$npm" "$PICK_PATH" "$adg" "$ip" "$label"
    ok "감시 서비스가 실행 중이며 인증서 변경을 실시간으로 감지합니다."

    echo "[7/7] SSH 연결 테스트"
    pct exec "$npm" -- sh -c "ssh -i '$SSH_KEY' -o BatchMode=yes root@'$ip' 'echo SSH_OK'" >/dev/null

    section "설정 완료"
    ok "cron, polling, bind mount 없이 실시간 자동 연동을 설정했습니다."
    field "인증서 경로" "$ADG_CERT_DIR/fullchain.pem"
    field "개인키 경로" "$ADG_CERT_DIR/privkey.pem"
    field "매핑 파일" "$MAP_FILE_REMOTE (LXC $npm 내부)"
    field "감시 서비스" "adguard-cert-sync (LXC $npm 내부, 부팅 시 자동 시작)"
    if [[ $tls_mode == 2 ]]; then
        echo "수동 등록: TLS certificate_chain/private_key는 비우고, certificate_path/private_key_path에 위 경로를 입력하세요."
    fi
    echo "이후 인증서가 갱신되면 수 초 내로 자동 감지되어 AdGuard Home에 반영·reload됩니다."
}

status() {
    local npm src ctid ip label ndig adig
    section "연동 상태 조회"
    read -rp "NPM Plus LXC 번호: " npm; check_ct "$npm"
    echo "감시 서비스 상태:"
    if pct exec "$npm" -- rc-service adguard-cert-sync status >/dev/null 2>&1; then
        printf '  %s실행 중%s (inotify 기반 실시간 감시)\n' "$C_GREEN" "$C_RESET"
    else
        printf '  %s중지됨%s · 메뉴 1) 새 연동 설치로 다시 시작할 수 있습니다.\n' "$C_RED" "$C_RESET"
    fi
    echo
    list_mappings_menu "$npm" || return 0
    echo
    echo "동기화 상태:"
    while IFS='|' read -r src ctid ip label; do
        [[ -n $src ]] || continue
        ndig="$(file_digest "$npm" "$src/fullchain.pem")"
        if [[ $ctid =~ ^[0-9]+$ ]] && pct status "$ctid" >/dev/null 2>&1; then
            adig="$(file_digest "$ctid" "$ADG_CERT_DIR/fullchain.pem")"
        else
            adig="(LXC $ctid 확인 불가)"
        fi
        if [[ $ndig == "$adig" ]]; then
            printf '  %s[일치]%s %s\n' "$C_GREEN" "$C_RESET" "$label"
        else
            printf '  %s[불일치]%s %s · 메뉴 4) 지금 강제 동기화를 실행하세요.\n' "$C_RED" "$C_RESET" "$label"
        fi
    done <<< "$MAP_LINES"
    echo
    echo "최근 로그 (LXC $npm 내부 $LOG_REMOTE):"
    pct exec "$npm" -- sh -c "tail -n 8 '$LOG_REMOTE' 2>/dev/null || echo '  (기록 없음)'"
}

remove_mapping_flow() {
    local npm pick count line sel_src sel_ctid sel_ip sel_label answer remaining
    section "연동 제거"
    read -rp "NPM Plus LXC 번호: " npm; check_ct "$npm"
    list_mappings_menu "$npm" || return 0
    count="$(printf '%s\n' "$MAP_LINES" | grep -c '|' || true)"
    read -rp "제거할 번호: " pick
    [[ $pick =~ ^[0-9]+$ ]] && (( pick >= 1 && pick <= count )) || die "목록에 없는 번호입니다."
    line="$(printf '%s\n' "$MAP_LINES" | sed -n "${pick}p")"
    IFS='|' read -r sel_src sel_ctid sel_ip sel_label <<< "$line"
    echo "삭제 대상: $sel_label"
    read -rp "삭제할까요? (Y/N): " answer
    [[ $answer =~ ^[Yy]$ ]] || { info "취소했습니다."; return 0; }
    local esrc ectid elabel
    esrc=$(sq_escape "$sel_src")
    ectid=$(sq_escape "$sel_ctid")
    elabel=$(sq_escape "$sel_label")
    pct exec "$npm" -- sh -c "
        grep -vF '$esrc|$ectid|' '$MAP_FILE_REMOTE' > '$MAP_FILE_REMOTE.new' 2>/dev/null || true
        mv '$MAP_FILE_REMOTE.new' '$MAP_FILE_REMOTE'
        rm -f \"$SYNC_DIR/state/\$(printf '%s' '$elabel' | tr '/ ' '__').digest\"
    "
    ok "연동을 제거했습니다. (다른 AdGuard 연동은 유지) AdGuard 인증서/SSH Key는 유지됩니다."
    remaining="$(pct exec "$npm" -- sh -c "
        cnt=\$(grep -c '|' '$MAP_FILE_REMOTE' 2>/dev/null || true)
        printf '%s' \"\${cnt:-0}\"
    ")"
    remaining=${remaining:-0}
    if [[ "$remaining" -eq 0 ]]; then
        read -rp "남은 연동이 없습니다. 감시 서비스도 중지할까요? (Y/N): " answer
        if [[ $answer =~ ^[Yy]$ ]]; then
            pct exec "$npm" -- rc-service adguard-cert-sync stop || true
            pct exec "$npm" -- rc-update del adguard-cert-sync default || true
            ok "감시 서비스를 중지했습니다."
        fi
    fi
}

force_sync_flow() {
    local npm pick count line src ctid ip label before after
    section "지금 강제 동기화"
    read -rp "NPM Plus LXC 번호: " npm; check_ct "$npm"
    list_mappings_menu "$npm" || return 0
    count="$(printf '%s\n' "$MAP_LINES" | grep -c '|' || true)"
    read -rp "동기화할 번호: " pick
    [[ $pick =~ ^[0-9]+$ ]] && (( pick >= 1 && pick <= count )) || die "목록에 없는 번호입니다."
    line="$(printf '%s\n' "$MAP_LINES" | sed -n "${pick}p")"
    IFS='|' read -r src ctid ip label <<< "$line"
    section "강제 동기화 실행"
    field "대상" "$label"
    if ! pct exec "$ctid" -- rc-service sshd status >/dev/null 2>&1; then
        die "AdGuard Home SSH 서버(sshd)가 실행 중이 아닙니다. 메뉴 1) 새 연동 설치를 다시 실행하세요."
    fi
    if ! pct exec "$npm" -- rc-service adguard-cert-sync status >/dev/null 2>&1; then
        warn "adguard-cert-sync 감시 서비스가 실행 중이 아닙니다. 강제 동기화만 1회 수행합니다."
    fi
    before="$(file_digest "$ctid" "$ADG_CERT_DIR/fullchain.pem")"
    field "AdGuard 이전 SHA-256" "$before"
    echo
    echo "[실행] $SYNC_DIR/watch.sh --once"
    pct exec "$npm" -- "$SYNC_DIR/watch.sh" --once
    after="$(file_digest "$ctid" "$ADG_CERT_DIR/fullchain.pem")"
    field "AdGuard 이후 SHA-256" "$after"
    src_digest="$(file_digest "$npm" "$src/fullchain.pem")"
    if [[ $src_digest == "$after" ]]; then
        ok "인증서 반영이 정상적으로 완료되었습니다."
    else
        die "인증서 내용이 일치하지 않습니다. 로그($LOG_REMOTE)와 SSH 연결을 확인하세요."
    fi
}

main() {
    local choice
    check_env
    while true; do
        echo; echo "=================================================="
        echo " NPM Plus -> AdGuard Home 인증서 실시간 연동"
        echo "=================================================="
        echo "  1) 새 연동 설치"
        echo "  2) 연동 상태 조회"
        echo "  3) 연동 제거"
        echo "  4) 지금 강제 동기화"
        echo "  5) 종료"
        echo
        read -rp "메뉴 선택 [1-5]: " choice
        case "$choice" in
            1) install || true;;
            2) status || true;;
            3) remove_mapping_flow || true;;
            4) force_sync_flow || true;;
            5) echo "종료합니다."; exit 0;;
            *) echo "[오류] 1부터 5 사이의 번호를 선택하세요.";;
        esac
    done
}
main "$@"
