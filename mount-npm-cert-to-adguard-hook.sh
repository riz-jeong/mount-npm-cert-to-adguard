#!/usr/bin/env bash
set -euo pipefail

# =====================================================================
# NPM Plus -> AdGuard Home 인증서 연동 (Certbot Deploy Hook 버전)
# =====================================================================
# - inotify / cron / polling / bind mount 사용 안 함
# - 추가 패키지 설치 없음 (순정 Alpine)
# - Let's Encrypt 갱신 시 certbot deploy hook으로 즉시 반영
# - Custom 인증서는 최초 1회 복사만 (자동 갱신 트리거 없음)
# - WebUI 수동 갱신 버튼도 certbot이 directory hooks를 실행하면 동작
#   (NPMplus 유지보수자: tls/certbot/renewal-hooks/{deploy,post,pre} 사용)
# =====================================================================

ADG_CERT_DIR=/etc/adguardhome/certs
SSH_KEY=/root/.ssh/id_ed25519_adguard
SYNC_DIR=/opt/npmplus/tls/.adguard-sync
MAP_FILE_REMOTE="$SYNC_DIR/mappings.conf"
LOG_REMOTE=/var/log/npmplus-adguard-deploy.log
HOOK_DIR=/opt/npmplus/tls/certbot/renewal-hooks/deploy
# Hook 파일명: 99-adguard-{NPM_LXC}-{ADG_LXC}-{CERT_NUM}.sh
# 예) 99-adguard-101-102-1.sh
make_hook_name() {
    # $1=npm_lxc $2=adg_lxc $3=cert_num
    printf '99-adguard-%s-%s-%s.sh' "$1" "$2" "$3"
}

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

# 원격 sh -c 단일따옴표 안전 이스케이프
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
        # JSON 배열 → 첫 도메인: ["a.com","b.com"]
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
        echo "  1) Certbot / Let's Encrypt · Deploy Hook으로 자동 반영"
        echo "  2) Custom · 최초 복사만 (자동 없음)"
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
            printf '%2d) [Custom]         npm-%s · %s  (자동 반영 안 됨)\n' "$n" "$num" "$domain"
        fi
    done <<< "$lines"
    echo " 0) 목록에 없음 · 번호 직접 입력"
    read -rp "선택: " pick
    if [[ $pick == 0 ]]; then
        echo "  1) Certbot / Let's Encrypt · Deploy Hook으로 자동 반영"
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
    echo "[2/6] AdGuard Home SSH 서버 확인..."
    if ! pct exec "$adg" -- sh -c 'command -v sshd >/dev/null 2>&1'; then
        info "AdGuard Home에 OpenSSH Server 설치..."
        pct exec "$adg" -- apk add --no-cache openssh
        pct exec "$adg" -- ssh-keygen -A
    fi
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
    echo "[3/6] NPM Plus SSH client 확인..."
    if ! pct exec "$npm" -- sh -c 'command -v ssh >/dev/null 2>&1 && command -v scp >/dev/null 2>&1'; then
        pct exec "$npm" -- apk add --no-cache openssh-client
    fi
    echo "[4/6] NPM Plus -> AdGuard SSH 인증 설정..."
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

# ------------------------------- Deploy Hook 생성 -------------------------------
# 파일명 형식: 99-adguard-{NPM}-{ADG}-{CERT}.sh
# 각 훅은 해당 인증서→AdGuard 한 쌍만 담당 (self-contained)
gen_hook_script() {
    # $1=outfile $2=src_path $3=adg_ip $4=label $5=cert_base(npm-N)
    local outfile=$1 src_path=$2 adg_ip=$3 label=$4 cert_base=$5
    cat > "$outfile" <<HOOKEOF
#!/bin/sh
# Deploy Hook: ${label}
# 파일명 형식: 99-adguard-{NPM_LXC}-{ADG_LXC}-{CERT_NUM}.sh
# certbot 갱신 시 \$RENEWED_LINEAGE 가 이 인증서(npm-N)와 일치하면 AdGuard로 반영
set -eu

SRC_PATH='${src_path}'
CERT_BASE='${cert_base}'
ADG_IP='${adg_ip}'
LABEL='${label}'
SSH_KEY=/root/.ssh/id_ed25519_adguard
ADG_CERT_DIR=/etc/adguardhome/certs
LOG=/var/log/npmplus-adguard-deploy.log

mkdir -p "\$(dirname "\$LOG")"
touch "\$LOG"

log() { printf '%s | %s\n' "\$(date '+%F %T')" "\$*" >> "\$LOG"; }

do_push() {
    src=\$1; ip=\$2
    scp -i "\$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -q \\
        "\$src/fullchain.pem" root@"\$ip":"\$ADG_CERT_DIR"/fullchain.pem.tmp 2>>"\$LOG" || return 1
    scp -i "\$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -q \\
        "\$src/privkey.pem" root@"\$ip":"\$ADG_CERT_DIR"/privkey.pem.tmp 2>>"\$LOG" || return 1
    ssh -i "\$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new root@"\$ip" "set -eu;
        mv '\$ADG_CERT_DIR/fullchain.pem.tmp' '\$ADG_CERT_DIR/fullchain.pem';
        mv '\$ADG_CERT_DIR/privkey.pem.tmp' '\$ADG_CERT_DIR/privkey.pem';
        chmod 644 '\$ADG_CERT_DIR/fullchain.pem';
        chmod 600 '\$ADG_CERT_DIR/privkey.pem';
        if command -v systemctl >/dev/null 2>&1; then
            systemctl reload AdGuardHome 2>/dev/null || systemctl restart AdGuardHome;
        elif [ -x /etc/init.d/adguardhome ]; then
            rc-service adguardhome reload 2>/dev/null || rc-service adguardhome restart;
        elif [ -x /etc/init.d/AdGuardHome ]; then
            rc-service AdGuardHome reload 2>/dev/null || rc-service AdGuardHome restart;
        else
            echo 'AdGuardHome 서비스 관리 명령을 찾을 수 없습니다.' >&2; exit 1;
        fi" 2>>"\$LOG" || return 1
    return 0
}

# 실제 파일 경로 결정 (/data 또는 /opt/npmplus)
resolve_src() {
    if [ -n "\${RENEWED_LINEAGE:-}" ] && [ -f "\${RENEWED_LINEAGE}/fullchain.pem" ]; then
        printf '%s' "\$RENEWED_LINEAGE"
        return
    fi
    if [ -f "\$SRC_PATH/fullchain.pem" ]; then
        printf '%s' "\$SRC_PATH"
        return
    fi
    # /data 경로 fallback
    alt="/data/tls/certbot/live/\$CERT_BASE"
    if [ -f "\$alt/fullchain.pem" ]; then
        printf '%s' "\$alt"
        return
    fi
    printf '%s' "\$SRC_PATH"
}

should_run() {
    # 수동 실행(강제 동기화) → 항상 실행
    if [ -z "\${RENEWED_LINEAGE:-}" ]; then
        return 0
    fi
    # certbot deploy → basename 이 이 훅의 인증서와 같을 때만
    lineage_base=\$(basename "\${RENEWED_LINEAGE%/}")
    [ "\$lineage_base" = "\$CERT_BASE" ]
}

if ! should_run; then
    exit 0
fi

real_src=\$(resolve_src)
if [ ! -f "\$real_src/fullchain.pem" ] || [ ! -f "\$real_src/privkey.pem" ]; then
    log "[WARN] \$LABEL: 소스 인증서 없음 (\$real_src)"
    exit 0
fi

if [ -n "\${RENEWED_LINEAGE:-}" ]; then
    log "[HOOK] certbot deploy: RENEWED_LINEAGE=\$RENEWED_LINEAGE → \$LABEL"
else
    log "[MANUAL] 강제 동기화 → \$LABEL"
fi

log "[SYNC] \$LABEL -> \$ADG_IP 반영 시도 (src=\$real_src)"
if do_push "\$real_src" "\$ADG_IP"; then
    log "[OK] \$LABEL -> \$ADG_IP 반영 완료"
else
    log "[FAIL] \$LABEL -> \$ADG_IP 반영 실패"
    exit 1
fi
HOOKEOF
    chmod 644 "$outfile"
}

deploy_hook() {
    # $1=npm $2=adg $3=cert_num $4=src_path $5=adg_ip $6=label
    local npm=$1 adg=$2 cert_num=$3 src_path=$4 adg_ip=$5 label=$6
    local hook_name hook_path tmp cert_base
    hook_name="$(make_hook_name "$npm" "$adg" "$cert_num")"
    hook_path="$HOOK_DIR/$hook_name"
    cert_base="npm-$cert_num"
    tmp="$(mktemp -d)"
    gen_hook_script "$tmp/$hook_name" "$src_path" "$adg_ip" "$label" "$cert_base"
    pct exec "$npm" -- mkdir -p "$HOOK_DIR" "$SYNC_DIR"
    pct push "$npm" "$tmp/$hook_name" "$hook_path"
    pct exec "$npm" -- chmod 755 "$hook_path"
    pct exec "$npm" -- touch "$MAP_FILE_REMOTE"
    rm -rf "$tmp"
    ok "Deploy Hook 설치됨: $hook_path"
    # 호출측에서 쓸 수 있도록
    HOOK_NAME_OUT=$hook_name
    HOOK_PATH_OUT=$hook_path
}

add_mapping() {
    # 형식: src|ctid|ip|label|hook_name
    # 같은 인증서(src)를 여러 AdGuard(ctid)에 연결 가능 — 고유 키: src|ctid|
    local npm=$1 src=$2 ctid=$3 ip=$4 label=$5 hook_name=$6
    local esrc ectid eip elabel ehook
    esrc=$(sq_escape "$src")
    ectid=$(sq_escape "$ctid")
    eip=$(sq_escape "$ip")
    elabel=$(sq_escape "$label")
    ehook=$(sq_escape "$hook_name")
    pct exec "$npm" -- sh -c "
        touch '$MAP_FILE_REMOTE'
        grep -vF '$esrc|$ectid|' '$MAP_FILE_REMOTE' > '$MAP_FILE_REMOTE.new' 2>/dev/null || true
        printf '%s|%s|%s|%s|%s\n' '$esrc' '$ectid' '$eip' '$elabel' '$ehook' >> '$MAP_FILE_REMOTE.new'
        mv '$MAP_FILE_REMOTE.new' '$MAP_FILE_REMOTE'
    "
}

# ------------------------------- 매핑 목록 -------------------------------
MAP_LINES=""
fetch_mappings() {
    pct exec "$1" -- sh -c "cat '$MAP_FILE_REMOTE' 2>/dev/null || true"
}
list_mappings_menu() {
    local npm=$1 i=0 src ctid ip label hook
    MAP_LINES="$(fetch_mappings "$npm")"
    [[ -n $MAP_LINES ]] || { info "등록된 연동이 없습니다."; return 1; }
    while IFS='|' read -r src ctid ip label hook; do
        [[ -n $src ]] || continue
        i=$((i + 1))
        # 구버전 매핑(hook 필드 없음) 호환
        if [[ -z ${hook:-} ]]; then
            hook="(구버전 훅)"
        fi
        printf '%2d) %s\n' "$i" "$label"
        printf '     원본 경로: %s\n' "$src"
        printf '     대상: AdGuard LXC %s (%s)\n' "$ctid" "$ip"
        printf '     Hook 파일: %s\n' "$hook"
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
    if [[ $PICK_TYPE == certbot ]]; then
        field "인증서 종류" "Let's Encrypt (Deploy Hook 자동 반영)"
    else
        field "인증서 종류" "Custom (최초 1회만, 자동 없음)"
        warn "Custom 인증서는 Deploy Hook이 동작하지 않습니다. 변경 시 메뉴 4) 강제 동기화를 사용하세요."
    fi
    field "인증서" "npm-$PICK_NUM ($PICK_DOMAIN)"
    field "원본 경로" "$PICK_PATH"

    # 같은 인증서+같은 AdGuard만 중복으로 취급 (다른 AdGuard로의 연동은 허용)
    existing="$(pct exec "$npm" -- sh -c "grep -F '$PICK_PATH|$adg|' '$MAP_FILE_REMOTE' 2>/dev/null || true")"
    if [[ -n $existing ]]; then
        info "이미 이 인증서→AdGuard LXC $adg 연동이 등록되어 있습니다: $existing"
        read -rp "덮어쓸까요? (Y/N): " answer
        [[ $answer =~ ^[Yy]$ ]] || { info "설치를 취소했습니다."; return 0; }
        # 덮어쓸 때 기존 hook 파일도 정리 (이름 동일하므로 deploy_hook이 교체)
    fi
    other="$(pct exec "$npm" -- sh -c "grep -F '$PICK_PATH|' '$MAP_FILE_REMOTE' 2>/dev/null | grep -vF '$PICK_PATH|$adg|' || true")"
    if [[ -n $other ]]; then
        info "같은 인증서가 다른 AdGuard에도 연결되어 있습니다 (병행 가능):"
        printf '%s\n' "$other" | while IFS= read -r line; do info "  $line"; done
    fi

    section "설치 진행"
    echo "[1/6] AdGuard Home 인증서 디렉터리 생성"
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

    echo "[5/6] 최초 인증서 Atomic Copy"
    copy_atomic "$npm" "$PICK_PATH" "$ip"

    if [[ $tls_mode == 1 ]]; then
        register_tls_paths "$adg"
    else
        info "TLS 경로는 수동 등록으로 선택했습니다."
    fi

    echo "[6/6] Certbot Deploy Hook 설치 (추가 패키지 없음)"
    if [[ $PICK_TYPE == certbot ]]; then
        label="npm-$PICK_NUM(Let's Encrypt: $PICK_DOMAIN) -> LXC $adg"
    else
        label="npm-$PICK_NUM(Custom: $PICK_DOMAIN) -> LXC $adg"
    fi
    deploy_hook "$npm" "$adg" "$PICK_NUM" "$PICK_PATH" "$ip" "$label"
    add_mapping "$npm" "$PICK_PATH" "$adg" "$ip" "$label" "${HOOK_NAME_OUT}"
    ok "매핑 등록 및 Deploy Hook 준비 완료."

    echo
    echo "[테스트] SSH 연결"
    pct exec "$npm" -- sh -c "ssh -i '$SSH_KEY' -o BatchMode=yes root@'$ip' 'echo SSH_OK'" >/dev/null

    section "설정 완료"
    ok "Deploy Hook 방식으로 연동을 설정했습니다. (inotify/cron/polling 없음)"
    field "인증서 경로" "$ADG_CERT_DIR/fullchain.pem"
    field "개인키 경로" "$ADG_CERT_DIR/privkey.pem"
    field "매핑 파일" "$MAP_FILE_REMOTE (LXC $npm 내부)"
    field "Deploy Hook" "${HOOK_PATH_OUT} (LXC $npm 내부)"
    if [[ $tls_mode == 2 ]]; then
        echo "수동 등록: TLS certificate_chain/private_key는 비우고, certificate_path/private_key_path에 위 경로를 입력하세요."
    fi
    echo
    echo "동작 방식:"
    echo "  - Let's Encrypt 자동/수동 갱신 시 certbot이 Deploy Hook을 실행 → AdGuard에 즉시 반영"
    echo "  - WebUI 갱신 버튼: NPMplus가 directory hooks를 실행하면 동작 (유지보수자 확인됨)"
    echo "  - Custom 인증서 변경 시: 메뉴 4) 지금 강제 동기화 사용"
    echo "  - 로그: LXC $npm 의 $LOG_REMOTE"
    echo "  - Hook 파일명 형식: 99-adguard-{NPM}-{ADG}-{CERT}.sh"
}

status() {
    local npm src ctid ip label hook ndig adig
    section "연동 상태 조회"
    read -rp "NPM Plus LXC 번호: " npm; check_ct "$npm"

    echo "Deploy Hook 파일:"
    list_mappings_menu "$npm" || return 0
    echo
    echo "동기화 상태:"
    while IFS='|' read -r src ctid ip label hook; do
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
        if [[ -n ${hook:-} && $hook != "(구버전 훅)" ]]; then
            if pct exec "$npm" -- test -x "$HOOK_DIR/$hook" 2>/dev/null; then
                printf '     Hook: %s%s%s\n' "$C_GREEN" "$hook" "$C_RESET"
            else
                printf '     Hook: %s%s (없음)%s\n' "$C_RED" "$hook" "$C_RESET"
            fi
        fi
    done <<< "$MAP_LINES"
    echo
    echo "최근 로그 (LXC $npm 내부 $LOG_REMOTE):"
    pct exec "$npm" -- sh -c "tail -n 10 '$LOG_REMOTE' 2>/dev/null || echo '  (기록 없음)'"
}

remove_mapping_flow() {
    local npm pick count line sel_src sel_ctid sel_ip sel_label sel_hook answer
    section "연동 제거"
    read -rp "NPM Plus LXC 번호: " npm; check_ct "$npm"
    list_mappings_menu "$npm" || return 0
    count="$(printf '%s\n' "$MAP_LINES" | grep -c '|' || true)"
    read -rp "제거할 번호: " pick
    [[ $pick =~ ^[0-9]+$ ]] && (( pick >= 1 && pick <= count )) || die "목록에 없는 번호입니다."
    line="$(printf '%s\n' "$MAP_LINES" | sed -n "${pick}p")"
    IFS='|' read -r sel_src sel_ctid sel_ip sel_label sel_hook <<< "$line"
    echo "삭제 대상: $sel_label"
    [[ -n ${sel_hook:-} ]] && echo "Hook 파일: $sel_hook"
    read -rp "삭제할까요? (Y/N): " answer
    [[ $answer =~ ^[Yy]$ ]] || { info "취소했습니다."; return 0; }
    local esrc ectid
    esrc=$(sq_escape "$sel_src")
    ectid=$(sq_escape "$sel_ctid")
    pct exec "$npm" -- sh -c "
        grep -vF '$esrc|$ectid|' '$MAP_FILE_REMOTE' > '$MAP_FILE_REMOTE.new' 2>/dev/null || true
        mv '$MAP_FILE_REMOTE.new' '$MAP_FILE_REMOTE'
    "
    if [[ -n ${sel_hook:-} && $sel_hook != "(구버전 훅)" ]]; then
        pct exec "$npm" -- rm -f "$HOOK_DIR/$sel_hook" || true
        ok "연동 및 Hook 파일($sel_hook)을 제거했습니다. (다른 AdGuard 연동은 유지)"
    else
        ok "연동을 제거했습니다. (다른 AdGuard 연동은 유지)"
    fi
}

force_sync_flow() {
    local npm pick count line src ctid ip label hook before after hook_path
    section "지금 강제 동기화"
    read -rp "NPM Plus LXC 번호: " npm; check_ct "$npm"
    list_mappings_menu "$npm" || return 0
    count="$(printf '%s\n' "$MAP_LINES" | grep -c '|' || true)"
    read -rp "동기화할 번호 (전체는 0): " pick
    if [[ $pick == 0 ]]; then
        section "전체 강제 동기화"
        while IFS='|' read -r src ctid ip label hook; do
            [[ -n $src ]] || continue
            if [[ -z ${hook:-} || $hook == "(구버전 훅)" ]]; then
                warn "구버전 매핑 스킵: $label"
                continue
            fi
            hook_path="$HOOK_DIR/$hook"
            if pct exec "$npm" -- test -x "$hook_path" 2>/dev/null; then
                info "실행: $hook"
                pct exec "$npm" -- "$hook_path" || warn "실패: $hook"
            else
                warn "Hook 없음: $hook"
            fi
        done <<< "$MAP_LINES"
        ok "전체 매핑에 대해 강제 동기화를 실행했습니다. 로그를 확인하세요."
        return 0
    fi
    [[ $pick =~ ^[0-9]+$ ]] && (( pick >= 1 && pick <= count )) || die "목록에 없는 번호입니다."
    line="$(printf '%s\n' "$MAP_LINES" | sed -n "${pick}p")"
    IFS='|' read -r src ctid ip label hook <<< "$line"
    section "강제 동기화 실행"
    field "대상" "$label"
    [[ -n ${hook:-} ]] && field "Hook" "$hook"
    if [[ -z ${hook:-} || $hook == "(구버전 훅)" ]]; then
        die "이 매핑에 Hook 파일이 없습니다. 메뉴 1)로 다시 설치하세요."
    fi
    hook_path="$HOOK_DIR/$hook"
    if ! pct exec "$npm" -- test -x "$hook_path" 2>/dev/null; then
        die "Hook 파일이 없습니다: $hook_path"
    fi
    if ! pct exec "$ctid" -- rc-service sshd status >/dev/null 2>&1; then
        die "AdGuard Home SSH 서버(sshd)가 실행 중이 아닙니다. 메뉴 1) 새 연동 설치를 다시 실행하세요."
    fi
    before="$(file_digest "$ctid" "$ADG_CERT_DIR/fullchain.pem")"
    field "AdGuard 이전 SHA-256" "$before"
    echo
    # 수동 실행 (RENEWED_LINEAGE 없이) → 해당 훅이 바로 push
    pct exec "$npm" -- "$hook_path"
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
        echo " NPM Plus -> AdGuard Home 인증서 연동"
        echo " (Certbot Deploy Hook 버전)"
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
