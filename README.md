# NPM Plus → AdGuard Home 인증서 연동

Proxmox LXC 환경에서 **NPM Plus** 인증서를 **AdGuard Home**에 자동 반영합니다.

- bind mount / cron / 원격 polling 없음
- Proxmox Host에서 `pct`로 실행
- 같은 인증서를 **여러 AdGuard**에 동시에 연결 가능

---

## 버전 선택

| | **inotify 버전** | **Hook 버전** |
|---|---|---|
| 동작 방식 | 파일 변경 실시간 감시 | Certbot Deploy Hook |
| 추가 패키지 | `inotify-tools` 필요 | **없음 (순정)** |
| Let's Encrypt | ✅ 자동 | ✅ 자동 |
| Custom 인증서 | ✅ 자동 감지 | ❌ 최초 1회 + 강제 동기화 |
| WebUI 갱신 버튼 | ✅ | ⚠️ NPMplus가 directory hooks를 호출하면 동작 |
| 권장 상황 | Custom도 자주 바꾸는 경우 | LE만 쓰고 패키지 추가를 피하고 싶은 경우 |

두 버전은 **동시에 사용해도** 서로 파일을 지우지 않습니다.

---

## 실행 방법

Proxmox **Host root**에서 실행합니다.

### inotify 버전

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/riz-jeong/mount-npm-cert-to-adguard/refs/heads/main/mount-npm-cert-to-adguard.sh)
```

### Hook 버전

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/riz-jeong/mount-npm-cert-to-adguard/refs/heads/main/mount-npm-cert-to-adguard-hook.sh)
```

---

## 메뉴

```
1) 새 연동 설치
2) 연동 상태 조회
3) 연동 제거
4) 지금 강제 동기화
5) 종료
```

### 1) 새 연동 설치

1. NPM Plus LXC 번호, AdGuard Home LXC 번호 입력
2. 인증서 선택 (Let's Encrypt / Custom)
3. AdGuard TLS 경로 자동 또는 수동 등록
4. 최초 인증서 복사 + (버전에 따라) 감시 서비스 또는 Deploy Hook 설치

**같은 인증서 → 다른 AdGuard** 로 여러 번 설치할 수 있습니다.  
같은 인증서+같은 AdGuard만 중복으로 취급합니다.

### 2) 연동 상태 조회

- 매핑 목록, 인증서 SHA-256 일치 여부, 최근 로그

### 3) 연동 제거

- 선택한 매핑만 제거 (다른 AdGuard 연동은 유지)
- Hook 버전: 해당 Hook 파일도 삭제
- inotify 버전: 남은 매핑이 없으면 감시 서비스 중지 여부 확인

### 4) 지금 강제 동기화

- 선택한 연동(또는 전체)을 즉시 한 번 반영

---

## 경로·파일

| 항목 | 경로 |
|------|------|
| AdGuard 인증서 | `/etc/adguardhome/certs/fullchain.pem` |
| AdGuard 개인키 | `/etc/adguardhome/certs/privkey.pem` |
| 매핑 파일 | `/opt/npmplus/tls/.adguard-sync/mappings.conf` (NPM LXC 내부) |
| 로그 | `/var/log/npmplus-adguard-deploy.log` (NPM LXC 내부) |
| SSH 키 | `/root/.ssh/id_ed25519_adguard` (NPM → AdGuard) |

### Hook 버전 추가

| 항목 | 내용 |
|------|------|
| Hook 디렉터리 | `/opt/npmplus/tls/certbot/renewal-hooks/deploy/` |
| Hook 파일명 | `99-adguard-{NPM}-{ADG}-{CERT}.sh` |
| 예시 | NPM 101, AdGuard 102, 인증서 1 → `99-adguard-101-102-1.sh` |

### inotify 버전 추가

| 항목 | 내용 |
|------|------|
| 감시 서비스 | `adguard-cert-sync` (OpenRC, 부팅 시 자동 시작) |
| 감시 스크립트 | `/opt/npmplus/tls/.adguard-sync/watch.sh` |
| 상태 digest | `/opt/npmplus/tls/.adguard-sync/state/` |

---

## 동작 요약

### inotify

1. `certbot/live`, `custom` 디렉터리를 inotify로 감시
2. `fullchain.pem` / `privkey.pem` 변경 감지
3. 매핑된 모든 AdGuard로 atomic scp → reload

### Hook

1. Certbot이 인증서 발급/갱신 성공 시 Deploy Hook 실행
2. `$RENEWED_LINEAGE` basename(`npm-N`)이 이 Hook의 인증서와 일치하면 반영
3. `/data` 또는 `/opt/npmplus` 경로 모두 처리

---

## inotify 완전 제거

```bash
# NPM LXC 번호에 맞게 수정 (예: 101)
pct exec 101 -- rc-service adguard-cert-sync stop
pct exec 101 -- rc-update del adguard-cert-sync default
pct exec 101 -- rm -f /etc/init.d/adguard-cert-sync
pct exec 101 -- rm -rf /opt/npmplus/tls/.adguard-sync
pct exec 101 -- apk del inotify-tools   # 선택
pct exec 101 -- rm -f /var/log/npmplus-adguard-deploy.log   # 선택
```

AdGuard 쪽 인증서·SSH 키·`AdGuardHome.yaml` TLS 경로는 그대로 둡니다.

---

## 요구 사항

- Proxmox VE Host (root, `pct` 사용)
- NPM Plus LXC, AdGuard Home LXC
- AdGuard에 SSH(sshd) 사용 가능 (없으면 설치 과정에서 자동 설치)

---

## 참고

- NPM LXC에 `openssl`이 없어도 Host openssl / NPM DB로 도메인 표시를 시도합니다.
- Hook 버전에서 WebUI 수동 갱신이 안 되면 메뉴 4) 강제 동기화 또는 자동 갱신(백그라운드)을 사용하세요.
- 매핑 고유 키: `인증서경로|AdGuard_LXC` → 같은 인증서를 여러 AdGuard에 연결 가능
