# Approved One-Time Linux Capture E2E

검증 환경: **WSL2 Ubuntu**, 2026-10-15.
기준 HEAD: `d3d27a0a92c2cbf86feadbdfad398172981d1343`, branch `main`.

**최종 판정: BLOCKED — 비대화형 sudo 사전 점검이 PASSWORD_REQUIRED로 실패했다.**
사용자의 중단 조건에 따라 재시도, 비밀번호 요청, 다른 권한 경로를 사용하지 않았다.
권한이 부여된 Capture Probe 시작 **0회**, 검증용 트래픽 전송 **0건**이다.
실제 패킷 E2E를 Fixture로 대체해 성공 처리하지 않았다.

기계 판독 기록: [실행 근거 JSON](native-capture-real-e2e-evidence.json).
이 기록은 이번 시도의 결과이며 권한 토큰이나 Collector attestation이 아니다.

## 1. 사용자 승인 범위 / 무결성

승인은 `lo`, UID/GID 1000의 별도 제한 Probe, 임시 CAP_NET_RAW만 해당한다.
1회당 최대 5초·128패킷, 최대 2회, 소유한 loopback UDP/TCP 소켓의 소량 테스트 트래픽만 허용된다.
SOC 전체 root 실행, 영구 file capability, Firewall/NIC/DNS/라우팅 변경은 승인 범위에 없다.

Git status/HEAD/log/diff/cached diff와 AGENTS.md를 먼저 읽었다. HEAD는 기준값과 일치했고
Index는 비어 있었다. 기존 수정 8개와 모든 미추적 파일은 보존하며 Replay 코드를 Stage하지 않는다.
시작 파일 **1,012개**의 SHA를 `/tmp/soc-approved-capture-baseline.json`에 기록했다.

기존 `native_probe.py` SHA256은 승인 기준값과 정확히 같다.

```text
59b67d8a7654eebbb7f05e3810b3d3e2da0aea5029872a09ca01ed1e9a12a50d
```

Probe, permissions, capture, pipeline, network_cli와 이전 parity 보고서를 확인했다.
**운영 코드·Probe·의존성·Artifact는 수정하지 않았다.** 같은 승인 아래 다른 Probe를 실행하지 않는다.

## 2. Privilege Preflight / 실제 실행

| 항목 | 실제 관측 |
|---|---|
| Real / Effective UID | 1000 / 1000; OS 계정 레코드와 일치 |
| Real / Effective GID | 1000 / 1000; OS 그룹 레코드와 일치 |
| Effective / Permitted / Inheritable / Ambient | 모두 `0` |
| Bounding Set | `2199023255551`; 이것만으로 Effective CAP_NET_RAW가 생기지 않음 |
| NoNewPrivs | `0`; 변경하지 않음 |
| lo identity | 시작/중단 후 동일; namespace/boot/ifindex/MAC 기반 digest |
| Python | 3.12.14; 실행 symlink의 실제 target SHA를 기록 |
| Python SHA256 | `fa67443527ed9647f760d807e2a38f26340757123e643c4639cf273ed15d5ea7` |
| setpriv | `/usr/bin/setpriv`, util-linux 2.39.3, root 소유 0755 |
| Python / setpriv / Probe file capability | 현재 xattr 조회에서 모두 ABSENT |
| sudo 사전 점검 | **1회**, exit **1**, PASSWORD_REQUIRED |

실제로 수행한 sudo 명령은 다음 하나다. stdin은 DEVNULL, timeout은 10초였으며
실제 경과 시간은 약 **0.018156초**였다. 이는 Capture 시간이 아니다.

```bash
/usr/bin/sudo -n -v
```

stderr 원문은 사용자명/호스트 식별자 노출을 피하기 위해 보고서에 싣지 않고 고정 실패 코드와
SHA만 기록했다. 비밀번호 입력이나 sudo 반복 시도는 하지 않았다.
`sudo -n setpriv ...`는 **실행하지 않았다**. 명령별 NOPASSWD 허용 여부도 별도로 조회하지 않았다.
따라서 모든 sudo 명령의 불가능을 입증한 것이 아니라, 사용자가 지정한 **비대화형 실패 시 중단**
조건이 성립하여 Capture 실행을 중단한 것이다.

기존 diagnose를 사용하는 신규 읽기 전용 확인에서도 `lo`의 AF_PACKET 생성은
PERMISSION_DENIED였다. 여기서는 raw socket이 열리지 않았으며 Packet 수신은 수행하지 않았다.

## 3. Restricted Process 조건

| 조건 | 정적/Fixture 확인 | 이번 실제 권한 실행 |
|---|---|---|
| 고정 lo 입력 | 기존 Probe에서 확인 | 미실행 |
| Root/추가 capability 거부 | 기존 permission 테스트 재사용 | 미실행 |
| 자식 UID/GID 1000 | 부모 OS 신원 확인; setpriv 인자는 미실행 | 미검증 |
| 승인 제한 5초 | 실행 시 `--seconds 5` 이하 필요 | 실제 Capture 시간 없음 |
| 최대 128패킷 | 기존 Packet budget 테스트 재사용 | 미검증 |
| Socket 생성 후 capset/재조회 | 기존 ABI/실패 시 close 테스트 재사용 | CAP_NET_RAW 보유→제거 전환 미검증 |
| Interface 재검증 | bind 전후 교체 거부 테스트 재사용 | 실제 bind 미실행 |
| Socket 종료/flush | Fixture 저장·종료·복구 테스트 재사용 | 실제 Socket 미생성 |
| 중복 Probe 실행 | 이번 권한 Probe 자체 0회 | 실제 경합 미검증 |

기존 Probe의 일반 인자 범위는 1~10초지만 이번 승인은 최대 5초만 허용한다.
승인이 있다고 일반 한도를 확장해서 사용하지 않았다. Probe 자체의 공용 실행 lock,
외부 READY handshake, 종료 후 영속 DB 전달은 기존 계약에 없다.
코드를 바꾸지 않은 상태에서 이 기능들이 존재한다고 가정하지 않는다.

## 4. Real Packet E2E / 수치

| 지표·단계 | 이번 실제 결과 |
|---|---|
| sudo preflight 시도 | 1회 |
| CAP_NET_RAW가 부여된 Probe 실행 | **0 / 최대 2회** |
| Capture 시간 | **N/A — 시작 안 됨** |
| Kernel packet / Network Flow / DNS Event count | **UNKNOWN / 미측정** |
| Controlled loopback traffic | **0건** |
| Kernel timestamp / IPv4·IPv6 / UDP·TCP | 실제 수집 미검증 |
| Source/Destination / Length / Event Digest | 실제 수집 미검증 |
| Queue / Source Store / Provenance / Audit | 실제 Packet 경로 미실행 |
| 실제 DNS query/response | 미검증; DNS 형식 메시지도 전송하지 않음 |
| Capture drop / gap | **UNKNOWN**; 0으로 대체하지 않음 |
| 실제 수집 후 restart/dedup/recovery | 미실행 |

관측한 패킷이 0개라는 측정 결과가 아니라 **수집을 시작하지 못한 것**이다.
Fixture 패킷과 실제 패킷을 섞어 집계하지 않는다. 학습 Golden Pair도 생성하지 않았다.

## 5. Recovery / 기존 Probe의 한계

실제 Packet을 저장한 Queue/SourceStore가 없으므로 실제 데이터의 종료 후 복구는 미검증이다.
기존 Probe는 private TemporaryDirectory 안에서 저장/재조회를 한 뒤 DB를 정리한다.
함수 안의 저장소 재구성을 **프로세스 종료 후 영속 복구**로 표시해서는 안 된다.
현재 승인에서는 Probe를 수정하지 않았으며 다른 수집기나 저장 계약으로 대체하지 않았다.

기존 Fixture Recovery 테스트는 owned-child Crash 5지점, Source/Queue/Audit 재처리,
중복 저장·집계 방지, SQLite 실패/Backpressure, Digest/Incident/Flow 변조 거부를 검증한다.
이는 실제 raw socket 수집 Crash의 증거가 아니다. Raw capture에는 journal cursor/replay가 없고
재시작 Gap을 명시해야 한다. Exactly-Once 네트워크 수집을 주장하지 않는다.

## 6. 보안 경계 / 변경 범위

- 일반 사용자 Python 실행 환경의 UID/GID 및 capability snapshot은 사전/사후 동일하다.
  Effective/Permitted 등은 0이며 상시 SOC Runtime에 권한을 부여하는 명령을 실행하지 않았다.
- Python/Probe에 file capability를 설정하지 않았다. setcap/setuid/sudoers 수정은 수행하지 않았다.
- Firewall, DNS, NIC, 라우팅, 서비스 설정을 변경하는 명령을 실행하지 않았다.
- Capture용 외부 트래픽·로컬 트래픽 모두 전송하지 않았다. Git fetch/push는 별도로 승인된
  소스 게시 작업이며 네트워크 테스트 트래픽으로 집계하지 않는다.
- 실패한 sudo 인증 시도가 OS 자체 감사 로그에 기록될 가능성과 보안 설정 변경은 구분한다.
  시스템 전체 파일 변경이 0이었다고 주장하지 않는다.
- Native AI/LLM 추론을 자동 실행하지 않았다. WRITE_DENIED, Policy/Approval 계약을 유지한다.
- Network Quality / Edge / DNS의 producer revision/config/Golden Pair는 여전히 미확보다.
  각 모델 운영 추론 **NOT_INFERABLE**, Finding promotion **BLOCKED**다.

## 7. Tests / 실제 Preflight와 Fixture 구분

신규 `tests/approved_native_capture_checks.py`는 명시 실행 전용으로, 승인 Source SHA,
실제 UID/GID/무권한 상태, 실제 permission denial·UNKNOWN drop·닫힌 Gate를 확인한다.
sudo, setpriv 권한 전환, 트래픽 생성, 모델 호출을 수행하지 않는다.

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest --import-mode=importlib -q \
  tests/approved_native_capture_checks.py

RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest --import-mode=importlib -q \
  tests/unit/network_capture tests/integration/network_monitor \
  tests/unit/operational_features tests/unit/security_ai/external \
  tests/unit/external_context tests/unit/gui tests/integration/gui
```

- 실제 Source/신원/권한 거부 확인: **3 passed, 0 failed, 0.26s**.
- Capture/Source/Provenance/GUI/Security 회귀: **411 passed, 0 failed, 51.46s**.
  이 중 Packet 성공·Drop·Timeout·복구 테스트는 **Fixture 기반**이다.
  무권한 CLI 입구 거부 테스트는 권한 Capture Probe 실행과 별도로 구분한다.
- 별도 Runtime/Scenario/Approval 회귀: **248 passed, 0 failed, 86.74s**.
  범위는 `tests/integration/linux_runtime`, `scenario`, `external_read_only_backend`,
  `tests/unit/approval`, `execution`이다. 실제 LLM 호출은 비활성이다.
- 독립 Git Export: 기준 HEAD archive에 이번 3파일만 복사했다. Source/권한 확인 3개를 포함한
  집중 회귀 **404 passed, 0 failed, 54.10s**, 별도 Runtime/보안 회귀
  **248 passed, 0 failed, 97.16s**다. 404는 작업 트리의 411개에서 기존 사용자 미추적
  `test_producer_parity_boundary.py` 10개를 제외하고 신규 확인 3개를 더한 실행이다.
  미커밋 Replay/사용자 코드에 의존하여 통과한 결과가 아니다.
- 로그: `/tmp/soc-approved-capture-{identity-tests,regression,runtime}.log`,
  `/tmp/soc-approved-capture-export-{tests,runtime}.log`.
- Ruff src/tests **PASS**, format 전체 **873 files PASS**, git diff --check **PASS**.
  신규 테스트의 초기 format 불일치만 해당 파일에 formatter를 적용해 수정했다.
- 기존 **1,012개 파일 SHA 일치**, 승인 Probe SHA 일치, Stage 전 Index 비어 있음을 재확인했다.

Fixture 성공으로 실제 Capture의 BLOCKED를 덮어쓰지 않는다. 테스트 수는 실행별로 보고하고
겹치는 실행 수치를 합산하지 않는다. 실제 Native AI·Real LLM 검증은 이번 실행에 포함하지 않는다.

## 8. 남은 Blocker / 후속 조건

1. **이번 비대화형 sudo 사전 점검 실패**가 직접 차단 사유다. 재시도·비밀번호 요청·sudoers
   수정·파일 capability 설정으로 우회하지 않는다. 권한 공급은 운영자가 별도 검토할 사항이다.
2. Source SHA가 같은 Probe만 이번 승인 대상이다. READY/단일 실행/영속 DB 전달 등 보완이
   필요하면 변경 Source와 영향 범위를 검토하고 새 승인을 받아야 한다.
3. 권한을 확보하더라도 실제 Packet/Drop/자식 UID·capability 축소와 저장·복구가 확인되기 전에는
   VERIFIED가 아니다. 이번에 쓰지 않은 2회를 자동 반복/예약 실행하지 않는다.
4. 실제 DNS 서비스 질의, eth0/물리 NIC, 물리 Linux 서버는 이번에 검증하지 않았다.
5. 실제 Capture 성공 후에도 학습 Producer/Golden Pair 미확보 모델은 NOT_INFERABLE이다.

## 9. 이번 파일

- `tests/approved_native_capture_checks.py`
- `docs/linux-soc-v1/native-capture-real-e2e.md`
- `docs/linux-soc-v1/native-capture-real-e2e-evidence.json`

운영 코드와 승인된 Probe를 변경하지 않는다. 이번 3파일만 HEAD archive에 적용하여 독립
재현성을 확인한 뒤 사용자 지시의 BLOCKED 감사 결과를 선별 커밋·푸시한다.
사용자 변경과 미커밋 Replay는 제외한다. Git 실행 결과/커밋 SHA는 최종 응답에서 보고한다.


## 10. 사용자 직접 실행 준비 — 2026-10-15 (별도 실행 승인 대기)

이 절은 위 BLOCKED 이력과 별개의 **준비 검증**이다. 현재 HEAD는
`d336693bc73298f5be72d32e9374595ba1d11cb1`이다. 이번 사용자 직접 실행 작업에서
Codex의 sudo/권한 부여/권한 Probe/실제 테스트 트래픽 실행은 모두 **0회**다.
사용자 결과도 아직 제출되지 않았다. 따라서 실제 Capture E2E 판정은
**BLOCKED — 새 실행 대상 승인 및 사용자 직접 실행 대기**이며 VERIFIED가 아니다.
Stage/Commit/Push는 사용자 실행과 결과 검증이 끝나기 전까지 수행하지 않는다.

### 10.1 원본 Probe와 새 수동 실행 대상

원본 `native_probe.py`의 SHA256은 기존 승인값과 일치하며 변경하지 않았다.

```text
59b67d8a7654eebbb7f05e3810b3d3e2da0aea5029872a09ca01ed1e9a12a50d
```

원본은 READY를 외부에 제공하지 않고, 종료 시 TemporaryDirectory와 SQLite DB를
삭제한다. 임의 sleep 후 트래픽을 보내거나 종료 후 요약 문자열만으로 저장·복구를
검증하면 이번 요구사항을 충족하지 못한다. 이를 위해 원본 ProbeCapture를 상속하고
기존 NetworkMonitor / Queue / SourceStore / Provenance를 재사용하는 별도 CLI를 준비했다.
기존 승인 파일과 운영 Collector·Runtime은 수정하지 않았다.

**새 실행 대상:**
`src/soc_agent/security_ai/operational/network_capture/manual_capture.py`

**새 SHA256:**

```text
1f52fcd13c3eabd025bb7a810db4b9709b6c85ea065fed103e9eabd055fc17ba
```

사용자 Phase 4의 “변경 이유와 새 SHA를 제시하고 별도 사용자 승인을 요청한다”에
따라 **새 CLI에 대한 별도 승인 전에는 아래 capture/watch 명령을 실행하지 않는다.**
기존 59b6… 승인을 새 실행 대상에 그대로 적용하지 않는다. Codex는 승인 후에도
권한 명령을 실행하지 않으며, 사용자가 직접 실행한다.

### 10.2 실행 계약과 READY 확인

- 새 세션 전용 0700 디렉터리, 파일 0600, 기존 경로 재사용·Symlink·`..` 거부.
- 실제 UID/GID를 명령 생성 시 읽으며 현재는 1000/1000이다. 다른 계정이면 재검토한다.
- `lo`와 부팅/Network Namespace/Interface Identity를 결합한다.
- 기존 root 거부·CAP_NET_RAW 단독·NoNewPrivs 검증을 재사용한다.
- Capture Socket을 연 후 Effective/Permitted/Inheritable/Ambient를 모두 제거한 뒤 READY를 발행한다.
  Bounding Set에는 NET_RAW만 남으며, NoNewPrivs=1 및 Permitted=0으로 재획득을 막는다.
- 수집은 통상 2초, 최대 128개 수신 Record다. Socket 생성 직전 별도 프로세스의
  기본 SIGALRM 4초 Watchdog를 설정한다. 이 프로세스에만 적용되며 Kernel이 종료하면
  Socket도 닫힌다. 실제 Watchdog 시간·Capability 전환은 사용자 실행 전에는 미검증이다.
- 비권한 watch는 READY 파일뿐 아니라 PID 시작 시각, 실행 Interpreter SHA,
  실제 Cmdline, UID/GID, 비어 있는 Supplementary Groups, Capability, NoNewPrivs,
  FD의 Socket Inode와 `/proc/net/packet`의 lo 바인딩을 확인한다.
- `/proc/PID/exe`, `/proc/PID/fd` 접근이 WSL 보안 설정으로 거부될 수 있다.
  이 경우 **트래픽을 보내지 않고 BLOCKED** 처리하며 ptrace/권한 설정을 완화하지 않는다.
- READY 관측 제한은 120초다. 폴링 대기는 검증 가능한 READY를 기다리는 것이며,
  고정 sleep이 지났다는 이유로 수집 준비 완료를 가정하지 않는다.
- 검증 후 자신이 소유한 127.0.0.1 UDP 소켓 2개 사이 2개 Datagram 및 TCP 소켓 사이
  연결 1회·짧은 양방향 메시지를 보낸다. Loopback 외 송신, Resolver 호출, Packet Injection은 없다.
- 트래픽 전 단일 Claim을 저장한다. 중단/실패해도 자동 반복하지 않는다.
  다른 Root를 사용하더라도 총 승인 Probe 2회를 넘을 수 없다. 우선 1회만 실행한다.
- 커널의 실제 Packet 수는 송신 횟수로 추정하지 않고 수신 Record로 센다.
  lo에서는 동일 통신이 방향별로 관측될 수 있다. Capture Drop과 수신 상한 이후의
  미관측 구간은 구분하며 손실 없음/Exactly-once 네트워크 수집을 주장하지 않는다.

설치된 setpriv는 util-linux **2.39.3**이며 아래 옵션은 실제 `--help`에 존재한다.
UID 전환 시 setpriv의 capability 유지 및 Inheritable→Ambient→exec 전달을 사용한다.
Bounding Set 변경만으로 Effective Capability가 생긴다고 가정하지 않으며,
Probe 자체가 최종 Effective/Permitted/Ambient 상태를 검증하고 불일치 시 거부한다.
**해당 전환의 실제 성공은 아직 검증하지 않았다.**

### 10.3 사용자 실행 명령 — 새 SHA 승인 후에만

아래는 준비된 명령이며 Codex가 실행한 권한 명령이 아니다.
먼저 두 터미널 모두 프로젝트 디렉터리로 이동한다. 아래 Root가 이미 존재하면
삭제하거나 재사용하지 말고 중단한다. Source/Interpreter가 실행 도중 바뀌면 거부된다.

```bash
cd ~/kdt-linux/autonomous-soc-agent
sha256sum src/soc_agent/security_ai/operational/network_capture/native_probe.py \
  src/soc_agent/security_ai/operational/network_capture/manual_capture.py
id -u
id -g
```

1. **터미널 B:** 사용자가 직접 sudo 인증을 완료한다. 비밀번호나 토큰은 Codex에 전달하지 않는다.

```bash
sudo -v
```

2. **터미널 A:** 아래 비권한 Observer를 먼저 실행하고
   `WAITING_FOR_VERIFIED_READY` 출력이 나타나는지 확인한다.

```bash
/home/geonug/kdt-linux/autonomous-soc-agent/.venv/bin/python -I \
  -m soc_agent.security_ai.operational.network_capture.manual_capture watch \
  --directory /tmp/soc-user-capture-v2-20261015-01
```

3. **인증한 같은 터미널 B:** 아래 Capture 명령을 **한 번만** 실행한다.
   sudo -n 실패 시 비밀번호 재요청·자동 재시도는 하지 않는다.
   명령의 UID/GID가 위 id 결과와 다르면 실행하지 않는다.

```bash
sudo -n /usr/bin/setpriv \
  --reuid=1000 --regid=1000 --clear-groups \
  --bounding-set=-all,+net_raw \
  --inh-caps=-all,+net_raw --ambient-caps=-all,+net_raw \
  --no-new-privs \
  /home/geonug/kdt-linux/autonomous-soc-agent/.venv/bin/python -I \
  -m soc_agent.security_ai.operational.network_capture.manual_capture capture \
  --directory /tmp/soc-user-capture-v2-20261015-01
```

4. **두 프로세스 종료 후** 아래 비권한 검증을 실행한다.
   실패하더라도 결과 디렉터리는 삭제하지 않는다. `verify`는 수집 Socket을 열지 않으며
   저장된 Queue 복구·멱등성 확인을 위해 해당 테스트 DB만 처리한다.

```bash
/home/geonug/kdt-linux/autonomous-soc-agent/.venv/bin/python -I \
  -m soc_agent.security_ai.operational.network_capture.manual_capture verify \
  --directory /tmp/soc-user-capture-v2-20261015-01
```

결과 디렉터리 경로와 두 터미널의 상태 코드/요약을 전달하면 Codex가 원본 결과를 읽고
다시 검증한다. API Key·sudo 비밀번호·인증 토큰은 전달하지 않는다.
예상 입력으로부터 실제 Packet 수를 미리 채우거나 Fixture 결과로 대체하지 않는다.

다른 경로/현재 UID에 맞는 명령을 **출력만** 하려면 다음을 사용한다. 이 명령은
디렉터리를 만들거나 sudo/setpriv를 실행하지 않는다.

```bash
.venv/bin/python -m soc_agent.security_ai.operational.network_capture.manual_capture \
  commands --directory /tmp/soc-user-capture-v2-20261015-01
```

### 10.4 결과 파일 및 복구 검증 범위

저장 파일은 session.json, ready.json, closed.json, traffic-claimed.json,
traffic-result.json, capture-result.json 및 runtime 하위 Queue/Source/Runtime SQLite다.
Payload 원문을 저장하지 않으며 DNS 이름 보존은 기본 비활성이다. Verification 출력에는
Event/Source/Provenance Digest 연결과 타임스탬프 범위가 포함된다.

`verify`는 기존 Source 재조회·Provenance v3 생성/검증·저장된 Audit Receipt 일치·
Audit Hash Chain·SQLite 3개 integrity_check·동일 Event 재전달 거부를 확인한다.
같은 저장소로 반복 검증해 Queue/Source/Receipt 결과가 유지되는지 확인할 수 있다.
원래 권한 Probe를 추가 실행하지 않는다. 새 Runtime Capture나 장시간 Runtime E2E를
수행한 것으로 보고하지 않는다.

READY/Session 파일은 같은 UID가 보유하는 Digest 연속성 자료다. 서명된 외부 증명이나
같은 UID 공격자에 대한 보안 격리가 아니다. 소스 SHA·OS Peer 관측·원본 Source/Audit의
상호 검증 결과를 분리한다. 재부팅 후 Namespace/Interface Identity가 달라질 수 있으며,
출처가 달라진 원본을 새 수집으로 위장하지 않는다. `/tmp`는 재부팅 후 유지 보장을 하지
않으므로 사용자 실행 후 결과를 검증·보존하기 전 재부팅하지 않는다.

Kernel Drop은 PACKET_STATISTICS의 측정 구간만 뜻한다. 미측정 값은 None/UNKNOWN이다.
시작/재시작 Gap은 기존 NETWORK_CAPTURE_GAP Audit에 남기고 유실 없는 재개로 표현하지 않는다.
IPv6·실제 DNS 서비스 질의·물리 NIC·물리 서버·Kernel Watchdog 종료·실제 Capability 전환은
현재 미검증이다. Network Quality/Edge/DNS 운영 Gate는 **NOT_INFERABLE**,
Finding Promotion은 BLOCKED, Agent WRITE는 WRITE_DENIED를 유지한다.

### 10.5 이번 준비 작업 파일

- `src/soc_agent/security_ai/operational/network_capture/manual_capture.py`
- `tests/unit/network_capture/test_manual_capture.py`
- `docs/linux-soc-v1/native-capture-real-e2e.md` (기존 이력 보존 후 이 절 추가)

기존 사용자 수정·미추적 Replay와 앞선 중단 작업의 interactive-evidence.json은
이번 작업에 포함하지 않는다. 최종 사용자 실행 결과 검증 전 Commit/Push하지 않는다.


### 10.6 이번 준비 검증 결과 (실제 Capture와 구분)

| 실행 | 결과 | 범위 |
|---|---|---|
| 신규 단위 테스트 | 25 passed, 0 failed / 4.37초 | Fake Socket / Proc Fixture / 임시 DB, 실제 Capability 전환 아님 |
| 작업 트리 관련 회귀 | 322 passed, 0 failed / 102.79초 | Capture / Provenance / Source / GUI / Runtime / READ-only 경계 |
| 후속 Capture 집중 회귀 | 110 passed, 0 failed / 30.67초 | 종료 시 Drop 통계 보존 변경 이후, 최종 URI 인코딩 한 줄 변경 이전 |
| 최종 코드 독립 Git Export 회귀 | **322 passed, 0 failed / 101.88초** | HEAD archive + 이번 소스/테스트/문서만 적용, 최종 새 Probe SHA와 일치 |
| Ruff src/tests | PASS | 기존 사용자 변경 포함 작업 트리 전체 |
| Ruff format --check . | PASS / 875 files | 기존 파일의 일괄 수정 없음 |
| git diff --check | PASS | Stage 없음 |
| 사용자 실제 권한 Capture | **미실행 / BLOCKED** | 사용자 새 SHA 승인과 직접 실행 필요 |

위 수치는 겹치는 테스트를 실행별로 기록한 것이며 합산하지 않는다. 초기 25개 신규
테스트와 작업 트리 회귀 이후 안전한 종료 통계·SQLite URI 인코딩을 보완했다. 최종
독립 Export의 322개에는 신규 25개가 포함되며, 최종 소스에 대한 결과는 이 실행이다.
신규 테스트는 READY 이전/위조/재전송 시 트래픽 거부, PID/UID/GID/Capability/Socket
Fixture 검증, Source·Receipt·Audit·SQLite 복구, 중복 Event 거부, 경로 변조,
Watchdog 설정·취소 순서를 확인한다. Watchdog 테스트는 Timer Stub이며 실제 프로세스
강제 종료 검증이 아니다. Fixture의 Timestamp 필드가 Native 형식이어도 실제 수집으로
판정하지 않고 READY/OS Peer/Traffic 근거가 없으면 PARTIAL로 유지한다.

독립 Export 실행 범위:

```text
tests/approved_native_capture_checks.py
tests/unit/network_capture
tests/integration/network_monitor
tests/unit/operational_features/test_operational_provenance.py
tests/unit/operational_features/test_auth_source_store.py
tests/unit/gui
tests/integration/gui
tests/integration/linux_runtime
tests/integration/external_read_only_backend
```

RUN_LIVE_LLM_TESTS=0, --import-mode=importlib를 사용했다. API/모델 추론은 실행하지
않았다. Export는 user/replay 변경을 제외하고 별도의 src를 PYTHONPATH로 지정했으며,
실제 로딩된 manual_capture / service / tools.errors의 경로도 Export 내부임을 확인했다.
로그는 `/tmp/soc-user-manual-export-tests.log`, 준비 Manifest는
`/tmp/soc-user-manual-export.json`이다. 이는 로컬 준비 산출물이며 Commit 대상이 아니다.

기존 1,016개 파일 중 이 보고서만 추가 수정했고 다른 1,015개 SHA는 일치한다.
최종 Probe SHA는 위 10.1과 같으며 원본 승인 Probe SHA도 보존했다. Secret 패턴 검사에서
키/Private Key는 발견되지 않았지만 이를 모든 민감정보 부재의 완전한 증명으로 해석하지
않는다. 신규 소스에는 sudo/setpriv 문자열 출력만 있고 subprocess/os.system/UID 변경
호출이 없다. 권한 명령은 사용자 터미널에서만 실행하도록 남겨 두었다.


## 11. Manual Capture v2 — 사용자 실행 결과 최종 검증

앞 절의 PASSWORD_REQUIRED / BLOCKED / 승인 대기 기록은 당시 결과로 보존한다.
사용자는 새 Manual Capture SHA를 명시적으로 승인하고 직접 WSL 터미널에서 실행했다.
이번 최종 검증의 범위는 **보존된 실제 lo 수집 세션 1건의 Capture·권한 축소·저장·복구**이며,
이 범위의 판정은 **VERIFIED**다. 새로운 Capture·테스트 트래픽·sudo/setpriv 권한 실행은
Codex가 수행하지 않았다. 실제 DNS 서비스 질의나 운영 AI 추론까지 VERIFIED인 것은 아니다.

### 11.1 승인·출처·보존

- 기준 HEAD: `d336693bc73298f5be72d32e9374595ba1d11cb1`.
- 승인 및 실제 저장 세션의 Manual Capture SHA256:
  `1f52fcd13c3eabd025bb7a810db4b9709b6c85ea065fed103e9eabd055fc17ba`.
- 원본 native_probe.py SHA256:
  `59b67d8a7654eebbb7f05e3810b3d3e2da0aea5029872a09ca01ed1e9a12a50d`.
  두 파일은 최종 검증 중 수정하지 않았다.
- 승인 범위: 사용자 직접 실행, lo 전용, 최대 128개 수신 Record, Capture Watchdog 4초,
  Probe 최대 2회, 일반 사용자 UID/GID, 별도 프로세스의 임시 CAP_NET_RAW,
  소켓 생성 직후 Capability 제거, 소유한 Loopback UDP/TCP 테스트만 허용.
- 검증 대상은 `/tmp/soc-user-capture-v2-20261015-02`의 저장 세션이다.
  접미사 02를 실행 횟수 2회로 해석하지 않는다. 확인 가능한 완료 세션은 1건이며,
  전체 사용자 시도 횟수는 독립 실행 원장이 없어 별도로 확정하지 않는다.
- 기존 `verify`는 Queue recover/enqueue 확인 과정에서 DB 쓰기를 할 수 있다.
  따라서 원본 파일을 읽어 별도 0700/0600 검증 복사본을 만든 후 그곳에서 실행했다.
  원본 증거 16개 파일의 SHA 및 파일 목록은 검증 전후 동일하다.
- Runtime의 기존 빈 writer.lock은 private 0700 부모 아래의 소유자 일치 0644 조정 파일이다.
  Source/DB/Receipt는 0600이며 원본 권한을 자동 수정하지 않았다.
- 민감한 전체 출력·원본 DB·PID·임시 Port·계정명·호스트 식별자는 커밋하지 않는다.
  별도 요약은 `native-capture-manual-v2-verified-summary.json`에 기록한다.

### 11.2 Terminal A / B / C

| 구분 | 검증 근거 | 결과 |
|---|---|---|
| Terminal A Observer | traffic-result의 COMPLETED, peer_verified=true, READY Digest 연결 | 저장 Receipt 검증 PASS |
| Terminal A READY 검사 | PID 시작 시각·UID/GID·실행 Interpreter·Cap 집합·lo Socket Inode를 검사하는 승인 코드 | 사용자 실행 당시의 저장 결과와 Source SHA 연결 |
| Terminal B Capture | capture-result / closed / session 연결, STOPPED, last_error=null | 실제 AF_PACKET 저장 세션 확인 |
| Terminal C 재검증 | 동일 복사본에 일반 사용자 별도 프로세스로 verify 두 번 실행 | 종료 코드 0 / 0, 결과 동일, VERIFIED |

사용자가 실행한 A/B/C 원래 콘솔 Transcript/종료 코드는 이번 요청에 첨부되지 않았다.
따라서 A/B 프로세스의 실제 Shell 종료 코드를 추정하여 0으로 기록하지 않는다.
현재 확인한 것은 보존된 A/B 결과·Source/Audit와 이번 재검증의 종료 코드다.
READY 자료는 같은 UID의 Digest 연속성 자료이며 서명된 외부 Attestation이 아니다.
현재 종료된 프로세스를 다시 살아 있는 Peer로 확인했다고 보고하지 않는다.

### 11.3 실제 패킷·Flow·저장 결과

| 항목 | 실제 저장 결과 |
|---|---|
| Input Origin | NATIVE_AF_PACKET_LOOPBACK_OWNED_TEST |
| Interface | lo, Session / Config / Packet Identity 일치 |
| Capture 시간 | 2.2856369100009033초, 승인된 4초 이내 |
| Packet Record | **32** — TCP 28 / UDP 4 |
| 방향 | INBOUND 16 / OUTBOUND 16 |
| Network Flow | **4** — 기존 진단용 Flow Summary |
| DNS Event | **0** — 실제 Resolver 질의 미검증 |
| Kernel Timestamp | 32개 모두 KERNEL_SO_TIMESTAMPNS, ns 값 보존 |
| Queue | **DONE 36**, 미처리 없음 |
| Operational Source | **36**, Incident / Source Binding 검증 |
| Provenance v3 | **36** Source Receipt 재검증 및 저장 Audit Receipt 일치 |
| SQLite | Runtime / Network Queue / Network Source 3개 integrity_check PASS |
| Payload / DNS 이름 보존 | false / false |
| Runtime Network 상태 | STOPPED / NOT_READY — 종료된 수집기를 READY로 표시하지 않음 |

Queue의 36건은 Packet 32 + Flow 4이며 단위가 다르므로 패킷 수 36으로 보고하지 않는다.
동일 통신의 lo 방향별 관측과 Flow 집계는 구분한다. 소유한 UDP/TCP 양쪽의 Port 쌍이
실제 Packet Record에 나타나는지 검사했다. 해당 Port 쌍과 일치하는 Record는 24개이며,
나머지 8개는 다른 lo 통신 관측이다. 32개 전체를 테스트 Generator가 만들었다고 주장하지
않는다. 모든 Packet의 양 끝 주소가 Loopback 범위임을 확인했다. 다른 통신의 원인이나
공격 여부는 추정하지 않는다. Raw Payload와 실제 Port는 커밋하지 않는다.

### 11.4 Capability 축소·정책 경계

READY와 종료 Receipt에서 Effective / Permitted / Inheritable / Ambient는 모두 **0**,
Bounding은 **8192 (CAP_NET_RAW만)**, NoNewPrivs는 **1**이다. 일반 사용자 UID/GID가
세션과 일치한다. 소켓 이후 권한 축소 결과가 저장된 READY와 Observer 결과에 연결된다.
Bounding Set 잔존을 Effective 권한 잔존으로 해석하지 않는다.

이번 Codex 실행에서는 권한 부여, sudo 인증, Capture, 트래픽 생성, 영구 파일 Capability,
sudoers, Firewall, DNS, NIC, 운영 보안 설정을 변경하지 않았다. 사용자 실행 당시 OS 전체
설정에 대한 사전/사후 Snapshot은 제공되지 않아, 저장 Receipt만으로 모든 외부 프로세스나
시스템 설정의 부재를 포괄적으로 증명한다고 주장하지 않는다.

Network Quality / Edge / DNS 모두 다음 상태를 보존한다.

```text
Operational Input: NOT_INFERABLE
Native Operational Inference: BLOCKED
Finding Promotion: BLOCKED
Feature Generation: DIAGNOSTIC_ONLY
Agent WRITE: WRITE_DENIED
```

모델 호출·Finding 생성은 각각 0건이다. 학습 Producer Revision/Configuration 및
Raw↔Feature Golden Pair 미확보 차단은 실제 Capture 성공으로 해제되지 않는다.

### 11.5 Kernel 계수·Drop·Gap

- Runtime 샘플의 kernel_packets는 **44**, 종료 직전 별도 샘플은 **4**다.
  PACKET_STATISTICS는 읽을 때 초기화되므로 샘플 합은 48이지만, 이를 사용자 공간에서
  파싱·영속 저장한 32개 Packet Record와 동일한 계수로 취급하지 않는다.
- 차이 16개를 추가 저장 Packet이나 확정 손실 Packet으로 추정하지 않는다.
  수집 종료·Socket Buffer 미소비·lo Kernel 계수 의미 등의 상세 원인은 이번 저장
  자료만으로 확정하지 못한다. Socket 종료 시 미소비 패킷 수를 별도 관측하지 않았다.
- Runtime 및 종료 직전의 capture_drops는 각각 **0 / 0**이다. 이는 해당 소켓의
  통계 샘플 구간 결과이며 전체 호스트의 손실 없음이나 재시작 연속 수집 보장은 아니다.
- Capture Gap은 **1**이다. 기존 NETWORK_CAPTURE_GAP의
  NO_KERNEL_PACKET_REPLAY_ON_START_OR_RESTART 기록이며 누락 패킷 수가 아니다.
- Kernel Packet 계수, 사용자 수신/저장 수, Drop, Gap을 서로 대체하지 않는다.

### 11.6 Recovery / 변조 탐지

별도 검증 프로세스 두 번에서 같은 결과가 재현됐다. Queue 재개 후 DONE 36,
Source/Provenance 36, Audit Digest, Packet/Flow 수가 유지됐다. 동일 Event 재전달은
거부되며 Duplicate Effect Prevented=true다. 이는 저장된 Event 재처리 멱등성이며,
외부 네트워크 Exactly-once 수집을 의미하지 않는다.

Audit Digest:

```text
a65e1ec434cf3f6bfc7bf69c3d4d799e38517ffe33c5540d0acb3194d21d75b1
```

수집 종료 시 Audit와 복구 후 Audit가 일치한다. 원본과 별도의 폐기 가능한 복사본에서
closed Receipt Digest 변조 및 Runtime Audit 변조를 각각 주입했고,
SESSION_RECORD_DIGEST_MISMATCH / RUNTIME_AUDIT_INTEGRITY_REJECTED로 거부됐다.
원본 증거는 변경하지 않았다. 실제 강제 종료 Capture를 새로 실행하지 않았다.
전체 Continuous Runtime을 다시 Capture 모드로 기동한 검증도 아니다.

### 11.7 독립 재현성과 범위

이번 Commit 후보는 Manual Capture 모듈, 관련 단위 테스트, 네트워크 차단 회귀 실행기,
이 보고서와 비민감 요약 JSON의 5파일이다.
기존 미커밋 Replay 및 사용자 변경은 포함하지 않는다. 실제 저장 Session의 코드 지문에는
당시 작업 트리의 service.py 전체 SHA도 들어 있다. 해당 파일의 사용자 변경은
LinuxMonitor 조사 Registry 연결에 한정되며, Manual Capture가 호출하는 initialize 함수의
AST는 기준 HEAD와 동일함을 확인했다.

독립 Export에서는 기준 HEAD + 이번 Commit 후보만으로 단위/통합 회귀를 실행한다.
과거 Session을 다른 소스 지문으로 자동 재인증하지 않는다. 즉, Export의 기능 회귀와
원래 소스 환경에서 저장된 실제 증거 재검증은 별개의 검증이다. 원래 Session Digest나
Code Fingerprint를 Export에 맞춰 고치거나 Source 검증을 우회하지 않는다.

### 11.8 남은 범위 / 다음 단계

실제 DNS 서비스 질의, IPv6 Capture, 물리 NIC/물리 Linux 서버, 장시간 수집·부하,
Kernel Watchdog 실제 발동, 프로세스 강제 종료 중 실제 Capture는 미검증이다.
승인된 테스트는 lo·소유한 UDP/TCP 통신에 한정되며 공격 탐지 정확도를 증명하지 않는다.
다음 단계는 학습 Producer/Golden Pair 확보와 물리 Linux 최소 권한 수집·Drop/Gap 관측 계획이다.
이번 작업에서 새 Producer·AI 자동 추론·GUI·운영 대응 기능을 추가하지 않는다.


### 11.9 최종 회귀·품질·변경 범위

| 실행 | 결과 | 실제 경과 |
|---|---|---|
| 초기 임시 실행기 회귀 | 392 passed / 6 failed | 231.84초 |
| 진입점 수정 후 작업 트리 | **398 passed / 0 failed** | 128.83초 |
| 독립 Export, 수정된 임시 실행기 | 398 passed / 0 failed | 127.07초 |
| 최종 독립 Export, 포함 대상 테스트 실행기 직접 사용 | **398 passed / 0 failed** | 113.52초 |
| 실제 저장 증거 재검증 | 별도 비권한 프로세스 2회 모두 VERIFIED / exit 0 | 새 Capture 없음 |
| 복사본 변조 거부 | Receipt / Audit 2개 모두 거부 | 원본 수정 없음 |
| Ruff check src tests | PASS | 소스 자동 수정 없음 |
| Ruff format --check . | PASS / 876 files | 신규 테스트 실행기만 정리 |
| git diff --check | PASS | 보호 파일 보존 |

테스트 수는 실행별이며 중복 합산하지 않는다. Manual Capture 단위 테스트 25개는
각 398개 실행에 포함된다. 초기 실패는 임시 Python pytest 실행기의 __main__ 보호가
없어 multiprocessing spawn 자식이 pytest를 재실행한 결과다. Network 저장 복구 5개와
Runtime Invocation 복구 1개가 Handshake Timeout으로 실패했다. 실행기 진입점을 고친 후
동일 범위 전체를 다시 실행해 통과했으며 승인된 Capture 소스나 기존 테스트 기준을
수정하거나 실패를 Skip하지 않았다. 초기 실패 로그도 보존한다.

실제 Capture/트래픽 금지를 지키기 위해 테스트 전용 실행기
`tests/native_capture_verification_guard.py`는 새 AF_PACKET / IPv4 / IPv6 소켓 생성을
Python Audit Hook에서 거부한다. Unix Socket은 기존 Runtime Operator 테스트에 사용한다.
각 정상 회귀 실행에서 네트워크 소켓 생성 시도 1개가 차단됐으며, 이는 기존 수집기
Permission Denied 경로의 **오류 주입 검증**이다. 실제 Kernel Capture 권한을 새로
실험한 결과가 아니다. 외부 Provider/모델 호출은 비활성이다. 강제 종료는 기존 Harness가
소유·확인한 Fixture 자식 프로세스에만 적용하며 권한 Capture 프로세스는 새로 띄우지 않는다.

재현 명령 (저장소 Root에서 실행, 외부 .env 값을 출력하지 않음):

```bash
RUN_LIVE_LLM_TESTS=0 PYTHONPATH="$PWD/src:$PWD" \
  .venv/bin/python tests/native_capture_verification_guard.py \
  --import-mode=importlib -q \
  tests/unit/network_capture \
  tests/integration/network_monitor \
  tests/unit/realtime \
  tests/unit/operational_features/test_operational_provenance.py \
  tests/unit/operational_features/test_auth_source_store.py \
  tests/unit/gui tests/integration/gui \
  tests/integration/linux_runtime \
  tests/integration/external_read_only_backend \
  tests/unit/approval tests/unit/execution
```

독립 Export는 기준 HEAD의 git archive에 아래 5파일만 적용했다. 테스트가 실제 Export의
src를 사용하도록 절대 PYTHONPATH를 지정했다. 기존 사용자 변경이나 Replay 모듈을 복사하지
않았으며, 최종 Export에는 위 테스트 실행기 자체도 포함하여 /tmp 실행기에 의존하지 않는다.
시험 완료 후 보고서/요약의 검증 수치만 갱신하며 Source/Test 코드는 동일하게 보존한다.

- `src/soc_agent/security_ai/operational/network_capture/manual_capture.py`
- `tests/unit/network_capture/test_manual_capture.py`
- `tests/native_capture_verification_guard.py`
- `docs/linux-soc-v1/native-capture-real-e2e.md`
- `docs/linux-soc-v1/native-capture-manual-v2-verified-summary.json`

원본 증거·DB·콘솔 전체·비밀번호·개인 식별값·모델 Artifact는 포함하지 않는다.
기존 README.md, pyproject.toml, docs/soc-command-center.md, Runtime/Replay 사용자 수정 및
미추적 파일은 제외한다. 이번 최종 작업 시작 시 1,018개 기존 파일 중 보고서 외 1,017개
SHA가 그대로임을 확인했다. Manual Capture 및 원본 Probe SHA도 승인값 그대로다.
현재 SOC 프로세스는 일반 사용자이며 Effective/Permitted/Inheritable/Ambient=0이다.
Python Interpreter 및 Manual Capture Source에 영구 File Capability가 없음을 조회했다.

최종 로그는 /tmp의 soc-final-capture-regression{,-final}.log,
soc-final-capture-export-{tests,final}.log에 보존하며 커밋하지 않는다.
Stage 파일/검증 Export 파일의 SHA 일치 및 민감정보 검사를 거쳐 5파일만 커밋한다.
Commit Hash / 원격 HEAD 검증 결과는 최종 작업 응답에서 보고한다.
