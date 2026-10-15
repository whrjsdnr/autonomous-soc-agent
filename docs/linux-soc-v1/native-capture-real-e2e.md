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
