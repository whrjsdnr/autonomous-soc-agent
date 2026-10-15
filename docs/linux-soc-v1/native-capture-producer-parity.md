# Linux Native Capture / Training Producer Parity

검증 환경: **WSL2 Ubuntu / WSLg**, 2026-10-15.
기준 HEAD: `b8cc23598cd2e3b3c870fe4a127a1bb39820023c`, branch `main`.
ML HEAD: `1800bd013edefd448671c97a8b7114409f639481`.

**판정: PARTIAL.** 권한 진단, 제한 Probe, 인터페이스 교체 방어, 저장·복구·보안 회귀를
구현/검증했다. 실제 AF_PACKET 수집은 권한 부여 승인 전이므로 **BLOCKED**다.
Network Top40 / DNS9 모두 학습 Producer revision/configuration과 Raw↔Feature Golden Pair가
없어 **NOT_INFERABLE**을 유지한다. 합성 수치 비교나 Native Fixture 추론을 운영 정합성으로
승격하지 않았다.

기계 판독 근거: [audit evidence](native-capture-producer-parity-evidence.json).
이는 이번 실행의 조사 기록이며 Collector attestation, 승인 토큰, 추론 허가가 아니다.

## 1. Baseline / 변경 보존

Git status/HEAD/log/diff/cached diff와 실제 `AGENTS.md`를 먼저 확인했다. 기존 Index는 비어 있었다.
시작 시 기존 수정 8개와 모든 미추적 파일의 SHA를 `/tmp/soc-native-parity-baseline.json`에
기록했다. README, pyproject, Command Center 문서, Scenario/Runtime/Tool 기존 변경과
미커밋 Reliability Replay는 이번 Stage 대상이 아니다. ML 저장소/환경/Artifact도 변경하지 않는다.

## 2. Capture Permission Audit

| 항목 | 이번 실제 WSL 결과 |
|---|---|
| Effective UID / GID | 1000 / 1000 |
| Effective / Permitted / Inheritable / Ambient capabilities | 모두 0 |
| CAP_NET_RAW / CAP_NET_ADMIN | 없음 / 없음 |
| NoNewPrivs | 0; 진단은 변경하지 않음 |
| 인터페이스 | lo, eth0, docker0 |
| Capture Backend | 기존 표준 라이브러리 AF_PACKET |
| libpcap / tcpdump | 현재 진단에서 찾지 못함; 설치하지 않음 |
| eth0 / lo socket 생성 | PERMISSION_DENIED |
| 실제 패킷 / DNS 관측 | BLOCKED; 0건 검증, 무트래픽을 입증한 것이 아님 |
| Capture Drop | UNKNOWN; 권한 거부를 drop=0으로 표시하지 않음 |

실행 명령:

```bash
.venv/bin/python -m soc_agent.linux_runtime.network_cli diagnose --interface eth0
.venv/bin/python -m soc_agent.security_ai.operational.network_capture.native_probe --seconds 1
```

첫 명령은 socket open/bind/close만 수행하고 privilege snapshot, UNKNOWN 지표, 기존 Gate를
반환한다. 두 번째는 `CAP_NET_RAW_REQUIRED`, exit 2로 **DB 생성 전 거부**됐다.
sudo 실행, 파일 capability/setuid 변경, Firewall/NIC/DNS 설정 변경은 수행하지 않았다.

AF_PACKET 생성에는 해당 network namespace를 관할하는 `CAP_NET_RAW`가 필요하다.
선택 인터페이스 bind/recv만 하고 NIC 설정을 바꾸지 않는 이번 경로에서 CAP_NET_ADMIN은
요청하지 않는다. Capability 보유와 수집 성공은 별도 검증이다.
[Linux packet(7)](https://man7.org/linux/man-pages/man7/packet.7.html).

## 3. Restricted Capture Process / 승인 대기 계획

`network_capture/native_probe.py`는 기존 Runtime과 별도로 **직접 명시해 시작하는 진단 Process**다.
GUI/Runtime이 sudo를 호출하거나 이를 자동 실행하지 않는다.

- 인터페이스 allowlist는 코드상 **lo 하나**다. 임의 인터페이스/Artifact/저장소 경로 입력이 없다.
- UID 0 거부. 유효 CAP_NET_RAW 필수이며 permitted/inheritable/ambient/bounding에 다른
  capability가 있거나 읽을 수 없으면 거부한다. NoNewPrivs=1도 필수다.
- 소켓 open/bind 후 capset으로 해당 Process의 effective/permitted/inheritable을 0으로 내리고
  ambient까지 실제 `/proc/self/status` 재조회로 확인한 뒤 패킷을 처리한다.
- 최대 10초(기본 5초), 최대 128패킷, batch 8, 최대 16개 진단 Flow다. 타이머 종료는 기존
  NetworkMonitor의 정상 flush/ack/close를 사용한다. 생산용 상시 broker는 아니다.
- Shell/subprocess/송신/Firewall 조작 경로가 없다. Payload와 DNS 원문은 저장하지 않는다.
- 새 private 임시 Runtime/Queue/SourceStore만 생성하며 기존 데이터 경로를 받지 않는다.
- 기존 SourceStore 재조회와 v3 receipt 검증, SQLite integrity_check, Queue 재구성 결과를
  요약한다. 성공 조건에는 무오류, 측정 drop=0, 전부 DONE, 복구 전후 Queue 동일성이 포함된다.
- 임시 DB는 Probe 종료 시 정리된다. 영구 운영 증거 저장/프로세스 Crash 뒤 재조회 검증과는
  다르다. 실제 결과가 없는 현재는 영속 운영 E2E를 주장하지 않는다.

**잔여 신뢰 경계:** CAP_NET_RAW는 receive-only capability가 아니다. 이미 열린 raw socket은
capability를 내린 후에도 외부 효과를 낼 수 있다. 이 Probe는 송신 API를 구현하지 않지만,
Python 프로세스 침해까지 막는 seccomp/전용 receive broker sandbox는 아니다. 운영 서비스의
특권 분리, immutable 배포 코드, 통신 경로 인증과 injection syscall 차단은 후속 검증 사항이다.
SOC 전체나 일반 Python 바이너리에 영구 setcap을 부여하지 않는다.

승인 요청 범위는 다음 **일회성 실행 최대 2회와 소유한 loopback 소켓의 소량 테스트 트래픽**이다.
사용자 지시 Phase 2가 sudo/권한 부여 전 명시적 승인을 요구하므로, 승인 전에는 실행하지 않는다.
테스트 DNS UDP/TCP를 확보하더라도 자연 발생 운영 DNS나 학습 Golden Pair로 표시하지 않는다.

```bash
# 승인 전 미실행. sudo -n 실패 시 비밀번호/다른 권한 경로로 우회하지 않는다.
sudo -n /usr/bin/setpriv \
  --reuid=1000 --regid=1000 --clear-groups \
  --bounding-set=-all,+net_raw --inh-caps=-all,+net_raw \
  --ambient-caps=-all,+net_raw --no-new-privs \
  "$PWD/.venv/bin/python" -I \
  -m soc_agent.security_ai.operational.network_capture.native_probe --seconds 5
```

실행 검토 Source SHA256:
`59b67d8a7654eebbb7f05e3810b3d3e2da0aea5029872a09ca01ed1e9a12a50d`.
setpriv의 일회성 UID/capability/no-new-privileges 동작 근거:
[setpriv(1)](https://man7.org/linux/man-pages/man1/setpriv.1.html).

## 4. Existing Pipeline / 발견한 결함

```text
Bound AF_PACKET → existing parse_packet → NetworkPipeline.packet
  → EventQueue commit / checkpoint → claim → OperationalSourceStore.ingest
  → build_receipt / audit_once → ack
  → diagnostic bidirectional Flow → same source revalidation
  → three closed model gates
```

PacketCapture 생성 시 기록한 interface identity와 실제 socket open 시점의 interface identity
사이에 재검사가 없었다. 현재는 **open 직전과 bind 직후** 모두 identity를 비교하며, 변경 시
CAPTURE_INTERFACE_CHANGED로 거부/close한다. 열린 socket에 다시 open하여 기존 handle을
덮어쓰는 것도 CAPTURE_ALREADY_OPEN으로 막는다. Fixture 테스트로 두 경계의 교체를 재현했다.
이 재검사가 모든 커널 namespace 변경의 원자적 방어를 증명하는 것은 아니다.

Queue/SourceStore/Audit가 서로 다른 SQLite DB이므로 다중 DB 원자성을 가정하지 않는다.
기존 idempotent 재처리와 source/digest 충돌 거부를 사용한다. Packet capture에는 journal 같은
영속 Cursor가 없다. 시작/재시작마다 NO_KERNEL_PACKET_REPLAY_ON_START_OR_RESTART Gap을
남기며, 중단 구간을 복구 성공으로 표시하지 않는다.

## 5. Flow / DNS 검증 범위

기존 IPv4/IPv6, TCP/UDP, 제한 IPv6 extension/VLAN, 길이·truncation 검증과 양방향 Flow를
재사용한다. Forward는 최초 관측 방향, duration은 seconds, 길이는 소켓 frame bytes이며
**학습 CICFlowMeter의 정의가 아니다**. 모든 Flow는 incomplete / DIAGNOSTIC_ONLY다.

DNS는 단일 question UDP 및 한 segment에 완결된 DNS/TCP만 지원한다. TCP stream 재조립,
fragment 재조립, 다중 question은 미지원이다. Query 원문 대신 case-preserving wire label의
digest를 기본 저장하며 IDNA/suffix/trailing-dot 변환을 학습 규칙으로 추정하지 않는다.
443/853 포트만으로 DoH/DoT 여부나 DNS 내용을 추정하지 않는다.

이번 실제 NIC 패킷, IPv4/6, DNS query/response, drop, 프로세스 재시작 수집은 **BLOCKED**다.
아래 Fixture 회귀는 실제 파서와 Queue/SourceStore/v3/복구를 호출하지만 실제 NIC 증거가 아니다.
WSL eth0는 가상 NIC/namespace 경계의 트래픽만 관측 가능한 후보이며 Windows host/물리 NIC
전체를 관측한다고 주장하지 않는다.

## 6. Training Producer Provenance

Notebook은 실행하지 않고 JSON code cells를 읽었다. ML tree의 `.git`, `.venv`, cache를 제외한
파일명 조사에서 PCAP/PCAPNG **0개**, producer/CICFlowMeter 코드·설정 후보 **0개**다.
이는 지정 로컬 경로에서 찾지 못했다는 뜻이며 원저자가 자료를 보유하지 않았다는 증명은 아니다.

| 자료 | 이번 확인 내용 | 학습 Producer로 인정 여부 |
|---|---|---|
| ML/notebooks/data.ipynb cell 0 | TrafficForML CSV read/헤더 검사 | 아니오 |
| notebooks/preprocessing.ipynb cells 67/68 | importance CSV의 head(40)로 컬럼 선정 | raw 계산 아님 |
| notebooks/model_sample_v4.ipynb cells 32/33/56 | rank 순서, Parquet → float32 LightGBM 입력 | raw 계산 아님 |
| notebooks/dnn_top40_v4.ipynb cells 0/1/2/43 | float32, nonfinite→NaN, scaler.partial_fit, mean impute/transform | 저장 전처리 근거; PCAP Producer 아님 |
| reports/CIC-Bell-DNS-EXF-2021_DNS_Security_EDA.ipynb cells 4/10 | stateless_features-*.pcap.csv 읽기, 기존 9컬럼 통계 | 파일명 pcap.csv는 PCAP parser가 아님 |
| 같은 DNS_Security_ML.ipynb cells 2/5 | 가공 CSV의 9컬럼 선택, RF/XGB/LGBM 실험 | FQDN Producer 및 공급 INT8 DNN 학습/export 아님 |
| packages/network-security-ai/.../contracts.py / preprocessing.py | Top40Contract.matrix, preprocess_dnn_batch | 입력/저장 scaler만 검증 |
| packages/dns-security-ai/.../feature_contract.json / preprocessing.py | DNS9 finite float32, named scaler, INT8 round/clip | 문자열 생성 규칙 UNVERIFIED |
| docs/security_ai/source_inventory.md / soc_integration_contract.md | DNS raw 데이터·DNN training/export 누락 명시 | 누락 근거 |

[CSE-CIC-IDS2018 공식 설명](https://www.unb.ca/cic/datasets/ids-2018.html)은 CICFlowMeter-V3
계열을 보고하지만, 로컬 학습 CSV를 생성한 정확한 revision/configuration을 제공하지 않는다.
[CIC-Bell-DNS-EXF-2021 공식 설명](https://www.unb.ca/cic/datasets/dns-exf-2021.html)은 자체
추출기와 특징 의미를 설명하지만, 이번 공급 모델과 연결된 producer revision과 문자열 처리
규칙/원본 행 대응은 확보하지 못했다. 최신 GitHub 재구현을 학습 Producer로 채택하지 않았다.

DNS9의 문서상 의미와 미확보 계산 경계는 다음과 같다. 전부 학습 Producer와의 parity는
**BLOCKED**이며, 아래 설명으로 새 Extractor를 구현하지 않았다.

| Feature | 공식 문서상 의미(REPORTED_ONLY) | 미확보 경계 |
|---|---|---|
| FQDN_count | FQDN 문자 수 | byte/codepoint, trailing dot, IDNA, case 입력 |
| subdomain_length | subdomain 문자 수 | suffix/등록 domain 판별, multi-label suffix 처리 |
| numeric | 숫자 문자 수 | ASCII/Unicode 숫자 집합, 정규화 순서 |
| entropy | query name 기호 빈도의 Shannon entropy, log₂ | 계산 대상 문자열/문자 집합, dot/case/빈 문자열 처리 |
| special | 특수문자 개수 | 완전한 문자 집합, escape/punycode 처리 |
| labels | dot 구분 label 수 | 빈 label, trailing dot, root/malformed name 처리 |
| labels_max | 최대 label 길이 | 길이 단위, label 전처리 |
| labels_average | 평균 label 길이 | 분모, 빈 label, rounding/dtype 전환 시점 |
| len | domain/subdomain 길이 | FQDN_count와 차이, domain 경계와 입력 표현 |

현재 Capture의 wire-label 파싱은 transport 관측이며 이 표의 학습 Feature 생성기가 아니다.
위 9개에 TTL Feature는 포함되지 않으므로 임의 TTL 값이나 zero를 추가하지 않았다.

## 7. Golden Pair / Feature별 Parity

| 항목 | Quality | Edge | DNS |
|---|---|---|---|
| 공식 이름/순서/float32 모델 계약 | VERIFIED: Top40 | VERIFIED: Top40 | VERIFIED: DNS9 |
| Artifact SHA / manifest | VERIFIED, 독립 모델 | VERIFIED, 독립 모델/scaler | VERIFIED, 독립 DNN/scaler |
| 추론 시 저장 전처리 | native missing, scaler 없음 | 저장 mean impute→scaler→float32 | named scaler→INT8 round/clip |
| Producer 계열 | REPORTED_ONLY | REPORTED_ONLY | REPORTED_ONLY |
| Producer revision / config / 실행 로그 | MISSING | MISSING | MISSING |
| 학습 Flow 방향/timeout/단위/active-idle 계산 | MISSING | MISSING | 해당 없음 |
| 학습 DNS case/dot/IDNA/suffix/entropy-label 규칙 | 해당 없음 | 해당 없음 | MISSING |
| Raw↔training Feature Golden Pair | MISSING | MISSING | MISSING |
| 학습 계산 정합성 판정 | BLOCKED | BLOCKED | BLOCKED |
| 운영 추론 | NOT_INFERABLE | NOT_INFERABLE | NOT_INFERABLE |

공식 `reviewed_binding()`의 ordered_names로 각각 40/40/9개를 읽었으며 전체 Feature별
`training_formula_parity`, producer/config/golden 상태와 Artifact 기대/실제 SHA를 JSON에 기록했다.
의미상 아는 포트/길이가 있어도 **학습 계산 정합성**의 검증 근거는 별개다.
Network의 order digest는 `ac252fd93d3c5504803695fc609e8209701c74c812b163508b001490cb31b649`,
DNS는 `3276c1b595ec566677bce530f2839247b7fa1320dc5e3549f85c0c17c959edd0`다.
공식 목록을 복제한 새 Extractor는 만들지 않았다.

Native 파일 **10/10**을 실제 읽어 크기/SHA와 공식 binding을 대조했다. 모델별 Fixture Native
추론과 Adapter/Context/Scripted Agent 검증도 기존 native test로 수행한다. 이는 raw 계산
정합성과 독립적이다. Artifact·Scaler를 수정/복사하거나 모델을 재학습하지 않았다.

`compare_exports.compare_exports()`와 `network_records.validate_reported_flow()`,
`dns_records.validate_reported_dns()/compare_dns_rows()`를 재사용한다. 기존 테스트에서
40/9 순서, Decimal 값 차이·상대/절대 오차·float32 bits, nonfinite/overflow/underflow,
source/row digest, Incident 연결, 변조를 검증한다. **실제 Golden Pair 비교는 미실행**이다.
수치 정책 EXACT_DECIMAL_EXPORTS_V1의 허용 오차는 0이며 이를 학습 공식 허용 오차로
발급하지 않는다. NaN/Inf를 운영 feature에서 조용히 보정하지 않는다.

## 8. Operational Gate

Capture source, producer revision/config, Golden Pair, 공식 feature contract, artifact,
adapter binding, provenance가 모두 검증되어야 운영 허가를 논의할 수 있다. 현재 Gate는
caller-set verified bit를 받지 않으며 세 모델 각각 다음 상태를 새로 반환한다.

```text
Collection: permission-dependent / current PERMISSION_DENIED
Diagnostic Flow: implemented, Fixture verified
Feature generation: DIAGNOSTIC_ONLY
Operational inference: NOT_INFERABLE / BLOCKED
Finding promotion: BLOCKED
WRITE: WRITE_DENIED
```

v3 receipt의 SOURCE_CHAIN_VALIDATED_UNATTESTED는 출처 진위/학습 parity가 아니다.
기존 v3 model_result=None, UNVERIFIED rule, Synthetic v2 전용 모델 계약은 그대로다.
Network/Edge 점수 평균, DNS와 검증되지 않은 correlation, LLM fact promotion은 추가하지 않는다.

## 9. GUI / 실제 WSLg

Dashboard에 실제 network.last_error를 `Permission / error`로 표시한다. 실제 권한 거부 상태가
PERMISSION_DENIED / NOT_READY이고 Drop UNKNOWN, 모델 NOT_INFERABLE임을 UI에서 확인했다.
GUI가 권한을 자동 부여하거나 상태 조회로 모델을 실행하지 않는다.
상단 AI Fixture env READY는 **Fixture 실행 환경**이며 Network Collector/운영 AI READY가 아니다.

실제 WSLg 캡처:

- [1920×1080](native-capture-screenshots/native-capture-permission-denied-1920.png)
- [1366×768](native-capture-screenshots/native-capture-permission-denied-1366.png)

스크린샷은 **실제 PERMISSION_DENIED 상태**다. 실제 패킷 수집 성공 화면이나 공격 탐지 화면이 아니다.

## 10. Tests / 실행 결과

```bash
RUN_LIVE_LLM_TESTS=0 \
SOC_EXTERNAL_ARTIFACT_ROOT="$PWD/.security-ai-demo/artifacts" \
SOC_EXTERNAL_INFERENCE_PYTHON="$PWD/.security-ai-demo/inference/bin/python" \
.venv/bin/python -m pytest --import-mode=importlib -q \
  tests/unit/network_capture tests/integration/network_monitor \
  tests/unit/operational_features tests/unit/security_ai/external \
  tests/unit/external_context tests/unit/package_status tests/integration/package_status \
  tests/native_package_status_checks.py tests/unit/gui tests/integration/gui
```

- **434 passed, 0 failed, 97.78s** (`/tmp/soc-native-parity-regression.log`).
  실제 native test는 합성 Feature 3모델 → Context → Scripted Agent/READ 경로다. 실제 LLM 요청 없음.
- 신규 permission/probe 테스트만 최종 별도 실행: **24 passed, 6.05s**.
  무권한 자식에서 capset ABI와 0-capability 재검증을 추가했다. 권한이 있던 상태에서
  CAP_NET_RAW를 제거하는 실제 실행은 승인 전 미검증이다. 위 수치와 합산하지 않는다.
- 실제 WSLg 권한 거부 UI: **1 passed, 5.29s** (`tests/native_capture_gui_checks.py`).
- 첫 확대 실행에서 Probe용 RuntimeConfig 필수 임계값 누락으로 **81 passed / 3 failed**였다.
  기존 계약이 요구하는 두 값을 명시하여 수정하고, 정상/Drop/UNKNOWN 경로 23개와 위 434개를
  재검증했다. 탐지 Worker는 Probe에서 시작하지 않으며 운영 임계값을 변경하지 않았다.
- 별도 Runtime/Security: **304 passed, 0 failed, 190.42s**
  (`/tmp/soc-native-parity-runtime.log`). 실행 범위:
  `tests/integration/linux_runtime`, `scenario`, `restricted_response`,
  `external_read_only_backend`, `tests/unit/approval`, `execution`.
  이 수치는 위 434개와 합산하지 않는다. S01~S12, 승인/정책/WRITE_DENIED와 실제 응답 범위 제한을
  기존 테스트로 재확인했다. 실제 Restricted Marker 변경은 격리 테스트 리소스만 해당한다.
- 독립 Git Export: HEAD archive + 이번 12파일만 적용했다. 미커밋 Replay와 사용자 변경을
  포함하지 않은 상태에서 집중/Native Fixture/GUI 회귀 **425 passed, 95.45s**,
  Runtime/Scenario/Approval 회귀 **304 passed, 194.20s**, 실제 권한 거부 WSLg 확인
  **1 passed, 2.73s**였다. 로그는 `/tmp/soc-native-parity-export-{test,runtime,gui}.log`다.
  집중 425는 작업 트리 실행 이후 추가된 ABI 테스트 1개를 포함하고, 사용자 미추적
  `test_producer_parity_boundary.py`의 10개는 제외한 수치다. 실행별 수치를 합산하지 않는다.
- 검증한 Python 소스/테스트 8개의 SHA가 Export와 작업 트리에서 모두 일치한다.
  범위 밖 기존 파일 **1,000개**도 시작 SHA 그대로다. Stage는 이번 12파일만 허용한다.

5개 기존 owned-child Crash Point(Source/Audit/ack 경계)와 Queue checkpoint 실패/overflow,
SQLite write failure, native/fixture source binding, digest/Incident/Flow 통계 변조 거부를 재사용한다.
SIGKILL은 테스트가 소유한 자식에게만 적용한다. 실제 capture process의 Crash 후 packet 복구는
미검증이며 Socket에는 중단 구간 replay가 없다는 제한을 유지한다.

품질 검사: Ruff src/tests PASS, 전체 format **871 files** PASS, git diff --check PASS.
Source/Artifact/정책/승인/모델 스키마의 의미를 변경하지 않았다.

## 11. Remaining Blockers / 후속 물리 Linux

1. 실제 권한 수집: 위 제한 Probe의 명시적 승인이 필요하다. 미승인을 실패/거부 승인으로
   간주하지 않고 **PENDING / NOT_EXECUTED**로 남긴다. eth0 상시 broker 권한은 별도 승인 범위다.
2. 정확한 학습 Producer source commit 또는 binary SHA/빌드, 설정 원문/실행 argv가 필요하다.
3. 원천 PCAP/FQDN과 원 Producer가 만든 CSV, flow segment/query별 대응키, 파일 SHA, 생성 로그,
   학습 입력까지 전처리 연결 자료가 필요하다. 합성 fixture는 대체 자료가 아니다.
4. DNS 공급 INT8 DNN의 실제 training/export 이력과 canonicalization/label/entropy 규칙이 필요하다.
5. 물리 Linux에서 실제 NIC/offload/drop/고부하/privilege-separated broker/재시작 Gap/보존 정책을
   검증한다. 현재 WSL 결과를 물리 서버나 Windows 검증으로 확장하지 않는다.

## 12. 이번 변경 범위

- `src/soc_agent/security_ai/operational/network_capture/permissions.py`: 읽기 전용 권한 진단.
- 같은 경로 `native_probe.py`: 명시적·별도·bounded loopback Probe, 기존 저장/검증 재사용.
- 같은 경로 `capture.py`: open/bind 전후 identity 및 중복 open 방어.
- `src/soc_agent/linux_runtime/network_cli.py`: 기존 diagnose 출력 확장.
- `src/soc_agent/gui/app.py`: 권한/오류 가시화.
- `tests/unit/network_capture/test_capture.py`, `test_permissions.py`: 경계·오류·Fixture 저장/복구.
- `tests/native_capture_gui_checks.py`: 실제 권한 거부 WSLg 확인.
- 이 보고서, audit evidence JSON, 실제 화면 PNG 2개.

기존 미커밋 Replay·사용자 변경은 Stage하지 않는다. 검증된 이번 파일만 별도 Git Export에서
검사했다. 사용자 지시의 audit commit/push 범위와 실제 권한 부여 승인은 별개다.
실제 Capture 승인은 여전히 PENDING이며 sudo/권한 변경은 미실행이다. Git 실행 결과/커밋 SHA는
최종 응답에서 별도로 보고한다. 보고서/Fixture 검증을 실제 Capture 또는 Producer Parity
VERIFIED로 표시하지 않는다.
