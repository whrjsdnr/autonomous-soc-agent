# One-command Native + DNS 연결 및 재시험 준비

2026-10-29. 브랜치 `feat/one-command-runtime`.
사용자 지시에 따라 실제 1시간 시험은 다음 작업으로 미뤘다.
이번 수정·검증에서는 Root 설치/인증/서비스 시작, Namespace 진입, Native/DNS 수집,
DNS 트래픽 생성, Host 인증 로그 읽기, 외부 API 호출, 실행 예약·영수증 발급을 하지 않았다.

## 오류 목록과 처리

| 항목 | 확인 내용 | 수정·검증 | 남은 실환경 범위 |
| --- | --- | --- | --- |
| Root 감시기의 오래된 표본 | 상태를 먼저 읽고 두 번의 blocking systemctl 조회 뒤 현재 시각과 비교했다 | `observe_service_health`가 서비스 조회 후 새 상태를 취득하며 동일 6초 기준을 적용한다. 실제 고정 Root coordinator에도 삽입·검증했다 | OS 지연 원인 UNKNOWN 유지; 수정 후 Live 미시험 |
| DNS 미연결 | Native GUI/CLI에 TCP 전용 NOT_COLLECTED 문구가 고정됐고 DNS 수신기 lifecycle이 없었다 | 기존 TotalCapture/stream helper를 사용하는 DNSProducer → durable metadata → IsolatedDNS Transaction → Audit → GUI 연결. Stop/Drain/종료를 Runtime이 소유 | 새 Helper Scope 승인·설치·실제 READY/Capture 대기 |
| Helper가 AI 전체를 import | Packet 모델의 SourceIdentity import가 전체 애플리케이션·NumPy로 이어져 격리 환경에서 실패했다 | 동일 SourceIdentity를 경량 모듈로 분리하고 기존 API에서 재수출. 256MiB import probe 및 복사한 격리 Python에서 ML 없이 import 통과 | Kernel/AF_PACKET 실행은 별도 |
| GUI 증거 검사 중 duplicate lock | 같은 GUI data directory의 두 번째 Desktop이 거부됐다 | 중복 실행 차단은 유지. 별도 inspection profile로 실제 Native 결과 5화면과 종료·재연결을 검증했다 | 새 DNS Live GUI 검증 대기 |
| 과거 Helper SHA 회귀 | 역사적 검증의 SHA를 변경된 현재 파일에 비교했다 | 원본 증거와 SHA는 그대로 보존. 당시 파일을 Git에서 보존해 원래 SHA를 검사하고 새 Manifest도 별도 대조 | 과거 승인은 새 Helper에 적용하지 않음 |
| 승인 전 listener 생성 | Runtime 객체 생성 시 listener를 열었다 | 생성자에서는 읽기 전용 검사만 수행하고 승인·단일 실행 잠금 이후에만 열도록 수정. 정책 거부 시 FD/Socket 미생성 회귀 통과 | 새 Live 미시험 |
| DNS 보관 byte budget | 전체 Storage 상한과 별개인 DNS metadata8MiB가 저장 직전에 강제되지 않았다 | transcript 인코딩 byte를 저장 전 검사, reject 계측, 복구 시 동일 byte 재구성. 초과 입력의 저장·추론 차단 검증 | 새 Live 미시험 |
| 수신 Queue 테스트의 시간 가정 | 부하에서 0.4초 timer가 늦어 실제 backlog 11인데 12 이상을 가정했다 | 실제 sender 진행 신호를 기다린다. 원래 6.1초 저장 지연, 5초 timeout, freshness/12개 backlog assertion을 모두 유지 | 테스트 보강이며 Kernel watchdog 완화 아님 |

직전 실제 시험의 최초 오류 `ROOT_HEARTBEAT_STALE`는 보존한다. 관측 순서 결함을 재현·수정했지만
과거 모든 지연의 원인을 확정하거나 새 Live 성공으로 재분류하지 않는다.
Program1145 UNKNOWN, 과거 global Cleanup UNVERIFIED, FAILED/false도 그대로다.

## 실제 운영 코드

`continuous/dns_source.py`는 별도 Continuous DNS 정책(최대3600초, 16fps/burst64,
transport32)을 사용한다. 기존 Diagnostic/Total 기본300초 정책은 바꾸지 않았다.
현재 Target Namespace·lo identity, Session SHA·코드/Interpreter, peer PID/UID/GID/시작시각/
argv/capability/FD·counter를 검증한다. Host의 후보 검증은 Namespace 진입 성공이 아니다.

`dns_helper.py`는 스스로 sudo/setns/capability를 얻지 않는다. 검토된 고정 launcher가
Target Namespace에서 실행해야 한다. Helper는 UID1000·CAP_NET_RAW로 AF_PACKET을 연 뒤
Eff/Prm/Inh/Amb를0으로 내린다. CapBnd는 기존 peer 계약의 NET_RAW, NoNewPrivs=1을 유지한다.
AI Runtime/GUI는 capability0이다. 새 App unit도 Target Namespace에 묶이며 GUI는 Host에 남는다.

`ContinuousRuntime.collect_dns/project_dns`는 실제 peer-검증 metadata를 모델 Job으로 바꾸지 않는다.
먼저 별도 durable transcript에 보존하고 UDP/TCP Query/Response를 기존 IsolatedDNS로 전달한다.
메타데이터8MiB 상한을 저장 전에 강제한다. 재시작 시 동일 transcript로 다시 구성하며 Session/sequence/내용 충돌과 중복 Audit를 차단한다.
Authentication 복구가 DNS transcript를 인증 이벤트로 해석하지 않도록 분리했다.

GUI Dashboard의 DNS 수집 상태, Continuous 상세, Security Events/Investigation의 DNS 증거가
Backend와 연결됐다. Raw payload·Query name을 보관하지 않으며 DNS9는 계속 INCOMPLETE다.
TCP DNS는 완전한 단일 메시지만 지원하고 재조립은 지원하지 않는다. DNS AF_PACKET counter
관측을 TCX Capture Attestation 또는 모델 Eligibility로 표시하지 않는다.

## 검증 결과와 증거

공통 증거 경로:
`/home/geonug/kdt-linux/autonomous-soc-agent/.git/dns-one-command-integration-20261029T104018Z/`.

- 최종 독립 validation Export: **466 PASS / 6 opt-in SKIP / 1 deselected**, 253.10초.
  deselect한 5,000-event 검사는 앞선 Workspace 전체 실행에서 이미 통과했다.
- Workspace import/identity/복구 집중 회귀 **42 PASS**, receiver/DNS/observer **22 PASS**, 최종 byte-budget·승인 전 listener 미생성 포함 집중 회귀 **40 PASS**.
- 기존 Controller·Admission·R1/R2·Lease 경로 **104 PASS**. Root 외부 경계를 mock한 정확한
  고정 TCX+DNS coordinator **10 PASS**. 실제 승인/Root 명령은 실행하지 않았다.
- 실제 저장 PCAP → 운영 CLI → RF/LR → Incident/Audit → 실제 Tk **1 PASS**, 44.84초.
  PCAP128레코드 기반 검증(at5ed95cf)이며 Native/DNS Live 성공으로 해석하지 않는다. 이후51788f5/4c05331의 변경은 Native DNS 보관 상한·계측과 승인 후 listener 생성에 한정된다. API0/SCRIPTED.
- 보존 Native40 / ELIGIBLE2 / Prediction2 / Incident1을 실제 Tk의 5개 화면에서 확인했다.
  종료·재연결 후 같은 STOPPED Backend·Audit가 유지된다. 실환경 수집을 다시 시작하지 않았다.
- Native6개 이중 빌드 및 Wheel 이중 빌드 동일. 격리 Helper Python802개 파일 목록 고정,
  pydantic2.13.5 import 및 AI/NumPy 미로딩 확인. systemd 후보2개와 shell 문법 검사 통과.
- Ruff check/format 및 diff 검사 통과. 실패한 최초 회귀/격리 import/구형 GUI 중복 잠금
  시도와 수정 후 결과를 함께 보존했다. 모든 시도가 최초부터 PASS였다고 보고하지 않는다.

주요 로그: `lifecycle-export-tests.log`, `import-recovery-tests-v2.log`,
`final-receiver-focused.log`, `governance-tests.log`, `lifecycle-fixed-trial-tests.log`,
`real-pcap-final-cli-gui.log`, `native-gui-current-code.json`, `lifecycle-build-identity.json`.

## Source·Artifact 고정

운영 Source Freeze: `4c05331e7020ab33b37bbab8f01ba4b2d513304a`.
Tree: `fe12fe0abb1625b30df55b1ae4be7208153c28b4`.
검증 전용 sender 동기화 Commit: `a94e2f8cc4f2b14ab2968ac6516159f85d1b8f51`.
마지막 validation Export의 src 파일은 운영 Freeze와 byte 단위로 일치한다.
보관 상한 수정은51788f5, 승인·잠금 후 listener 생성 수정은4c05331이다. 테스트/보고서의 별도 Commit을 다른 Artifact의 Git으로 바꿔 적지 않는다.

| Identity | SHA256 |
| --- | --- |
| Source file map digest | `a83214f63c250d0831e1ef34d3500c11fa3be11fdcd465532958d941b6a386c7` |
| Source archive | `be25e041c101420c88074dfd6355d082706920df4b56b865d3592e676f11af21` |
| Wheel | `a567c963536c015af282e5ca0c197fb3778d0d7156c705591f4146349387c3c3` |
| Root Manifest 후보 | `6ae3a00304c762ee6ce316c53b1f77548ee699fdf12caaeeaa84bb43d1f60fb3` |
| 새 실행 요청서 | `678a973da95d4e7414465636603b90725f410fc71f986232f5da4bfd42295733` |
| 새 검토 패키지 | `d6bee7b3d225c05aefd080f064ccefc40ecc0084014e27b846e36777acf75e10` |
| DNS Session 파일 | `262a8ced81b339550946f5c1046618d304ec704be106efd17581ca52bea18984` |

Native BPF/Provider/Root service/policy 파일은 이전 설치와 동일하다. 개별 전체 SHA는
`lifecycle-build-identity.json`, 새 App/Helper 후보와 Session은
`native-dns-lifecycle-final-review/approval-request-final-v2.json`에 있다. 세션은 이 JSON을 기준으로 한다.

Legacy Ledger81행/SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`
불변. Legacy 계측은 Campaign Root12/Native4, Batch3 Root9/Native1이다.
별도 보존 Continuous 실행·Root Audit를 지우거나 Legacy 횟수에 섞어 환급하지 않았다.
설치 정책 SHA `401ecb1b5b8575916423f560d1befc7c16a30c91a5209284a48418c922e15f99` 불변.
새 DNS system unit은 미설치이며 기존 세 서비스는 inactive/PID0 상태다.

## 한 명령 시작과 실제 승인 경계

다음은 **다음 실환경 작업에서 사용할 후보**이며 이번 작업에서는 실행하지 않았다.

```bash
bash /home/geonug/kdt-linux/autonomous-soc-agent/.git/dns-one-command-integration-20261029T104018Z/start-with-dns.sh
```

내부에서 기존 `soc-agent start --home .../native-dns-lifecycle-final-profile --gui`를 호출한다.
Source/Artifact/Session/Lease/Ledger 자동 대조 → Scope/R1 표시 → 사용자의 yes → 직접 sudo →
내부 check → 승인된 고정 설정 적용 → TCX/App/DNS Helper → GUI 순서다.
SHA 복사/입력을 요구하지 않는다. Source·설치·Ledger·유효기간 불일치면 실행하지 않는다.
이전 기본 profile을 덮어쓰지 않았다. `setup/status/stop/gui/doctor`의 기존 Entry Point도 유지한다.

```bash
cd /home/geonug/kdt-linux/soc-one-command-runtime
.venv/bin/soc-agent doctor --home /home/geonug/kdt-linux/autonomous-soc-agent/.git/dns-one-command-integration-20261029T104018Z/native-dns-lifecycle-final-profile
.venv/bin/soc-agent start --home /home/geonug/kdt-linux/autonomous-soc-agent/.git/dns-one-command-integration-20261029T104018Z/native-dns-lifecycle-final-profile --preview
.venv/bin/soc-agent status --home /home/geonug/kdt-linux/autonomous-soc-agent/.git/dns-one-command-integration-20261029T104018Z/native-dns-lifecycle-final-profile
.venv/bin/soc-agent gui --home /home/geonug/kdt-linux/autonomous-soc-agent/.git/dns-one-command-integration-20261029T104018Z/native-dns-lifecycle-final-profile
.venv/bin/soc-agent stop --home /home/geonug/kdt-linux/autonomous-soc-agent/.git/dns-one-command-integration-20261029T104018Z/native-dns-lifecycle-final-profile
```

Root installer는 고정 설정5개만 대상으로 백업·검증·적용하며 서비스4개만 제어한다.
새 DNS helper capability와 App Target 실행은 기존 TCP 전용 승인 범위가 아니다.
AGENTS.md §33의 Human Review → Approved Update에 따라 정확한 새 Scope 검토가 필요하다.
현재 후보의 승인·예약·실행 영수증은 발급하지 않았다. Host preview는 source/plan/DNS binding PASS,
doctor의 Target 내부 검사는 BLOCKED이다. 후자는 승인된 실제 진입 전의 정상적인 차단이다.

**단일 시작이 모든 권한의 자동 승인을 뜻하지 않는다.**

- 이번 후보는 수동 DNS 수집이다. DNS 질의 생성0/외부 연결0이며 전용 Target의 TCP 시험만으로
  DNS Query/Response가 발생하지 않는다. 다음 실제 DNS Transaction 시험에는 고정 로컬 공급원과
  새 R2 권한 검토가 필요하다. 원래 TCP 승인을 DNS 생성 권한으로 사용하지 않는다.
- RF/LR은 실제 봉인·Attestation·Network14 ELIGIBLE 입력의 기존 exact Action 승인 이후다.
  Capture Scope만으로 미래 Job의 모델 영수증을 자동 발급하지 않는다. 승인 없으면 대기/보존한다.
- 새 Host Authentication 수집/IF 분석, 실제 LLM API, DNS9, 위험한 대응은 이 후보에 포함하지 않는다.
  기존 별도 결과의 조회와 새로운 실행 권한을 구분한다.
- 전체 상한3600초에 시작/종료를 포함하며3500초까지 Stop을 준비한다. 순수 수집3600초를
  보장하는 후보가 아니다. 순수1시간 수집을 원하면 다음 시간 계약 검토에서 명시해야 한다.

따라서 판정은 **비권한 통합·실행 준비 완료 / 새 Native+DNS Live 검증 대기**이다.
기존 제한 Native 성공과 Offline 시연을 보존하며 OPERATIONS_VERIFIED로 승격하지 않는다.
