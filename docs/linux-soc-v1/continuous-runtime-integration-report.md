# 최신 결과 — 2026-10-29 제한된 실제 Native Continuous E2E

**실제 Kernel TCX → 봉인 Window → Network14 ELIGIBLE → 승인된 RF/LR → Incident →
읽기 전용 SCRIPTED 조사·Audit → GUI 경로를 검증했다.** Capture는 제한 시험1회이고,
모델은 정지 후 같은 원본 Native 입력을 기존 CLI에서 별도 인간 Action 승인으로 분석했다.
무인 상시 운영·Host 전체 수집·운영 승격·실제 LLM API 검증을 의미하지 않는다.
이하 이전 시점의 BLOCKED/FAILED/UNKNOWN 보고는 원문 그대로 보존한다.

## 실제 실행과 증거

- 실제 설치·Capture 코드: `608c03e71bf7f4f99a34d2230476c1249be864ec`.
  사용자의 수정 후 재실행 지시를 새 파일/Source/Ledger Binding에 기록했다.
  이전 소비 승인 재사용 없이 새 인간 결정·설치 정책을 검증했고, 사용자 터미널에서
  Scope yes·sudo 인증 후 추가 시험 **1회**만 수행했다.
- 증거: 공통 Git 디렉터리
  `continuous-scalar-recovery-20261029T012308Z/execution/execution-result.json`.
  실제 모델 결과: 같은 디렉터리 `retained-native-model-analysis/result.json`.
  Source/build 검증 및 별도 인간 모델 Action 요청·결정·감사 파일을 함께 보존한다.
- Target `net:[4026532232]`, Host `net:[4026531833]` 유지. 내부 check PASS,
  lo UP/ifindex1/외부 Route·Interface 없음, Namespace Socket Cookie8855.
- Kernel load·TCX attach·Root READY·인증된 ordinary Producer READY 모두 PASS.
  Root 서비스 정상 exit0, 실행 약188초로 승인된240초 이내.
- TCP `127.0.0.1:18080`, source18081/18082에서 연결2·요청2·응답2 성공.
  첫 연결 종료부터 다음 연결 종료까지 `35.00120635s`; 고정 Helper 코드의35초 wait와
  일반 사용자/Capability0 실행을 함께 검증했다. DNS·외부 접속0.
- 실제 Native metadata **20건**, Window seal **2개**(callback20/0), Counter·Clock·epoch·
  delivery/drain 정합성 및 Capture Attestation VERIFIED. Queue Drop/invalid/재시작0.
- 보존된 첫 Window Session `131d3617-6393-5c63-aa69-6c92b5ea5146`.
  Window ID `9a0854fc5718e7cf826e2ecec42cb83789b694d4a4b46c8fd37068065c16d79e`.
  Flow2개 중 **ELIGIBLE1 / INCOMPLETE1**. 마지막 Flow는 이후 관측 이벤트 timeout witness가
  없으므로 기존 계약대로 차단한다. 단순 벽시계 대기나 FIN만으로 승격하지 않았다.
- 사용자 추가 `승인한다` 메시지는 당시 대기 중인 보존 Native 입력의 RF/LR Action으로
  별도 기록했다. 기존 `ApprovalManager`·`GovernedExecutor`와 CLI가 job/implementation/
  output/Session/Namespace/release/time을 검증했고 부적격 Flow는 추론하지 않았다.
  실제 RF/LR **2 Prediction**, Incident **1개** 생성.
  Incident `c37a311d-436d-57eb-a698-3166f1b7dd6b`, 분류 `UNKNOWN_ANOMALY`.
  입력은 승인된 정상 TCP 시험이며 이 모델 결과가 실제 공격임을 입증하지 않는다.
- SCRIPTED 조사 계획·읽기 전용 도구·평가·`SOURCE_CONTINUITY_VERIFIED`·Audit PASS.
  실제 LLM API0, DNS9 추론0. 모델 receipt에 REAL_NATIVE·Artifact SHA·Feature fingerprint·
  Window/Flow/증거 참조·지연을 기록했다. `analyze-offline`의 `native_executed=false`는
  분석 명령이 새 Capture를 시작하지 않았다는 뜻이며 입력 origin은 REAL_NATIVE다.
- 실제 Tk GUI에서 LIVE Native 수집 상태와, 이후 감사 검증된 REAL_NATIVE 모델 결과2건을
  각각 표시했다. GUI 종료 후 Collector가 계속 동작함도 확인했다. 정지 후 결과는 LIVE로
  표시하지 않는다. `execution/show-verified-native-result.sh`로 Root·Capture·추론 재실행 없이
  보존된 실제 결과를 다시 열 수 있다.
- Root·ordinary Runtime·인증 STOP ACK Cleanup 모두 VERIFIED, Helper Socket 정리 PASS.
  이번 Kernel link/prog/map 전후 JSON 모두 동일. Root Audit chain PASS,
  Continuous Audit8개 검증. 과거 전역 Cleanup UNVERIFIED·Program1145 UNKNOWN은 유지.
- Legacy Ledger **81행**, SHA
  `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` 불변.
  기존 Campaign Root12/Native4·Batch3 Root9/Native1 기록은 초기화/환급하지 않았다.
  Continuous 시작 시도는 별도 실행 증거/Root Audit에 기록하며 이번 성공 시작은1회다.

## 오류 탐색·수정 최종 목록

| 문제 | 처리 및 실제 검증 |
|---|---|
| BTF 누락 | `-g`·prefix map·BTF/libbpf 파일 parse. 실제 Kernel load 성공 확인 |
| 가변 stack 접근 verifier 거부 | 첫 복구의 map 임시 buffer도 다음 verifier에서 거부된 실패를 보존. 최종 고정 destination helper parser로 교체 |
| 가변 map pointer verifier 거부 | scalar offset + 1/2/4/16-byte helper 읽기, cache/map 제거. 기존 parser와 정상·절단·변조 C differential 회귀, 실제 Kernel load/TCX 성공 |
| 원래 errno 유실 | C cleanup 전 errno 보존·Python OSError 전달, cleanup EUCLEAN 우선 유지. 실제 EACCES 실패 로그도 보존 |
| Kernel load 전에 소켓 READY 노출 | Provider load/attach 후 bind/listen. 운영 run 실패 회귀 및 이번 실제 READY 순서 확인 |
| Root 자식 종료를 outer timeout으로만 표시 | 새 고정 Launcher가 Producer READY 대기 중 Root 실제 종료를 즉시 확인, 최초/후속 오류 분리 |
| STOP ACK 뒤 닫힌 socket을 Cleanup 실패로 오판 | 검증된 binding의 stop_ack만 idempotent 처리. 이번 실제 Runtime·Collector Cleanup VERIFIED |
| 모델 승인 대기 중 정상 Stop 오분류 | 사용자 Stop·승인 대기·실행 중 모델 자식 없음 조건만 정상 취소. 예상치 못한 취소는 UNKNOWN. 이번 실제 승인 대기 Stop 정상 |
| GUI Cleanup 혼동 | ordinary/Collector Cleanup 분리, Replay NOT_APPLICABLE, 실제 ACK 없는 VERIFIED 승격 금지 |
| Apport 후속 오류 | 해당 고정 서비스의 표준 excepthook만 복구, 원래 traceback 보존. 시스템 sandbox 변경 없음 |
| bpftool wrapper 조회 실패 | 기존 고정 executable SHA 대조, 이번 Kernel 전후 조회 모두 성공·동일 |
| Native Packet·Flow·Eligibility 집계 누락 | 후속 ordinary 코드에서 native_tcx Packet 수와 기존 candidates() 재검증 결과를 집계. 승인·모델 호출 조건 변경 없음. 원본 시험의 0 표시를 덮어쓰지 않고 별도 재계산 결과로 보존 |
| 검증 runner의 다른 checkout/model 환경 참조 | 테스트 전용 기존 모델 root·각 subprocess Source 명시. 최초 실패 로그 보존 후 Workspace/Export 회귀 통과 |
| 최종 Flow INCOMPLETE | 오류가 아닌 기존 관측 이벤트 기반 종료 계약의 정상 차단. 원본 INCOMPLETE 유지 |
| systemd oneshot RuntimeMaxSec 경고 | 비차단 설정 경고이며 같은 unit의 `TimeoutStartSec=90s`가 실제 시작 상한을 유지함을 확인. 시험은37초 내 Helper 정상 종료. 기존 승인 unit은 임의 변경하지 않음 |

## 후속 표시 수정과 최종 비권한 검증

최종 ordinary 집계 수정의 Workspace/독립 Export **각90 PASS**, 장시간 stress2개는 deselected.
실제 Tk GUI 회귀는 Workspace/Export **각2 PASS**이며, 별개로 위 실제 LIVE/보존 Native 모델 화면을 검증했다.
Ruff·Format·Diff PASS. Native 산출물6개·Wheel 재현 빌드 일치.
집계 수정은 Root 파일을 변경하지 않으며 이미 성공한 Capture를 다시 실행하지 않았다.

- 최종 Source653개 `1d29c7c5a6376f5e71bc5a2cc25d3e84f1dd0f9670f787c6ce6b3e5555ce8059`
- 최종 Wheel `93f5589a6364c98f86a7bf9c571707bdba07dc4fb11bee49ce7fe98a4d181e12`
- BPF `da58d00289ce04a3c818f8ca5b776f1b2fccaaef9b96f324f60a24904bcde8f6`
- Provider `62e4610379f9dc3b8f2a5fb070009dfcdcdbf2c1a5a0f6d76c0c2a22b6296bff`
- Root Service `9a259bf55d1d8f1d88b86860fdc9ac9986fefea0958cc1435d8788f28e372119`
- Root policy code `cb050423f29747e7b0ab96b89248ad5893eea1e8c9c8bb24edc1f0c5585b3d53`
- 실제 시험 설치 정책 `edcf7a424d48a43a2e0a8412906e7c9cc8b78528b2084a7191712a5d2ac6040f`

최종 판정은 **제한된 NATIVE_CONTINUOUS E2E VERIFIED / DEMO_READY**다. 장시간/고부하 상시
운영, 새로운 Scope의 실행 승인, DNS9 학습 추출 계약, 실제 Native 이상에 대한 REAL_API 조사는
이번 성공 범위가 아니다. 저장 파일 단독의 진위를 OS attestation으로 승격하지 않는다.
실제 실행 원본·승인·Root Audit·비소비 검증을 결합한 이번 제한 시험의 결과만 판정한다.

---

# Continuous Native AI 연결 — 2026-10-29 최종 비권한 통합 (이전 보고 보존)

**판정: Window Attestation → Native 모델 action admission → RF/LR → Incident·Audit·GUI
운영 코드 연결 완료. 실제 Kernel/Native Continuous E2E는 미검증·실행 차단 유지.**
이 판정은 Fixture/Offline 성공이며 LIVE VERIFIED 또는 RELEASE_READY가 아니다.
운영 코드 Commit: `b7efb09855b8387b47959ab0a4d853dfc8ea5630`,
Tree: `7941ae00b39aff5b4d2e7e230e984bf84796a720`.
브랜치 `feat/continuous-runtime`에 이번 변경만 선별 Commit/Push한다.
이전 보고는 아래에 당시 상태로 보존한다.

## 구현과 검증 경계

`continuous.capture`는 Root가 보낸 봉인 Window와 보존된 이벤트에서 Feature와 입력 영수증을
다시 계산한다. 기존 Phase D `assess_capture`, `assess_windows`, `input_receipts`,
`tcx_input`, `VectorRequest`와 RF/LR Adapter를 재사용했다. 기존 Phase D 정책·제한·검증식은
변경하지 않았다. 새로운 예산/승인 프레임워크나 정책 영수증 발급기는 추가하지 않았다.

Root 서비스는 180초 또는 4,000 callback에서 새 소유 Map Window를 종료한다.
실제 PRE_ATTACH Counter, 시작 Clock bracket 3개, detach→ring consume→POST_DETACH Counter,
종료 Clock bracket 3개와 callback/drop 정산을 봉인한다. Window당 최대 4,096 metadata와
128 possible CPU를 검증한다. BPF의 분당 admission 상태만 다음 Map으로 전달하므로
Map 교체가 같은 분의 quota를 초기화하지 않는다. Capture Counter는 새 Map의 실제
조회 결과로 검증하며, 이전 값을 빼서 가짜 zero baseline을 만들지 않는다.

Window 교체 사이에는 관측되지 않는 구간이 있다. 이 경계를 넘는 Flow는 합치지 않는다.
이 보장은 소유 hook의 지원되는 metadata 범위이며 Host 전체 무손실 수집 보장이 아니다.
FIN/RST나 wall-clock 대기는 기존 30s/120s 관측 이벤트 timeout witness를 대체하지 않는다.
부족한 Counter/Clock/epoch/drop/drain/Feature 증거는 INCOMPLETE/UNKNOWN/INVALID로 차단한다.

일반 사용자 Runtime은 Root peer·Namespace·program·policy·epoch·seal을 확인하고,
원본 transcript를 durable commit한 뒤 모델 Queue로 전달한다. 각 Window/Flow/job/Incident는
결정적 Identity를 사용한다. Crash 후 같은 transcript를 재구성해 기존 Queue admission을
재사용한다. 일부 입력만 남은 Window는 Counter 정산을 통과할 수 없으며, 새 epoch에서
과거 부분 Window를 적격으로 승격하지 않는다. Replay/변조 seal은 거부한다.

Native 모델 호출은 Capture 권한과 분리했다. 적격 Native job도 **기존 exact retained TCX
model action approval**이 없으면 Worker를 시작하지 않고 대기한다. 승인 파일의 SHA·action·
Session·Namespace·release identity·implementation·유효기간은 기존 CLI/Executor가 검증한다.
`native_model_approvals`는 기존 영수증을 읽는 디렉터리이며 발급기가 아니다. 일반 GUI의
Native 분석 직접 시작 차단은 유지했다. Collector의 `native_model_inference=false`도 유지하며,
Root 서비스가 모델을 실행하도록 확대하지 않았다. 새 Window에 이전 action 승인을 재사용하지 않는다.

봉인 release identity는 설치 파일 SHA map의 canonical digest다. 기존 Root Release manifest나
Namespace 정책 영수증으로 가장하지 않는다. 저장 파일의 재계산만으로 OS 진위를 확정하지 않으며,
retained Native Evidence Envelope는 기존 DECLARED_UNATTESTED 구분을 유지한다.

## 실제 데이터·모델 결과

| 시나리오 | 결과·근거 |
|---|---|
| 실제 저장 PCAP, REAL_OFFLINE / REAL_MODEL | 이번 개발의 Continuous CLI 실행에서 Packet 88개, Flow 45개, RF/LR Prediction 6개, NORMAL Incident·Audit 3개 |
| 봉인 Window, FIXTURE / REAL_MODEL | ELIGIBLE Flow 1개와 INCOMPLETE Flow 1개를 구분; RF/LR Prediction 2개, UNKNOWN_ANOMALY Incident·SCRIPTED 조사·읽기 전용 평가·Audit |
| 운영 Queue → 분석 subprocess | 같은 Fixture를 실제 Continuous Worker와 CLI에서 처리하고 결과·Audit 재검증 |
| Native 형태의 합성 증거 / 승인 없음 | Feature 적격성은 독립 심사하되 모델 호출 0개, 기존 action 승인 요구 |
| 과거 저장 Native 증거 | 9개 후보 중 ELIGIBLE 0개, INCOMPLETE/UNKNOWN 유지, 모델 호출 없음 |
| 실패 Attestation | Counter gap·ring loss·disabled·clock drift·epoch·drop·partial·baseline·drain·cleanup·schema·namespace·seal 변조 차단 |
| 복구 | transcript 게시 후 handoff 전 중단, 동일 epoch receiver 재시작, 중복 seal·job·새 epoch 부분 Window 검증 |
| GUI | 실제 Tk에서 Fixture/Replay origin·domain·eligibility·Prediction·Incident 상세·Audit·종료·재연결 검증 |

PCAP 실행은 후속 Root 종료 오류 보존 보완 전의 처리량/Stop 중도 종료 검증이다.
후속 변경은 Root 오류 분류/원인 보존에 한정되며 최종 Source 집중 검증으로 확인했다. `38 dropped + 3 DONE + 4 PENDING = 45`
Window를 계측했고, 남은 입력은 보존했다. 모델 오류 0개, Stop·Cleanup VERIFIED다.
새 외부 API 호출은 0회이며 새 조사는 SCRIPTED다. 실제 Kernel Event/Live/LLM 성공으로
표기하지 않는다. DNS9 학습 추출 계약 부족에 따른 차단은 유지했다.

과거 Native 파일 SHA:
`f1b1e42143ef8be973f2ee16319c18757cdda114dbb7304e9f479d6503147388`
(`native-stabilization-batch3/approved-runtime-20261027-1/stage/supervised-result.json`).
그 원본 파일, 기존 FAILED/false/UNKNOWN, 설치·Rollback은 수정하지 않았다.

## 회귀와 재현 빌드

관련 전체 회귀는 Workspace/독립 Export 각각 **314 PASS · GUI 1 FAIL**이었다.
GUI 실패는 Test Fixture가 새 origin 필드를 전달하지 않았던 원인까지 수정해 별도 재검증했다.
최종 Source의 **Capture/admission/Root 종료 진단 집중 검증은 양쪽 각각 32 PASS**다.
이 배치에는 detach 실패와 chained Cleanup 오류가 VERIFIED로 덮이지 않는 검증도 포함된다.
**최종 실제 Tk GUI는 Workspace/독립 Export 각각 2 PASS**다.
식별된 실패는 모두 수정 후 해당 경로 재검증을 통과했다. 겹치는 테스트를 합산하지 않는다.
집중 검증 범위: Window/admission/Unix framing/durable recovery/실제 RF·LR/Root 빌드 경계.
Root peer·설치 권한·Kernel boundary는 Mock이며 실제 Root/Kernel 테스트가 아니다.

첫 전체 회귀는 Workspace/Export 각각 313 PASS·GUI 1 FAIL이었다. origin 열 추가 후 기존 GUI
테스트가 domain을 고정 열 0에서 읽던 원인이었다. 열 이름으로 검증하고 Fixture origin 확인을
추가했다. 추가 origin 확인에서는 기존 Fixture의 누락 필드를 보완했다. 테스트 assertion을 제거하거나 모델·적격성 기준을 완화하지 않았다.
초기 수집 단계의 동명 test_contracts 충돌은 `--import-mode=importlib`로 실행했다.
처음의 worktree model backend 경로 누락은 기존 검증용 환경을 명시해 해결했다.

Ruff check·format(1,469 files)·Diff 통과.
최종 Source Snapshot(652 files):
`2e8788d43d2236dc5aa70d8da6a9dfb1a8602a3642bb6c9f9fe1dc1838098cb1`.
Workspace/Export Source 동일. Native 산출물 6/6 및 Wheel byte-identical.

| 산출물 | SHA256 |
|---|---|
| Wheel | `905512792be47286ed9a7fe8e317dfcac0058ab5cc4032d04e277d4b64d716f5` |
| continuous.bpf.o | `a5e249726ac00966679b2b0c9360825e69ec9da64e44cf360d0a1ea608fa7548` |
| provider.so | `cc66ab23b3d28e32ab3a4f7581b155d1cca704c047d5cc2006ac18fd3557980d` |
| Root service.py | `5126b0661cce26c8fe527cccff2022d74cb4a3c12695ee1a7ecdc23aa8db6fd6` |
| policy.py | `cb050423f29747e7b0ab96b89248ad5893eea1e8c9c8bb24edc1f0c5585b3d53` |
| Runtime identity | `431f2854bdd2c515f47ad60784263b1446305b1b515108ab5a898aef313ee7fb` |
| Service unit | `df58418162abcc539103453345c889d6b133f153935d15ad6a3251020826a033` |

모델은 기존 RF/LR 고정 Artifact이며 SHA는 이전 기록과 같다. 새 모델·새 Feature 정의는 없다.
증거: 공통 Git 디렉터리 `.git/continuous-native-attestation-20261028T234603Z/`.
최종 Source/build identity, Fixture 결과·Audit, 현재 PCAP 서비스 결과·Audit를 보존했다.

## 실제 Kernel 검증에 필요한 조건

1. 변경된 파일/Source SHA·Runtime·Namespace·lo·capability·자원 제한을 대상으로 한 별도
   Continuous 서비스 설치/시작 Approved Update. 이전 Diagnostic 영수증은 사용할 수 없다.
2. 실제 Kernel attach/detach·per-CPU Counter·clock·ring drain·재시작·소유 자원 Cleanup 검증.
3. 봉인된 적격 Native Window의 기존 action-specific 모델 실행 승인. 이는 자동 발급되지 않는다.
4. 트래픽을 생성한다면 별도 정확한 R2/Root Scope 승인. 이 서비스는 DNS를 생성하지 않는다.

Continuous Native AI는 코드상 연결됐으나 실환경 E2E VERIFIED는 아니다. 실제 Root·Native·DNS·
Namespace 진입·Host 인증 로그·API 호출·예약·영수증 소비는 수행하지 않았다.
Ledger 81행과 SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` 유지.
Campaign Root 12/Native 4, Batch 3 Root 9/Native 1 이력과 기존 OBSERVE_ONLY/운영 한도를 보존했다.
Host `net:[4026531833]`, SOC inode `4026532232`는 비권한 조회만 수행했다.

---

## 이전 통합 이력 (이하 당시 보고 보존)

# Continuous Runtime 장시간 자율 통합 결과 — 2026-10-28

**판정: Offline/저장 증거 기반 통합 검증 완료. Native Continuous AI는 NOT_READY.**
TCX 서비스 운영 코드와 빌드 경로를 구현했으나 활성화하지 않았다. 실제 Kernel 수집 검증과
Continuous capture attestation → 모델 action 승인 연결은 아직 구현·검증이 필요하다.
따라서 다음 출근 시 승인만 받으면 전체 Native AI가 동작하는 상태라고 선언하지 않는다.

운영 코드: `0b3bbd9`, `1dd5121520f542dfd1954309b76970b5768cc903`.
후자 Tree: `3f57c83b8434d66f4f210ffd764eea4615a50c7a`.
실행·중지·복구 절차: [Continuous 운영 안내](continuous-runtime-operations.md).
아래 이전 보고는 당시 검증 이력으로 보존한다.

## 실제 구현한 경로

- 독립 TCX BPF/provider/Root service와 일반 사용자 socket producer를 구현했다.
  승인된 기존 Namespace·lo만 허용하고, Root 소유 설치 attestation·파일/Runtime SHA·peer UID·
  capability·cgroup 자원 제한을 검증한다. 범용 명령이나 setns 실행 기능은 없다.
  Root 서비스는 GUI 연결 종료와 독립적이며 소유자 STOP_CAPTURE와 제한된 Cleanup ACK를 제공한다.
  서비스는 설치·활성화되지 않았다. 기존 Phase D의 4,096 이벤트/300초 계약은 변경하지 않았다.
- Kernel monotonic 이벤트를 기존 ordering/window 추출기에 연결했다. Capture 증명이 없는
  Native window는 UNKNOWN/INCOMPLETE이며 모델 호출을 차단한다. UTC로 임의 변환하지 않는다.
- 저장 journal transport/cursor와 기존 Authentication parser·5분 feature extractor·실제
  IsolationForest를 연결했다. 종료 watermark가 없는 입력은 추론하지 않는다.
  Host journal 수집기는 자동 생성하지 않는다. 새 모델이나 feature 정의는 만들지 않았다.
- 원본 입력+cursor 원자적 저장, 재시작 replay/dedup, auxiliary 인증 queue, Native segment
  무결성, quota 실패, quiescent archive/새 디렉터리 restore를 구현했다.
  기존 v1 디렉터리는 보존하고 새 Runtime은 fresh v2 디렉터리를 요구한다.
- 기존 AI subprocess·fusion·Incident·SCRIPTED 조사/읽기 전용 도구·평가·Audit을 재사용했다.
  GUI는 domain·eligibility·Prediction·Incident 상세를 실제 Backend 결과에서 조회한다.
  GUI 종료는 독립 Collector 서비스를 종료하지 않는다.

## 비권한 E2E 증거

| 경로 | 입력/모델/조사 | 결과 |
|---|---|---|
| Packet | 실제 저장 IoT23 PCAP / 실제 RF·LR / Offline | 498 records, 233 packets, 116 windows, Prediction 10, Incident·Audit 5 |
| Authentication | 저장 Synthetic 인증 42건+watermark / 실제 IF / SCRIPTED | Prediction 1, Incident·조사·Audit 1 |
| Crash recovery | 일반 사용자 서비스 SIGKILL 후 재시작 | committed raw 11건 복구, 중복 11건 식별, 인증 unique 42건 유지 |
| Worker failure | 분석 자식 Exit 17 | Collector 유지, queue 보존, circuit/명시적 복구 후 처리 재개 |
| DNS | 저장 Transaction/Fixture | provenance·queue·Audit 계약 검증; DNS9 추론 차단 유지 |
| GUI | 실제 Tk와 실제 Offline 모델 결과 | 상세 조회, domain 표시, 종료·재연결 검증 |

Packet queue 포화에서 drop 107, DONE 5, PENDING 4를 기록했다:
`107 + 5 + 4 = 116 windows`. 손실 없는 처리나 장기 운영 처리량을 입증한 결과가 아니다.
위 Packet 실행과 인증 실행은 후속 Root 전용 제한/보관/GUI 보완 이전의 비권한 기능 실행이며,
최종 Source는 아래 회귀·독립 Export와 재현 빌드로 검증했다.
실제 API 호출은 0회이며 새 LLM 조사는 SCRIPTED다. 기존 실제 API 증거와 구분한다.

증거(공통 Git 디렉터리):

- `.git/continuous-stream-tcx-compatible-20261028T105254Z/`: PCAP/실제 모델 결과.
- `.git/continuous-runtime-autonomous-20261028T104506Z/`: 인증/강제 종료/복구 결과.
- `.git/continuous-autonomous-release-20261028T114636Z/`: 최종 SHA, 빌드, 검증 로그.

## RCA와 검증 범위

- retain-before-seen 중단 시 unique 계측이 증가하던 문제를 durable replay 식별로 수정했다.
- Native 후보의 필수 관측 시각 누락은 `None`으로 명시했으며 Kernel 시계를 UTC로 위조하지 않았다.
- 저장 실패가 소유 분석 자식/socket Cleanup을 건너뛰던 경로를 정리하고 최초/후속 오류를 분리했다.
- 인증 producer poll 취소 완료 전에 STOPPED/backup이 가능하던 경로는 poll 완료를 기다리도록 했다.
- 부분 기록·SHA/namespace 불일치·disk quota·checkpoint 손상·중복·worker 실패·owner STOP ACK 실패를
  비권한 테스트로 검증했다. Root peer/cgroup/설치 경계는 Mock이며 실제 권한 실행 성공이 아니다.

동결 Source 기준 Workspace **332 PASS**, 독립 Export **332 PASS**.
후속 제한/보관/GUI 변경은 집중 회귀(29 PASS, 보관 수정 후 단일 재검증 PASS, GUI 2 PASS)와
최종 독립 Export **31 PASS**로 검증했다. 서로 겹치는 테스트를 합산하지 않는다.
전체 332개를 마지막 소규모 변경 후 다시 실행한 결과로 표기하지 않는다.
Ruff check·format(1,467 files)·git diff --check 통과.
장시간 검증은 5,000 이벤트/모의 event-time이며 실제 수일 wall-clock 운영 soak가 아니다.

## 최종 Source·Artifact Identity

| 항목 | SHA256 |
|---|---|
| Source snapshot (651 src files) | `f1216e52262a47e3304536541041ed23044febd0f47ce26603abf71b09c240b3` |
| Wheel Workspace/Export 동일 | `eaba18afb8334402f242171ae37cc3a87df01ebf76a517c3e454b3dce7fdd070` |
| continuous.bpf.o | `a5e249726ac00966679b2b0c9360825e69ec9da64e44cf360d0a1ea608fa7548` |
| provider.so | `390324119ebbaed8f40d1f2678411e38398c32bbe1315b37d396a93f2d883edd` |
| Root service.py | `1b05588a74b32c6ea16582d999a373cdde5a9e1ab3e599e8facdb93896e69090` |
| Installation validator | `cb050423f29747e7b0ab96b89248ad5893eea1e8c9c8bb24edc1f0c5585b3d53` |
| Runtime identity | `431f2854bdd2c515f47ad60784263b1446305b1b515108ab5a898aef313ee7fb` |
| Service unit | `df58418162abcc539103453345c889d6b133f153935d15ad6a3251020826a033` |
| RF | `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` |
| LR | `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882` |
| Authentication package manifest | `aabeb76277534d9300f70699dfddb84214720add607ef1d17b4c0e34e084b5f6` |

Workspace/독립 Export Native 산출물 **6/6 동일**, Wheel도 byte-identical이다.
이는 비권한 빌드 증거이며 설치된 실행 권한이나 신규 Root Manifest/실행 영수증이 아니다.

## 보존·남은 작업

Ledger **81행**, SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` 보존.
Campaign Root 12/Native 4, Batch 3 Root 9/Native 1 이력 보존.
기존 개발 OBSERVE_ONLY와 운영 Root 한도는 변경하지 않았다.
Host `net:[4026531833]`, 기존 SOC inode `4026532232`는 비권한 조회로 확인했다.
실제 Root/Native/DNS/Host 인증 로그/API 호출, 예약·영수증 소비·Ledger 변경 모두 0회다.

Native Continuous를 위해 남은 최소 작업은 다음과 같다.

1. 독립 서비스 설치/권한/Namespace/자원 정책의 인간 Approved Update와 고정 Runtime 설치.
2. 실제 Kernel attach·counter·clock·flow 종료·drain·소유 자원 Cleanup 검증.
3. Continuous capture attestation과 모델 action 승인 연결 구현·회귀. 현재 Native 모델 허용은 false다.
4. 실제 DNS Sidecar Continuous 연결과 Host 인증 transport의 별도 읽기 권한 검증.
5. 별도 승인된 Live 환경의 부하·저장 기간·장애 soak 검증.

현재 Offline 시연과 저장 인증 AI·조사·GUI 통합은 가능하다. Native Continuous 실환경 운영 및
Native AI E2E VERIFIED/RELEASE_READY는 선언하지 않는다.

---

## 이전 검증 이력 (이하 원문 보존)

# Continuous Runtime 통합 검증

검증일: 2026-10-28, WSL Ubuntu, 일반 사용자. 브랜치 `feat/continuous-runtime`.
기준 GUI 통합 `f9bac1074552418120b7ddb88f6f81c9fab2f619`에서 별도 worktree로 개발했다.

**판정: Replay 서비스 구현·실제 모델·GUI 검증 완료 / Native Continuous 운영 전환 미완료.**
상시 TCX producer/transport는 아직 구현되지 않았다. 이는 승인만 받으면 실행할 수 있는
상태가 아니다. 기존 Native 진단, Offline 시연, Linux 인증 감시를 보존했다.

## 구현한 운영 경로

```text
PCAP parser subprocess / explicit JSONL replay
 → sequence / identity / clock checks
 → reused StreamingFlows (30s idle / 120s active)
 → PacketWindowJob + expiry witness
 → persistent bounded EventQueue
 → isolated ordinary-user analysis subprocess
 → existing pinned Network14 producer / RF / LR
 → existing fusion / Incident / read-only response / SCRIPTED investigation
 → verified outcome + audit
 → independent service status / GUI attachment
```

`src/soc_agent/continuous/`는 별도 프로세스의 start/run/status/stop/reset-worker,
단일 실행 잠금, heartbeat, 소스 pin, 코드 SHA pin, 저장 한도, durable queue,
손실 계측, 실패 circuit, 종료 drain을 구현한다. Collector task와 AI task는 분리되며
모델 오류가 Collector를 종료하지 않는다. GUI는 일반 사용자 Application Backend를
통해 서비스를 조작하고, GUI 종료는 이 서비스에 Stop을 보내지 않는다.

새 모델·Feature 정의·LLM 프레임워크·예산/승인 시스템은 만들지 않았다.
Packet Window는 기존 LiveRequest/producer/receipt와 OfflineWorkflow에 연결했다.
`OFFLINE_PCAP` provenance를 실제 producer 계약에 맞춰 보존하고 Native gate는 유지했다.
중복 Event ID의 내용 변경은 거부하고, 동일 내용의 다른 전송 sequence는 중복으로 계측한다.

EOF/Stop/clock/source gap으로 닫힌 Flow는 INCOMPLETE다. 실제 후속 이벤트로
30s/120s 종료를 관측한 window만 offline eligibility를 심사한다. 이것은 Native P02/P03
attestation이 아니다. UNKNOWN/INCOMPLETE/INVALID 또는 model schema 불일치는 추론하지 않는다.

## 실제 데이터 검증

모든 아래 실행은 **REAL_OFFLINE / REAL_MODEL**이다. Root, socket traffic, TCX는 없다.
기존 IoT23 PCAP SHA:
`80dcc2602519479ddcde889fa902fee19a76696630811452f8df38888af894f2`.
별도 parser 검증에서 원본 23,623 record를 읽었다. 아래 서비스 실행은 전체 파일 분석이
아니라 운영 Start/Stop과 bounded handoff를 검증하기 위한 중도 Stop이다.

| 항목 | 모델 연결 수정 후 기능 실행 | 최종 Source freeze 실행 |
|---|---:|---:|
| 입력 record | 1,810 | 829 |
| parsed Packet | 1,158 | 469 |
| 제외 record | 652 | 360 |
| Flow window | 336 | 172 |
| offline metadata ELIGIBLE | 334 | 170 |
| INCOMPLETE | 2 | 2 |
| AI queue drop | 326 | 165 |
| 실제 RF/LR Prediction | 12 | 6 |
| Incident·검증된 Audit | 6 | 3 |
| 종료 시 durable PENDING | 4 | 4 |
| 모델 오류 | 0 | 0 |
| Stop / owned process cleanup | VERIFIED | VERIFIED |

첫 성공 실행은 NORMAL 5개와 UNKNOWN_ANOMALY 1개를 생성했다. 미분류 이상은 기존
읽기 전용 조사·평가·Audit으로 이어졌으며 planner는 **SCRIPTED**다. 최종 freeze 실행의
3개 Incident는 NORMAL이다. 실제 API 호출은 **0회**다. 과거 실제 API E2E 증거는 보존하되
이번 Continuous 서비스의 실제 LLM 검증으로 재사용하지 않는다.

큐 크기를 4로 둔 의도적 포화에서 손실을 모두 기록했다. 최종 실행의
`3 DONE + 4 PENDING + 165 dropped = 172 windows`가 맞는다. 이는 lossless 처리나
운영 처리량 보장이 아니다. 중도 Stop에서 남은 4개 입력은 삭제하지 않았다.
서비스 자체 peak RSS는 최종 실행 170,921,984 bytes이며 전체 자식/cgroup 합계가 아니다.

증거:
- `.git/continuous-runtime-20261028T100000Z/`: 최초 Schema 실패 보존.
- `.git/continuous-runtime-verified-20261028T100700Z/`: 실제 Prediction 12개 실행과 이중 빌드.
- `.git/continuous-runtime-final-20261028T100540Z/`: 최종 source의 실행, 상태·입력·결과·Audit.

## RCA / 회귀

확인한 결함을 실제 Entry Point 검증으로 수정했다.

- Gap 종료에 기존 FlowSummary가 허용하지 않는 문자열을 사용하던 경로를 기존
  RESTART_GAP/PACKET_LIMIT 계약으로 연결했다. 상세 최초 오류는 서비스 audit에 보존한다.
- 새 증거의 integrity 값이 기존 EvidenceEnvelope enum과 맞지 않아 모델 호출 전
  ValidationError가 발생했다. 기존 REPLAY_VERIFIED/FIXTURE를 사용하고 window quality는
  별도 provenance로 보존했다. 실패 결과는 덮어쓰지 않았다.
- PCAP helper의 512MiB virtual memory 제한에서 기존 scientific import가 실패했다.
  기존 research footprint에 맞춘 3GiB AS, 60 CPU-second 제한과 thread 1개를 적용했다.
  기존 Native 진단의 256MiB 정책은 수정하지 않았다.
- 최종 evidence flush 실패도 owned AI process cleanup을 건너뛰지 않도록 했다.

Workspace 관련 회귀 **290 PASS**. 독립 Export는 **282 PASS**, Git identity가 필요한
Controller admission 8건은 Git 메타데이터 없는 Export에서 setup error가 발생했다.
Export 자체를 독립 Git snapshot `fa5c675ec128eeaf01788bc0a007353b2ad7aaba`으로 고정한 뒤
그 **8건 PASS**를 확인했다. 검증 조건·Assertion을 완화하지 않았다.

범위: 새 서비스/quality/clock/gap/dedup/queue/recovery, 실제 RF/LR 및 outcome Audit,
실제 Tk Start·재연결·GUI close·중복 Start·Stop, 기존 GUI/Offline/RawDNS/TCX AI,
Controller admission·요청 진단·R1/R2, 기존 Flow 및 모델 계약.

5000 synthetic record를 처리해 4096 diagnostic event cap을 서비스 권한으로 전용하지
않음을 확인했다. 별도로 synthetic event-time 약 5시간/600 Packet/599 eligible window,
bounded Flow state와 정확한 queue drop을 검증했다. 실제 5시간 wall-clock 또는 Native
soak를 수행한 것은 아니다. Worker 실패→POISON→circuit, Collector 제한 재시작→circuit,
변경 SHA·부분 source·오래된 heartbeat·Native authority 차단을 검증했다.

Ruff / Format(1454 Python files) / Diff PASS. Workspace·독립 Export source 일치.
각각 생성한 Wheel은 byte-identical이며 staged Wheel에서 CLI import/help도 PASS다.

## Identity 및 보존

구현 Commit: `a7fa22acbecc7ec71c19b1784c7d2ef6211db25c`.
구현 Tree: `ef93e17b12b396e295ccd70edf4bbd7eac34b36c`.
Source snapshot (633 .py/.json/.c/.h 파일 경로·SHA map canonical JSON):
`ae5bbe0787635169efd830197d27237a9368575d8139f7c1d18494b1f2892f17`.
Wheel SHA256:
`4a17db6e75c056ff462d34d1bf25b559c382db4d581a0affcbce37a93164b7cc`.

RF Artifact: `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603`.
LR Artifact: `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882`.
각 실제 receipt에 Feature fingerprint, model manifest/version, input/source digest,
예측·지연·evidence reference가 기록됐다. 새 Native Bundle/Execution Image/Root Manifest나
정책 영수증은 발급하지 않았다. Replay Wheel은 Root 실행 승인 대상이 아니다.

기존 실행 Ledger **81행**, SHA
`07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` 불변.
Campaign Root12 / Native4, Batch3 Root9 / Native1 불변. 신규 Root/Native/DNS/API 0회,
예약·영수증 소비 0회. 기존 설치·Rollback·FAILED·false·UNKNOWN을 변경하지 않았다.
Host `net:[4026531833]`와 `/run/netns/soc-native-b3` inode `4026532232`를 비권한
stat/readlink로 확인했다. Namespace 진입/변경은 하지 않았다. 고정 Native worktree도 clean이다.

## 운영 전환에 남은 작업

1. 상시 TCX producer와 인증된 최소 권한 transport를 구현·검증해야 한다.
   현재 `NATIVE_SERVICE`는 fail-closed다. 기존 진단을 반복 호출하는 방식으로 대체하지 않았다.
2. 기존 LinuxAuthenticationCollector/runtime은 보존·상태 attach한다. 공통 상시 Packet/DNS/Auth
   collector로의 live event 통합은 아직 미완료다. 저장 Raw DNS/Auth job은 기존 파이프라인을 재사용한다.
3. Native Continuous service 설치·권한·Namespace/interface·IPC·자원·복구 계약에 대한 별도
   §33 승인과 실환경 검증이 필요하다. 기존 진단 승인/R1/R2를 전용할 수 없다.
4. 지속 저장 archival/rotation 및 처리량 튜닝, 실제 장시간 soak, cgroup 전체 자원 검증,
   권한 분리 후 Native eligibility·AI E2E 검증이 필요하다.
5. 새 서비스에서 실제 생성형 LLM은 미검증이다. 별도 API 사용 계약과 어댑터 연결이 필요하다.
   DNS9는 학습 추출 계약 미확보로 계속 INCOMPLETE다.

실행·중지·복구와 uninstalled user-service unit 설명은
[Continuous Replay Runtime](continuous-replay-runtime.md)에 있다.
**Offline DEMO 경로 유지 / Continuous Replay 검증 / Native Continuous NOT_READY**다.

## 2026-10-29 승인된 TCP 제한 시험 — BLOCKED

승인된 기준 `f1d4dc3`와 Source 652개, Runtime, Namespace lease, Ledger 81행,
고정 Helper/Unit SHA를 자동 대조했다. 사용자 터미널에서 Scope `yes` 및 sudo 인증을
받은 뒤 고정 파일 설치와 Collector 서비스 시작을 **1회** 시도했다. 자동 재실행하지 않았다.
증거: 공통 Git 디렉터리 `continuous-tcp-approved-20261029T002200Z/`.

| 실환경 항목 | 결과 |
|---|---|
| Namespace 내부 사전 검사 | PASS: `net:[4026532232]`, ifindex 1 / lo UP, 외부 Interface·Route 없음 |
| Socket Namespace Cookie | Target 8855 / Host 3; 내부 TCP/UDP Socket 목록 비어 있음 |
| 고정 파일 설치 | Collector 파일·설치 정책·240초 drop-in 및 보충 승인된 Helper/Unit SHA 대조 완료 |
| 승인된 포트 | 사전 조회에서 18080·18081·18082 미점유; 대체 포트 사용 없음 |
| Collector | 09:24:42 KST 시작, 09:24:43 종료; 실제 서비스 exit 1 |
| TCP Helper | Collector READY 전 실패로 시작하지 않음; 연결·요청·응답 모두 0; 35초 간격 검증 미실행 |
| Packet / Window / ELIGIBLE | 각각 0 / 0 / 0; Attestation 입력 없음 |
| 실제 Native RF/LR / Prediction / Incident | 각각 0 / 0 / 0; 모델 Action 미발급 |
| GUI Native 결과 | 제공할 실제 수집·분석 결과 없음; LIVE VERIFIED로 표시하지 않음 |
| DNS / LLM / DNS9 | 실행 없음; DNS9 INCOMPLETE 보존 |
| Stop / 소유 자원 | systemctl stop exit 0, 서비스 cgroup 비어 있음, 소유 socket 제거; Root Audit의 SERVICE_STOPPED cleanup VERIFIED |
| 전역 Kernel 비교 | UNVERIFIED: `/usr/sbin/bpftool`이 현재 WSL Kernel용 실행 파일을 찾지 못해 전·후 조회 모두 exit 2 |

최초 원인은 libbpf의 `BTF is required, but is missing or corrupted`다.
`Provider.__init__ → continuous_open → bpf_object__open_file`에서 객체 해석이 실패하여
`CONTINUOUS_TCX_ATTACH_FAILED_NO_RETRY`로 종료했다. 실제 BPF load/attach 성공 증거는 없다.
바깥 실행기는 `ROOT_SERVICE_EARLY_EXIT`, terminal exit 1로 후속 실패를 별도 보존했다.
Apport의 `/var/crash` 읽기 전용 오류는 원래 예외 이후 발생한 후속 오류이며, 보안 설정을
완화하지 않았다. 과거 Program 1145 UNKNOWN·Cleanup UNVERIFIED·FAILED/false는 그대로다.

### 비권한 최소 수정

BPF Source의 BTF `.maps` 선언과 달리 빌더가 `clang -g0`를 사용하여 `.BTF`를 제거했다.
원래 객체의 libbpf userspace open 실패를 Root·Kernel 호출 없이 재현했다. 빌더만 `-g`와
고정 debug 경로로 변경하고, 모든 빌드에서 실제 `bpf_object__open_file` 파싱 성공을 요구하도록
보강했다. 이 검사는 `bpf_object__load`나 TCX attach를 호출하지 않는다. 손상 ELF 거부와
실제 BTF 객체 파싱을 기존 재현 빌드 회귀에 추가했다. Namespace·권한·트래픽·적격성 계약은
변경하지 않았다. 설치된 승인본이나 원본 실행 증거를 수정하지 않았다.

수정본 비권한 빌드(미설치):

- Source: `ca4a3f1ad9c45ede054148fb1b6bb38dcc8f2318b57db7fd21ec27ec4d559bfa`
- BPF object: `408744c24580f4d643a4235cb581409b3ee669092e1a902d99bbf938b3221ac8`
- Wheel: `f02ea8360130bf32621760c2fea9ae3c16a4e7709eba9bb566bc377a2bc754f6`
- 독립 Export와 Workspace Native 6/6 SHA 및 Wheel SHA 동일.
- Provider·Service·Policy·Runtime identity·Unit SHA는 기존 승인본과 동일하다.

Legacy Ledger는 81행 / `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`
그대로다. 기존 Campaign Root 12·Native 4 / Batch 3 Root 9·Native 1 기록을 환급하거나
초기화하지 않았다. 이번 별도 Continuous 서비스 시작 시도 1회는 인간 결정·설치 SHA·Root
Audit·terminal exit에 기록했으며, 이를 Legacy Diagnostic 예약 또는 예산 소비로 가장하지 않았다.

현재 판정은 **BLOCKED**다. 수정본은 userspace 파싱과 빌드만 검증됐으며 Kernel 성공이 아니다.
다음 시험에는 새 BPF/Source Binding, 미소비 실행 승인, 기존 설치 보존 교체 계획, 정상 TCP
Scope, 사용자 확인·sudo가 필요하다. 현재 1회 승인을 재사용하거나 자동 재실행하지 않는다.
실제 봉인 Window와 적격 job이 확보된 후 별도의 exact model Action 승인이 필요하다.

修复回归：Workspace / 独立 Git Export 各 **66 PASS，2 deselected**。范围包含 Capture
Attestation、模型 Action 拦截、Fixture 实际 RF/LR、Queue/Worker、Transport、Root 服务边界
及 BTF 用户态解析。未重跑 5,000 事件和 multi-hour 两项长时压力测试，不宣称全量回归。
首次批次使用过长的证据目录作为 pytest basetemp，Unix socket 测试触发 AF_UNIX 路径上限；
另一个“未安装”测试依赖本机确实没有安装策略。日志保留，长时批次中止后换短 `/tmp` 路径，
并将该测试的缺失策略路径显式隔离，原拒绝断言不变。最终双环境上述 66 项全部通过。
Ruff 全仓检查、Format（1,469 files）、Diff 均通过。新的 BTF 构建与测试均没有 Kernel load、
权限提升、TCP/DNS 发送或 Native 模型 Action。Fixture 模型测试不计入 Native 成功。

## BTF 수정본 재시험 준비 — 2026-10-29

운영 코드 `36c2eccc6b2e3fb4539720328f9383b1e906a29b`를 기준으로 비권한 검증을 수행했다.
새 Root/TCX/TCP/모델 실행, 예약, 영수증 소비 및 기존 Ledger 수정은 없다.
검토 패키지: 공통 Git 디렉터리
`continuous-btf-retest-review-20261029T003500Z/approval-package.md` 및 `approval-request.json`.

- 실제 빌더는 BPF에 `-g`, 고정 file-prefix/debug-compilation 경로를 사용한다. Provider C의
  `-g0`는 변경하지 않았다. 새 Object에 `.BTF`·`.BTF.ext`가 있고, libbpf userspace open 및
  고정 bpftool의 **Object 파일** BTF dump에서 events/config/counters 타입을 검증했다.
  Kernel load/attach는 수행하지 않았다.
- 새 디렉터리의 Native 빌드 6개 SHA가 직전 Workspace/독립 Export 수정본과 전부 일치한다.
  BPF SHA `408744c24580f4d643a4235cb581409b3ee669092e1a902d99bbf938b3221ac8`,
  Source SHA `ca4a3f1ad9c45ede054148fb1b6bb38dcc8f2318b57db7fd21ec27ec4d559bfa`.
- 설치된 실패 Object는 여전히 `a5e249…7548`이며, 서비스·정책·Runtime·Helper·Unit과
  설치 정책의 모든 기존 SHA도 일치한다. 수정본을 설치하거나 이전 파일을 덮어쓰지 않았다.
- 과거 Diagnostic Supervisor `88dfad10…20a`, Controller `d1f1e0e4…bbc`, Root Manifest
  `e40ebd24…11f`와 Root 파일 9개·Controller Python 124개 파일을 실제 SHA로 대조했다.
  이들은 과거 자료의 무결성 확인이며 Continuous 실행 권한·실행 이미지로 재사용하지 않는다.
  실제 Continuous 경로는 고정 systemd Collector와 일반 사용자 Runtime이다.
- Continuous release identity는 설치 파일 SHA map의 canonical digest이며 `soc-continuous-seal:v1`
  계약을 사용한다. 새 Capture Session은 승인된 서비스에서 실제 generation 생성 후
  `UUID5(NAMESPACE_URL,str(generation))`로 결정된다. 아직 존재하지 않는 Session을 임의로 만들거나
  과거 Diagnostic Session/Release 0.6.3을 대신 사용하지 않았다.
- Target dev4/inode4026532232·Host4026531833·boot·lease SHA·Ledger 81행 SHA가 일치한다.
  이번 Namespace 내부 check는 권한 승인을 기다리며 과거 PASS와 구분한다.
- `/usr/sbin/bpftool` wrapper 대신 실제 파일
  `/usr/lib/linux-tools/6.8.0-147-generic/bpftool`을 찾아 버전/파일 BTF dump와 SHA를 검증했다.
  새 승인 범위에는 이 고정 도구를 이용한 읽기 전용 Kernel link/prog/map 전·후 조회를 포함한다.
  현재 전역 Kernel Cleanup UNVERIFIED 이력은 변경하지 않는다. 사전 조회 실패/기존 lo hook 충돌은
  Capture 시작 전 차단하며 기존 프로그램을 제거하지 않는다.

재시험 요청은 **새 BPF와 승인 후 재결합할 설치 정책만** 백업 후 고정 경로에서 교체하고,
나머지 승인 파일은 SHA 검증 후 유지하는 범위다. 기존 설치본·정책·Root Audit를 백업/보존한다.
기존 240초, Root 128MiB/CPU25%/Tasks4, per-CPU/minute quota·Window 제한 및 고정 TCP
18080 ← 18081/18082, 연결 2회·35초 간격·고정 payload·일반 사용자 Capability 0을 유지한다.
만료 시각은 승인 기록 후 최대24시간 및 검토한 상위 유효기간 이내에서만 확정한다.
최종 설치 정책의 인간 결정 hash·만료·정책 SHA는 새 인간 승인 전에는 발급하지 않는다.

다음 승인 후 검증할 것은 Kernel load → 소유 TCX link → Collector/Producer READY → TCP 2회
→ 실제 Counter/Clock/Window 봉인 → Attestation → Network14 Eligibility → 정상 Stop/Drain/
소유 자원 및 전역 Kernel 전·후 비교다. 각 단계 최초 오류와 실제 exit를 보존하고 자동 재실행하지
않는다. 모델·DNS·외부 API 권한은 포함하지 않는다. 판정은 **READY_FOR_REVIEW / KERNEL_PENDING**이며,
기존 실패 시작 1회 승인을 재사용할 수 없다. 적격 Native job이 생긴 뒤 별도 모델 Action을 검토한다.

## 자율 복구 세션 — Kernel verifier 재시험 및 확인된 문제 전면 수정

승인 요청 `60b6f02f…731847`의 Git/Source/파일/Ledger Binding을 다시 대조하고 사용자
`승인함`을 기록했다. 사용자 터미널 Scope yes·sudo 인증 후 기존 BPF와 설치 정책을
Root 전용 백업에 보존하고 승인된 BTF Object만 설치해 **시작 1회**를 시도했다.
증거: 공통 Git 디렉터리 `continuous-btf-retest-approved-20261029T004325Z/`.

### 이번에 확인한 문제와 수정 결과

| ID | 문제 / RCA | 실제 수정과 검증 | 상태 |
|---|---|---|---|
| P01 | `-g0`로 BTF 누락 | 앞선 `36c2ecc` 수정 유지; BTF section·libbpf parse·재현 빌드. 이번 Kernel 로그에서 BTF 누락은 재발하지 않음 | 코드 수정 및 재시험에서 기존 오류 해소 확인 |
| P02 | Kernel verifier `R2 variable stack access prohibited for !root` | 공유 parser가 가변 IPv4 IHL/VLAN transport offset으로 128-byte **스택** header를 참조. Continuous만 고정 per-CPU 임시 buffer map(1개 key, CPU당128 bytes)으로 교체, 파싱/복사 실패 직후 모두 지움. metadata ABI와 parser는 유지; Capability·CPU·메모리 한도 확대 없음 | Host의 실제 ingress C 동작 검증; 새 Object Kernel verifier는 PENDING |
| P03 | Native C 실패 원인이 무조건 EPERM으로 덮임; Python은 errno 없는 ValueError | Cleanup 직전 최초 errno 보존, Cleanup 실패 EUCLEAN 우선은 유지. Python OSError에 errno 전달. 실제 C 실패/정리 경로를 Host harness로 실행해 EACCES 보존, Python의 EACCES/ENOMEM/EIO/EUCLEAN 검증 | 비권한 검증 PASS |
| P04 | 인증된 STOP ACK 이후 socket이 닫히면 일반 Runtime Stop이 실패 | 수신 경로에서 binding 검증된 stop_ack만 사용하여 idempotent Stop. ACK 없는 단순 VERIFIED 문자열, UNKNOWN/UNVERIFIED는 거부. 재접속 시 과거 ACK 초기화 | 실제 Unix framing + 경계 Mock 검증 PASS |
| P05 | 모델 Action 대기 중 정상 Stop을 미확인 Worker 장애/Cleanup 실패로 오분류 | 사용자 Stop·승인 대기 상태·모델 자식 미시작 조건을 모두 만족한 취소만 정상 대기 종료로 분류. 예기치 않은 취소는 UNKNOWN 유지. 입력은 보존하고 Queue POISON으로 자동 추론 재실행 차단 | 운영 Runtime.run 경로 검증 PASS, 모델 호출0 |
| P06 | GUI의 단일 Cleanup 표시가 ordinary Runtime과 Root Collector 상태를 혼동시킴 | snapshot과 실제 Tk 화면에 Runtime cleanup / Collector cleanup 분리. Replay는 NOT_APPLICABLE_REPLAY, Root 증거 없으면 UNKNOWN, Root UNVERIFIED를 승격하지 않음 | 실제 Tk 종료/재연결·결과 표시 검증 PASS |
| P07 | Apport가 읽기 전용 `/var/crash`에 쓰려다 최초 오류 뒤에 추가 예외 발생 | 고정 서비스 프로세스의 excepthook만 Python 표준 handler로 지정. 원래 traceback 보존. 시스템 패키지·read-only sandbox 변경 없음 | 일반 사용자 실제 entry subprocess 거부/진단 검증 PASS |
| P08 | `/usr/sbin/bpftool` wrapper로 전역 전후 조회 불가 | 기존 설치된 고정 executable의 SHA를 검증해 읽기 전용 조회. 새 도구 설치·권한 추가 없음 | 이번 실제 Root 전후 link/prog/map 조회 모두 성공·동일 |

P04/P05는 수정 전 Git Export에서도 새 회귀로 재현해 **2 FAIL**을 고정했고, 수정본은 통과했다.
C ingress harness는 실제 `continuous.bpf.c`를 Host로 컴파일하여 helper 경계만 Mock한다.
IPv4 기본/최대 IHL+2 VLAN, IPv6, TCP/UDP metadata, copy 실패와 ring reserve 실패의
Counter 보존 및 header bytes 삭제를 검증했다. 이 Host 실행을 Kernel verifier 성공으로 간주하지 않는다.
임시 buffer는 packet bytes를 파일/이벤트로 보관하지 않고 파싱 직후 지운다. 추가 map은
기존 소유 object Cleanup에 포함하며 자원 상한은 그대로다.

### 실제 재시험 결과 — BLOCKED

- Namespace 내부 check PASS: target4026532232 / lo UP / 외부 interface·route 없음.
- 09:46:00 KST Collector 시작 → BPF program load에서 verifier 거부 → 09:46:01 종료 **exit 1**.
  로그에 첫 verifier 원인과 Python/바깥 launcher의 후속 오류가 별도 보존됐다.
  Root UID라도 승인된 제한 Capability 환경에서는 위 가변 스택 접근을 허용하지 않았으며,
  이를 해결하기 위해 권한을 추가하지 않았다.
- TCX attach/Collector READY 없음. TCP Helper 시작0, 연결0, packet0, Window0,
  Attestation 입력 없음, Network14 ELIGIBLE0, 실제 Native RF/LR/Prediction/Incident0.
  Native GUI 결과 없음. DNS·외부 API 호출 없음.
- Root Audit hash chain 검증 및 소유 Cleanup VERIFIED. 새 고정 bpftool로 조회한
  **이번 시험의** Kernel link/prog/map 전후 JSON은 모두 동일하다.
  과거 Program1145 UNKNOWN·전역 Cleanup UNVERIFIED·FAILED/false는 변경하지 않는다.
- Legacy Ledger **81행**, SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`
  불변. 기존 Campaign Root12/Native4 및 Batch3 Root9/Native1 기록은 초기화·환급하지 않았다.
  별도 Continuous 서비스 시작 시도는 첫 BTF 실패와 이번 verifier 실패로 각1회이며 각 실행 증거/Root Audit에 보존했다.

### 수정본 비권한 검증·릴리스 판단

Workspace / 독립 Git Export **각87 PASS**, 실제 Tk GUI **각2 PASS**.
기존 5,000-event/multi-hour 압력 테스트2개는 재실행하지 않았으며 전체 테스트 suite 통과로
표현하지 않는다. 실제 RF/LR·Auth IF·Incident/Audit 및 SCRIPTED 조사 경로는 기존 회귀에서
검증했다. 신규 Native 모델 Action이나 실제 LLM API 호출은 없다.
Native 산출물6개 및 Wheel의 Workspace/Export SHA 동일, Ruff·Format·Diff 통과.

- Source `02d58ab28dffd138c933271c841e7f9f6d927d6c0ab8aff62b8dbf7f9234d71f`
- 새 BPF `800a502f88a3f9a2c8a0d4feda8e60f9b2f0217c4b58cd82629c2da48487fa68`
- Provider `62e4610379f9dc3b8f2a5fb070009dfcdcdbf2c1a5a0f6d76c0c2a22b6296bff`
- Root Service `f43dc5eb7538566e3951e1ce91a291a0d0b98ef90e8681c9d5905cef4c1bb715`
- Wheel `3b3b8e290d0304c0752f83b03307203b86ea9ae52535cf846033082dae964336`

이 수정본은 **미설치·미실행**이다. 현재 설치본/새 백업/원래 Rollback/모든 실행 증거는 유지했다.
기존 시험 승인은 사용 완료이며 자동 재실행하지 않는다. 변경된 Root 파일3개와 새 Source에
대한 정확한 다음 시험 Binding을 별도 준비한다. 같은 Namespace·TCP2회·최대240초·기존 자원
범위를 유지하며 실제 모델 Action은 별도다. 문제의 코드 수정·비권한 검증은 완료했지만, 새
Kernel load/attach/Window/Eligibility 검증은 아직 남아 있다. Offline/Fixture 시연과 GUI 회귀는
보존되어 **DEMO_READY**, Native Continuous는 **BLOCKED / KERNEL_RETEST_PENDING**이다.

모델 대기 Stop 회귀에는 이전 분석 자식이 이미 정상 종료/정리된 경우도 포함했다. 완료된
process 객체가 남아 있어도 현재 job의 새 모델 실행으로 오인하지 않으며, 실행 중 자식이나
Cleanup UNVERIFIED 및 요청하지 않은 취소는 정상 종료로 승격하지 않는다.

## 추가 Kernel 재시험과 helper 기반 파서 복구

`072f58b`에 대한 정식 단일 재시험 승인은 사용자 터미널 Scope yes·sudo 인증 후 집행했다.
증거는 공통 Git 디렉터리 `continuous-verifier-retest-approved-20261029T011029Z/`에 보존한다.
기존 가변 스택 문제는 재발하지 않았으나 scratch map의 가변 offset에서 Kernel verifier가
`R1 tried to add from different maps, paths or scalars`로 거부했다. 최초 원인은 Kernel load
errno13이며 바깥 Producer READY timeout은 후속 오류다. 권한 부족으로 단정하거나 Capability를
추가하지 않았다. 실제 TCX/TCP/Window/Native 모델 호출은 모두0, Root·ordinary Cleanup은
VERIFIED, 이번 link/prog/map 전후는 동일, Root Audit chain과 Legacy Ledger81행은 불변이다.
이 결과는 과거 전역 Cleanup UNVERIFIED나 Program1145 UNKNOWN을 변경하지 않는다.

| ID | 확인된 오류 | 수정·검증 |
|---|---|---|
| P09 | scratch map의 가변 header pointer가 제한 Capability verifier에서 거부됨 | Continuous 전용 `packet_parser.h`에서 scalar skb offset + 고정1/2/4/16-byte helper destination으로 읽음. header cache/scratch map 제거. 기존 Phase D 파서는 그대로 두고 실제 C oracle과 정상·절단·변조 패킷을 비교 |
| P10 | Kernel load 전에 Unix socket bind가 먼저 실행되어 Root Socket READY를 잘못 알림 | 실제 Provider load/attach 성공 후 bind/listen. 운영 `run()`을 실행하는 권한 경계 Mock 회귀에서 attach 거부 시 bind/listen0·socket close·Audit·최초 errno 보존 검증 |
| P11 | 바깥 Launcher가 Root 조기 종료 후에도 Producer timeout까지 대기 | 다음 고정 단일 시험 recipe에서 Producer READY 대기 중 Root 자식 종료를 즉시 확인. 최초 Root 오류와 후속 outer 오류를 각각 보존 |

패킷 metadata ABI, parser admission/drop 판정, ring/counter/lease/Window, Namespace·TCP·자원·권한
상한은 유지한다. Host C 회귀와 BTF/libbpf 파일 parse는 실제 Kernel 검증과 구분한다.
새 Native 산출물6개와 Wheel은 Workspace/독립 Export에서 일치한다.

- Source653개 `32ec9c5da3747551ef6092d351d894065eb5b1fec92eab033855291a5bb6506e`
- BPF `da58d00289ce04a3c818f8ca5b776f1b2fccaaef9b96f324f60a24904bcde8f6`
- Root Service `9a259bf55d1d8f1d88b86860fdc9ac9986fefea0958cc1435d8788f28e372119`
- Provider `62e4610379f9dc3b8f2a5fb070009dfcdcdbf2c1a5a0f6d76c0c2a22b6296bff`
- Wheel `bf9a9a8e2154eec0d7fb0470077156ed4adbed5725a3ffe972d4a2f6feaa0449`

사용자의 새 `오류 다 해결하고 자동 재실행해라` 지시는 같은 제한 범위에서 수정본 추가 시험1회에
결합한다. 소비된 기존 승인 기록은 재사용하지 않고 새 Git/Source/파일/설치 정책·인간 결정으로
결합하며, 실제 사용자 터미널 Scope yes·sudo 인증은 유지한다. 자동 반복 루프는 없다.
Native RF/LR 모델 Action·DNS·외부 API 권한은 포함하지 않는다.

비권한 검증은 Workspace/독립 Export **각89 PASS·장시간 stress2개 deselected**, 실제 Tk GUI
**각2 PASS**, Ruff·Format·Diff PASS다. 최초 검증 실행의 테스트 환경에는 기존 모델 Interpreter
root 및 자식 PYTHONPATH가 빠져 모델/CLI 회귀가 실패했다. 실패 로그를 지우지 않고 보존했으며,
테스트 전용 기존 환경 root와 각 Source를 명시한 실행에서 모두 통과했다. 보안/모델 조건은
수정하지 않았다. 새 외부 API 및 승인되지 않은 Native 모델 호출은0이다.
