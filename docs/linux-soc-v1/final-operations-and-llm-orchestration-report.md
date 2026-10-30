# Final operations and LLM orchestration verification

## 2026-10-30 승인된 A/B 실제 실행 최종 결과

**최종 판정: PARTIALLY_VERIFIED.** A의 실제 Plan은 검증했지만 Assessment는 실패했다.
B는 실제 수집·모델·조사·GUI를 일부 검증했지만, 순수 수집 3,600초와 Runtime Cleanup을
충족하지 못했다. `LLM_ORCHESTRATION_VERIFIED`, `NATIVE_ONE_HOUR_VERIFIED`,
`OPERATIONS_VERIFIED`는 이번 시험에 부여하지 않는다. 기존 제한 시험의 성공 판정은 보존한다.

아래 실제 결과가 최신 판정이다. 문서 후반의 사전 검증 기록은 승인·실행 전 시점의 이력이며
현재 재실행 안내가 아니다. 승인된 API 2회와 Native 1회를 사용했다. 자동 재실행은 하지 않았다.

### 실제 실행 Binding 및 증거

- 실행 코드: `66814fcd6d987b50a3a77e92bbad484961d32852`, 보고 기준 HEAD: `29c0234`.
- 코드 Tree: `702eadfcb0ecdbb7896ca3424577a5e0f7c868f1`.
- Source digest: `2da026fb46fdd72ba66316190413c6f3a71ebd07dee1aef477864d0c2d9e4afd`.
- 승인 패키지 SHA: `5d8dc41fb4bcd00ac2b7f9eb35f77128545ec583142cc17fa9e3a70a507b6a74`.
- Root Manifest: `47be0e61d6fb6347bfcbf5b64a2a9055f175b95bc7b70a8fa731a44ac2fd6819`.
- 실행 Wheel: `76c082b6a279506dae34d3da3814898ee8adb63453cdb76e73d4ab4d31eda9eb`.
- Runtime Session: `64ac9f4f-1883-4062-a9dc-98e0b0798547`.
- DNS Session: `6264cbd6-a2de-499b-a7c0-87739b639a31`.
- Namespace `net:[4026532232]`, `lo / Ingress` 유지.
- 원본 실행 소스 `frozen-source-final`, 후보 `native-one-hour-final`은 수정하지 않았다.
- 최신 근거: 공유 `.git/final-llm-hour-preflight-20261030T100117Z/approved-execution-records/`
  아래 `api-final-summary.json`, `native-final-summary.json`, GUI 검증 결과 및 회귀·빌드 로그.
- 상세 Root/Runtime 결과는 `native-one-hour-final/execution/`, `future-runtime/`에 보존했다.

### A — 실제 LLM Plan 성공, Assessment Timeout

| 항목 | 실제 결과 |
|---|---|
| Provider / 모델 | 기존 OpenAI / `gpt-5-mini` |
| 요청 / 재시도 | 2회 / 0회 |
| Investigation Plan | 실제 응답, 구조화된 Schema 검증 통과 |
| Read-only Tool | `read_local_source_report` 완료 |
| Assessment | 승인된 20초에서 `LLMTimeoutError`, 응답·사용량 없음 |
| 후속 Replan | 미실행; 최초 Adaptive 계획을 평가 후 재계획으로 계산하지 않음 |
| Checkpoint / GUI | Revision 5, FAILED 상태와 Plan·Timeout을 실제 Tk 재연결 2회에서 확인 |
| Audit | 체인 검증 통과; 원본 Native 증거 불변 |

고정 Incident `83d6db5e-7b0a-5b39-934a-97e860b3b752`, Task
`74819a09-b7c4-5891-a35d-d4ca71e25c99`, Evidence Revision
`9c82b6ff11f6a23cec30163e2280b4c3474e729640b947de3dceac85c1901295`를 사용했다.
첫 요청은 약 9.139초, 입력 2,264 / 출력 689 token이다. 공식 단가로 계산한 **첫 응답 비용은
$0.001944**다. 두 번째 요청은 사용량 응답이 없으므로 **총 청구 비용은 UNKNOWN**이다.
두 요청의 사전 로컬 비용 예약 합계는 $0.02255775로 승인 상한 $0.05 이내였다.
키·민감 원문을 로그나 Git에 노출하지 않았고, 최소화된 증거만 승인된 API로 전송했다.

원격 Timeout 원인은 응답 증거가 없어 UNKNOWN이다. 요청 한도·20초 Timeout을 늘리거나
재호출하지 않았다. 실행 wrapper의 최종 `AssertionError`/exit 2는 성공 요건 불충족을
알린 후속 오류이며, 최초 운영 오류는 Assessment의 `LLMTimeoutError`다.
Coordination 우선순위는 LOCAL_RULE이고 실제 LLM 판단은 Plan에 한정한다.

### B — 실제 Native 수집 및 종료 결과

사용자가 터미널에서 Scope를 직접 확인하고 sudo 인증한 후 1회 실행했다.
고정 Root 8경로 중 승인된 5개 변경만 적용했으며 기존 설치 백업·Rollback을 보존했다.
상한은 전체 4,200초, Collector 128MiB/CPU25%, Runtime 512MiB/CPU50%, Queue32,
Runtime 저장 점검256MiB / Root Audit64MiB였다. 실행 중 상한을 완화하지 않았다.

| 항목 | 실제 결과 |
|---|---|
| 전체 실행 | 1,165.985초 (약 19분26초) |
| Collector 부착 경과 시간 | 1,150.322초 |
| VERIFIED seal의 활성 수집 합계 | **1,080.335초 (약 18분), 목표 3,600초 미달** |
| Native metadata | 144건: Runtime 수용134건 + 실패 후 격리10건 |
| DNS Transaction | UDP2 + TCP1 = 3개 |
| Window | 정상 봉인·Attestation VERIFIED6개 + 실패 진단 Window1개 |
| Network14 | ELIGIBLE9 / INCOMPLETE6 |
| RF/LR | 별도 인간 승인된 1개 작업, 4개 입력, 실제 Prediction8건 |
| Incident / Investigation Task | 2개 / 5개 |
| Runtime Queue | DONE2 / PENDING4 / POISON1, 원본 보존 |
| Queue Drop / 모델 오류 | 0 / 0 |
| 실제 외부 API / DNS9 | B에서 모두 0회 |
| Runtime·Root 종료 코드 | 2 |

TCP는 6개 Helper 실행에서 12연결 완료를 확인했다. 일곱 번째 Helper는 실행 중 Cleanup으로
취소됐다. 이 마지막 실행의 연결 완료 수를 추정하지 않으며 14연결 완료로 보고하지 않는다.
최대 38연결 계약을 초과하지 않았다. DNS는 기존 로컬 dnsmasq만 사용했다.

첫 봉인 작업만 사용자가 별도 승인했다. 이후 5개 작업 검토는 미승인 상태에서 실패했으며,
열려 있던 해당 검토 터미널만 종료했다. 새 모델 영수증이나 추가 모델 호출은 없었다.
조사는 SCRIPTED이며 A의 실제 API 결과를 B의 실시간 LLM 조율로 합산하지 않는다.

실제 Tk GUI의 종료·재연결 후 Backend가 동일 PID로 RUNNING인 것을 확인했다.
Dashboard·Continuous·Investigation·AI Analysis 등 실제 화면에서 Native 상태,
Prediction8·Incident2·Task5와 SCRIPTED 조사 표기를 확인하고 화면 증거를 보존했다.
Authentication NOT_ATTACHED를 실제 수집으로 표시하지 않았다. 실패 후 지속 운영 성공이나
발생하지 않은 충돌·재계획 성공은 주장하지 않는다.

### 오류 목록 및 RCA

| 오류 | 증거 및 처리 |
|---|---|
| A Assessment `LLMTimeoutError` | 실제 요청 2번째, 20초 무응답. 공급자 측 원인 UNKNOWN. 재시도 없이 보존 |
| B `CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT` | 11:16:24.126639 UTC, control 수신 공백 5.001초. 같은 Producer PID/start identity, IPC 연결 유지, receiver queue0/drop0. Root heartbeat 최대 공백6.253초 확인 |
| Root `COLLECTOR_EARLY_EXIT` | 위 Timeout 후 STOP에 따른 후속 관측 오류. 최초 원인으로 바꾸지 않음 |
| DNS 종료 중 heartbeat/exit 증거 부족 | STOP 후 CLOSED와 최종 Counter는 수신했지만 Runtime receipt 시점 프로세스 ALIVE. 당시 Cleanup UNVERIFIED 유지 |
| CLI `executed:false` 오표시 | 실제 Capture 뒤 실패해도 BLOCKED/false를 출력하는 결함 확인. 비권한 최소 수정·회귀 완료 |

Native Timeout은 단순 무트래픽 판단과 구별된다. 마지막 데이터 후 약145초였지만 control
메시지가 끊긴 5초에 실패했다. 마지막 성공 수신은 11:16:19.125606 UTC였고 Root 다음
heartbeat는 약6.253초 뒤였다. Root의 검증·lease 갱신·poll 경로 중 어느 단계가 지연됐는지,
OS 스케줄링 또는 I/O가 원인인지는 현 증거만으로 확정할 수 없어 UNKNOWN으로 남긴다.
Queue 포화·Producer 교체·OOM을 원인으로 단정하지 않았다. Timeout을 임의로 늘리지 않았다.

### Cleanup — 영역별 독립 판정

| 영역 | 판정 및 증거 |
|---|---|
| TCX | STOP ACK 수신, failure STOP 약1.322초, 소유 Collector Cleanup VERIFIED |
| Window | 정상6개 보존, 실패 진단 seal1개는 정상 VERIFIED 입력으로 승격하지 않음 |
| DNS Helper | CLOSED·최종 Counter VERIFIED. Runtime 종료 receipt에서는 ALIVE이므로 Cleanup UNVERIFIED |
| Root 소유 자원 | 최종 고정 unit MainPID0, 소유 Map/Link/Socket 잔류 없음; 해당 Scope VERIFIED |
| Runtime | 마지막 Flush VERIFIED, 전체 Cleanup UNVERIFIED; 후속 오류가 최초 Timeout을 덮지 않음 |
| Global Kernel | UNVERIFIED 유지; 현재 소유 자원 정리를 과거·전역 보장으로 확대하지 않음 |

DNS STOP 요청은 11:16:26.177538 UTC, CLOSED 관측은 11:16:28.179570 UTC였다.
Runtime receipt는 11:16:29.188 부근에서 프로세스가 살아 있음을 기록했다. 이후 Root 최종
unit 결과는 MainPID0/Exit0이었다. **뒤늦은 종료 증거로 앞선 Runtime receipt를 고치지 않았다.**
현재 해당 Producer·Runtime·Helper PID가 없다는 일반 사용자 조회도 과거 증거와 분리했다.

Ledger는 기존 **81행**, SHA
`07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`로 불변이다.
이번 실행·승인·종료는 별도 실행 영수증/Audit에 기록됐으며 기존 Campaign 계수를 초기화하거나
과거 영수증을 재사용하지 않았다. Root Audit 기존 prefix와 추가 체인, Runtime Audit 체인,
A service/B service/queue SQLite integrity_check 모두 통과했다. 기존 증거211개 SHA를 보존했다.

### 실패 후 최소 수정·검증·Git

코드 Commit **`970c43a`**: `continuous/cli.py`의 foreground `run` 오류는 이제
`FAILED_OR_BLOCKED`, `executed:null`, 증거 디렉터리를 반환한다. 실행 여부는 보존된
Runtime/Audit로 확인하게 하고, 실제 수집 후 실패를 미실행으로 단정하지 않는다.
기존 `test_operating_cli_child_exit_and_failure_evidence`에 해당 결과 검증을 추가했다.
승인·Timeout·Kernel·Root 정책을 변경하지 않았고, 설치된 시험 Artifact에도 적용하지 않았다.

- Workspace 관련 회귀 **88 PASS** (54.79초).
- 독립 Export 같은 회귀 **88 PASS** (61.30초).
- Workspace의 pytest 임시 디렉터리 정리 경고49건은 별도 보존. Export 전용 임시 경로는 경고 없이 통과.
- Ruff check PASS / format 1,539파일 PASS / `git diff --check` PASS.
- Native6개: Workspace 이중 빌드·Export 일치, 실제 실행 Native6개와도 일치.
- Wheel: Workspace 이중 빌드·Export SHA 일치.
- 수정 후 Wheel SHA: `e0a3bb92ee6a7b5cad01b7dfb02793a6240e707d2dbe3920f932dce00d8741bb`.
- 새 Wheel은 **비권한 빌드 결과**이며 위 실행 Wheel과 다른 Artifact다. 기존 승인을 승계하지 않는다.
- 재현·회귀 증거: `approved-execution-records/postfailure-validation/`.

코드·테스트와 이 보고서만 선별 Commit/Push하며 최종 Git 결과는
`approved-execution-records/git-final-executed.json` 및 최종 응답에 기록한다.

### 남은 조건

1. API Assessment 무응답 원인과 적정 시간 계약을 확인해야 한다. 새 호출은 새 정확한 승인 필요.
2. Root control heartbeat 공백의 단계별 원인을 더 좁혀야 한다. 이번에 원인을 해결했다고 주장하지 않는다.
3. DNS CLOSED 이후 실제 종료와 Runtime Cleanup receipt 사이의 경합을 해결·비권한 검증해야 한다.
4. 수정본은 새 Source/Artifact Binding으로 검토하고 Root·Native·R1·트래픽·시간 Scope,
   사용자 확인·sudo 인증을 다시 충족해야 한다. 모델은 봉인된 ELIGIBLE 작업별 별도 승인이다.
5. 3,600초 VERIFIED 활성 수집과 전체 Cleanup이 모두 충족되기 전에는 1시간/운영 VERIFIED가 아니다.

추가 Root·Native·DNS·API 실행, 설치, 승인 소비를 하지 않았다. 재시험을 자동 시작하지 않는다.

---

## 보존된 승인 전 사전 검증 기록 (이하 과거 시점)

아래 BLOCKED/NOT_RUN/승인 대기·미설치 표현과 실행 예시는 **실행 전 기록**이다.
이번에 소비한 Session/승인을 다시 실행하는 지침으로 사용하지 않는다.


Date: 2026-10-30, Asia/Seoul. Branch: `feat/one-command-runtime`.

**비권한 준비·수정·검증 완료. 실제 API 및 1시간 Native 시험은 새 승인 대기(BLOCKED).**
기존 제한 Native Orchestration의 `NATIVE_ORCHESTRATION_VERIFIED` 판정은 보존한다.
이번 개발·FAKE_HTTP 검증을 실제 LLM/API/Kernel 성공으로 확대하지 않는다.

## 기준선과 보존

시작 HEAD `7de4794`, 기존 후속 코드 `71377c7`. 실제 이전 Kernel 시험은 별도로 동결한
`c542398`에서 실행됐다. 이번 코드 Commit은 `66814fcd6d987b50a3a77e92bbad484961d32852`,
Tree `702eadfcb0ecdbb7896ca3424577a5e0f7c868f1`이다. 이후 보고서 Commit은 실행 Source를
바꾸지 않으며, 새 시험은 private `frozen-source-final`의 이 코드에 결합된다.

기존 실제 결과: Packet54, DNS Transaction3, attested Window3, Network14 ELIGIBLE5,
RF/LR8, Incident2, Investigation Task5, Queue Drop0, 모델 오류0, 소유 범위 Cleanup VERIFIED.
조사는 SCRIPTED이고 이 시험의 실제 API 호출은0이다. 과거 별도 Incident의 실제 API2회는
이번 Incident의 LLM 검증으로 재사용하지 않는다.

- 이번 보존 목록211개 SHA 일치; 이전 Native 성공/실패·설치 증거 불변.
- 기존 설치8경로의 현재 SHA와 후보 Manifest의 `current_sha256` 일치; 설치하지 않음.
- Ledger81행, SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`, 체인 VERIFIED.
- Campaign Root12 / Native4, Batch3 Root9 / Native1; 미해결 예약 목록 비어 있음. 초기화하지 않음.
- 실제 승인 영수증 발급·소비0, 실행 예약0, Root/Native/DNS/신규 모델/외부 API 실행0.
- Program1145·과거 Heartbeat 원인 UNKNOWN, 과거 FAILED/false/UNVERIFIED 유지.

증거 디렉터리(공유 Git 디렉터리 기준):
`.git/final-llm-hour-preflight-20261030T100117Z/`.
최종 후보는 **`native-one-hour-final/`**뿐이다. `native-review`, `native-review-final`,
`native-review-final-v2`, `native-review-ready`는 이전 비실행 초안으로 보존하며 승인·실행에 사용하지 않는다.

## 확인한 결함과 최소 수정

| 확인 사항 | 수정 및 검증 |
|---|---|
| 기존 API 최소화기가 Continuous advisory 및 Adaptive tool/evidence/history 항목을 전달하지 않음 | 기존 `security_ai/api_investigation.minimized`에 UUID·digest·enum·허용 tool catalog만 투영. Raw source와 자유형 error/purpose는 전달하지 않음 |
| 기존 2회 API 계약과 Continuous coordination/planning의 호출 수가 다름 | `continuous/api_investigation.RetainedAPIClient`가 정확한 Task·Source Revision을 고정. Coordination은 명시적 LOCAL_RULE, 계획·평가만 기존 API adapter 호출. 이후 재계획은 HUMAN REVIEW |
| DNS 정책의 정상 유한 종료도 Continuous Runtime이 EARLY_EXIT로 처리 | `DNSProducer.policy_duration_completed`가 정책 종료시각·Counter·인증된 CLOSED·프로세스 종료·durable cleanup을 모두 검증할 때만 종료 허용. 조기 종료·증거 누락·오류는 계속 차단 |
| PRE_ATTACH/POST_DETACH 시간은 실제 capture-enabled 시간보다 넓음 | Root `continuous/native/service.py`가 첫 enable 이후부터 종료/lease 만료 중 이른 시점까지 기록. Lease 공백 발생 시 해당 Window의 enabled duration 주장 금지. 갱신 시작뿐 아니라 syscall 완료 시각까지 이전 lease와 비교해 호출 중 만료도 제외 |
| 회전·복구 시 활성 수집 시간 합산 근거 부족 | `CaptureSeal`에 선택적 interval 증거, CPU boundary 내부 검증, 겹침·Replay 차단. VERIFIED seal의 서로 겹치지 않는 구간만 Runtime이 재구성·합산. 과거 seal에는 시간 증거를 소급 생성하지 않음 |
| 실행 후보 복사본에 이전 600초·변경 파일3개 등의 안내가 남음 | 새 후보의 요청·독립 승인 항목·terminal·Root fixed launcher·systemd 제한을 4200초 계약 및 실제5개 변경으로 대조. Scope 입력 전에 잔여75분 검사 |
| 새 retained API entry의 display Source가 Store config와 달라 GUI가 거부 | private 실행 entry가 기존 JSONL_REPLAY 저장소 종류를 유지하고 별도 `RETAINED_REAL_NATIVE_NO_NEW_CAPTURE` origin 표기. 기존 GUI 무결성 검사를 완화하지 않음 |

제품 변경: `continuous/api_investigation.py`, `continuous/investigation.py`,
`continuous/dns_source.py`, `continuous/service.py`, `continuous/capture.py`,
`continuous/native/service.py`, `security_ai/api_investigation.py`.
새 범용 Orchestrator·승인/예산 시스템·Kernel 프로그램은 만들지 않았다.
기존 API 2회/4096 token 상한, DNS3600초 상한 및 모델 Action 경계는 유지한다.

## Phase A: 보존 Native Incident → 실제 API 준비

기존 `InvestigationTasks → consume → ApplicationService → SOCRuntime →
InvestigationPlanner/AdaptiveInvestigationPlanner → InvestigationOrchestrator →
read_local_source_report → ThreatAssessor → Checkpoint/Audit`를 사용한다.

- Incident `83d6db5e-7b0a-5b39-934a-97e860b3b752`.
- Task `74819a09-b7c4-5891-a35d-d4ca71e25c99`.
- Evidence Revision `9c82b6ff11f6a23cec30163e2280b4c3474e729640b947de3dceac85c1901295`.
- Retained input SHA `5fa8c214b96387348bdfdd4339f9186719c93f17d90f328e6a4f0ab31707a707`.
- 원본 Native Flow/Window·모델/Feature fingerprint·prediction 결과는 기존 검증된 분석
  디렉터리에서 읽기 전용 대조했다. 새 RF/LR를 호출하지 않았다.
- 최초 모델 advisory는 실제 결과상 conflicting이다. 초기 Adaptive 계획과 평가 후의
  재계획을 구분한다. 충돌 해결 성공을 미리 가정하지 않는다.

제안 범위는 **기존 `https://api.openai.com/v1` / `gpt-5-mini`, 최대2회, 재시도0**이다.
계획1회·평가1회, 요청당 completion4096 token, timeout20초, 최소간격1초,
전체 로컬 비용 예약 상한 **USD0.05**. Output 최대8192 token; 각 입력은 UTF-8/schema byte
보수적 token 예약과 비용을 전송 전에 검사한다. 외부로 전송하는 데이터는 UUID·digest·
열거형 advisory와 tool catalog이며 원본 주소·도메인·계정·payload·파일 경로는 제외한다.

요금 기준은 [공식 모델 문서](https://developers.openai.com/api/docs/models/gpt-5-mini)의
입력$0.25/출력$2.00 per million token이다. 비용은 보수적 로컬 예약/추정이며 공급자
청구 보증이 아니다. 현재 모델 제공 여부와 키 유효성은 실제 호출 전까지 미검증이며,
실패 시 다른 모델로 자동 전환하거나 재호출하지 않는다. 선택할 기존 `.env`는0600임을
메타데이터로만 확인했다. 이번 작업에서 키 내용은 읽거나 기록하지 않았다.

`llm-review/run-retained-api.py --check`는 Source·Task·원본 결과 pin만 검사하며 API0이다.
실행 시에는 기존 `APIRunAuthorization`의 별도 인간 승인 파일과 선택된 env 경로가 필요하다.
정확한 신규 attempt 디렉터리를 독점 생성하고 원본 저장소를 수정하지 않는다.
두 호출을 소진한 후 후속 재계획은 `WAITING_HUMAN`으로 남긴다. 6회 계약을 새로 만들지 않았다.

### 실제 실행 entry의 비권한 검증

원본 Native Task를 사용하고 **HTTP 전송만 FAKE_HTTP**로 대체했다.
초기 Adaptive 계획, 실제 로컬 읽기 전용 tool, 구조화된 평가, 동일 Incident/Task,
Checkpoint, Audit chain, GUI Backend 및 재진입 차단을 검증했다.
실제 Tk 창 종료·재연결2회에서 Task·평가와 `Native live: False`를 확인했다.
상세 결과는 Continuous의 조사 Task와 detail에 표시된다. 과거 원본 SCRIPTED 평가는 유지한다.

이 검증의 가짜 요청2회/가짜 token 사용량은 실제 API 비용·추론 성공이 아니다.
현재 **실제 API 호출0, 실제 사용 token0, 실제 비용0, 실제 LLM Plan/Assessment/Replan 미검증**.
추가 모델 실행0. 초기 테스트 harness의 잘못된 Backend 명칭/property와 Source 표기 오류,
교정 전 로그도 별도 보존했다.

## Phase B: 순수 활성 수집 1시간 / 전체70분 후보

기존600초 또는3600초 전체 승인을 확대 적용하지 않는다. 새 승인을 요청한다.

| 구간 / 상한 | 새 후보 |
|---|---|
| 전체 실행 | 인증 후 설치·시작·STOP·Drain·Cleanup 포함4200초 |
| 수집 목표 | VERIFIED sealed enabled interval 합계≥3,600초; attach/회전/drain 공백 제외 |
| 정상 Stop | 목표 도달 또는 전체3900초 시점, 목표 미달은 NOT VERIFIED |
| Drain | 전체4020초까지 |
| Collector / Runtime systemd RuntimeMax | 3960초 |
| DNS helper | 기존3600초 정책 유지, 마지막1초 종료예산; TCX보다 먼저 끝날 수 있음 |
| Root watchdog | TERM4130초 + KILL30초, Root spawn<15초 → 최종4175초 미만 |
| ordinary Worker watchdog | TERM4190초 + KILL5초 + 종료 여유5초 =4200초 |
| 독립 systemd 최악 종료 | Runtime≤4100초, TCP≤3685초 |
| 승인 유효기간 | 기록부터≤24h, 상위 2026-10-31 16:00:57.778156 KST까지; 입장 잔여>75분 |

Duration은 향후 실제 봉인 증거로만 판정한다. 과거 limited trial의396.1369초 boundary
합계를 이번 새 enabled metric의 실환경 검증으로 재해석하지 않는다. Event 없는 Window도
Counter·Attestation이 충족될 수 있으나, AI 성공은 별도 적격 입력·Action·결과가 필요하다.

Namespace `net:[4026532232]`, Host `net:[4026531833]`, lo/Ingress 유지.
Root8개 기존 경로 중 내용변경5개: Collector trial-limit, continuous-installation,
operations-runtime unit, DNS unit, Collector `service.py`. TCP/dnsmasq/기존 DNS drop-in 내용 불변.
새 Directory·자동 서비스 enable·패키지 설치 없음. 고정 Manifest 설치/백업은 승인 후에만 한다.

TCP는 기존 Listener127.0.0.1:18080, source18081/18082, 최대19 helper/38연결,
새 generation당 최소180초·pair 내부35초, 기존 고정 요청/응답이다.
DNS는 기존 dnsmasq127.0.0.53:53의 UDP2/TCP1, 고정 질문·ID·wire SHA를 유지한다.
두 READY와 DNS probe 완료 후 TCP를 시작한다. 외부 연결·임의 포트·추가 트래픽 없음.

Collector128MiB/CPU25%/PID4; Runtime512MiB/CPU50%/PID32; Queue32.
Runtime256MiB/RootAudit64MiB는 주기적 사용량 점검이며 filesystem hard quota가 아니다.
DNS helper512MiB/CPU10%/PID4, UID1000 초기 socket open에 NET_RAW, 이후Capability0.

### 새 Artifact Identity

| 항목 | 값 |
|---|---|
| Runtime Session | `64ac9f4f-1883-4062-a9dc-98e0b0798547` |
| DNS Session | `6264cbd6-a2de-499b-a7c0-87739b639a31` |
| Release | `0.6.3` |
| Source map canonical SHA | `2da026fb46fdd72ba66316190413c6f3a71ebd07dee1aef477864d0c2d9e4afd` |
| Source archive SHA | `ddf077802ab0be2b7a4ae1db650042073b7ba9ef0ce26e1573134702c003ac73` |
| Wheel SHA | `76c082b6a279506dae34d3da3814898ee8adb63453cdb76e73d4ab4d31eda9eb` |
| Collector service.py SHA | `2f4de1475b9092025da195db1872ede9be1bcd2e5817d1a46dbbb0bae9d05024` |
| Root Manifest SHA | `47be0e61d6fb6347bfcbf5b64a2a9055f175b95bc7b70a8fa731a44ac2fd6819` |
| Native request SHA | `b78b7e363fe3884b77f396c8288b2e84987d31d8b6794add0f07778c27bcaa50` |
| Execution pins SHA | `0681754ecdfd90574a42037785801cd3ffd52fd9d3d59f08338ff3653b519913` |

전체 Native6개 SHA는 증거 디렉터리의 `final-artifact-identity.json`에 있다.
소유 Cleanup 성공은 TCX STOP ACK·진단/정상 Seal·DNS CLOSED/최종 Counter·durable proof·
Root/Runtime/Audit Drain을 각각 검증해야 한다. 자연 DNS 정책 종료는 owner STOP ACK로
위조하지 않는다. 강제 종료·누락 증거는 UNVERIFIED이며 Exit0만으로 성공 판정하지 않는다.

## 사전 검사·회귀·빌드

| 검증 | 결과 |
|---|---|
| Workspace Continuous/API/Provider 회귀 | 388 PASS |
| Workspace SOCRuntime/Planner/Assessment/GUI/CLI | 402 PASS; 합계790 distinct |
| 독립 Export 기본 같은790개 | 첫 실행789 PASS/1 FAIL; 동일 실패 테스트 무수정 단독 재검증1 PASS |
| Export 최초 실패 | DNS silence 테스트의 전체 시간5.4657초가 기존5초 assertion 초과; 단독3.43초 PASS |
| 최종 lease 경계 수정 회귀 | Workspace65 PASS / 최종 독립 Export65 PASS; 신규 호출 중/최초 lease 만료2건 포함 |
| 시간 실패 원인 판정 | 실제 스케줄링/fsync 기여는 UNKNOWN; Assertion·제품 timeout 완화 안 함, 최초 로그 보존 |
| Ruff / Format / diff | PASS; 최종 Format1539개 |
| Native build | Workspace2회 + Export,6개 모두 동일; libbpf 비권한 파싱만, Kernel load 없음 |
| Wheel | Workspace2회 + Export SHA 일치 |
| 새 fixed launcher | 실제 `system()` 함수만 AST 추출, 명령 경계 mock; 시작 deadline 경계8건 PASS |
| systemd | 후보5개 unit + drop-in의 오프라인 parser PASS, daemon-reload/activation 없음 |
| 공식 CLI | setup=CONFIGURED_NOT_STARTED; doctor=PREFLIGHT_ONLY_NO_INFERENCE; start--preview=직접 Scope/R1/sudo 필요; status=STOPPED/NOT_STARTED |
| Namespace | nsfs inode·lease provenance VERIFIED, target 진입/내부 검사는 승인 대기 |
| Model Registry | RF/LR 파일 SHA PASS, 운영 추론 별도 Action 대기 |
| 준비 API entry | retained Native Task + FAKE_HTTP2회 → core/평가/Audit/GUI/중복실행 차단 PASS |
| 실제 Tk | 신규 조사 저장소 attach/reconnect2회 PASS; 새 Live/API 없음 |

이전 초안의 scope 문자열·nested deadline 복사 오류는 최종 후보 전부 대조 후 교정했다.
Source·Source archive·frozen/export/실행 pin 및 기존 설치 SHA 대조가 통과했다.
기본790건 검증 후 최종 Root lease 경계2건을 추가했다. 최종 Source의 관련65건과 빌드를
양쪽에서 다시 검증했다. 최초 focused invocation의 모델 fixture1건은 기존 검증 repository
환경 변수가 빠져 fail-closed됐고, 올바른 환경의65건 전체는 PASS했다. 해당 로그도 보존한다.
Export의 기존 시간조건1건은 Assertion 수정 없이 해당 케이스만 재검증했다.

## 실행 준비와 승인 경계

하나의 검토 패키지:
`.git/final-llm-hour-preflight-20261030T100117Z/approval-package.md`.
그 안의 A(API)·B(Native/Root/R1/Traffic) 승인과 C(봉인 후 모델 Action)는 독립적이다.
A 승인만으로 B의 Runtime이 외부 API를 호출하지 않는다. B는 기존 SCRIPTED 조사,
AF_UNIX 전용 일반사용자 Runtime을 유지한다. 실제 LLM은 별도 retained 조사로 검증한다.
RF/LR는 실제 ELIGIBLE 작업마다 기존 action-specific 승인(상한96호출/20작업)을 사용한다.
미승인 작업이 종료 계약에 따라 취소되면 AI 운영 성공으로 보고하지 않는다.

다음 명령은 현재 **비소비 검사**만 수행한다. `SOC_AGENT_HOME`의 기존 기본 프로필은 변경하지 않았다.

```bash
cd /home/geonug/kdt-linux/soc-one-command-runtime
export SOC_AGENT_HOME=/home/geonug/kdt-linux/autonomous-soc-agent/.git/final-llm-hour-preflight-20261030T100117Z/native-cli-profile-final
PYTHONPATH="$PWD/src" .venv/bin/python -m soc_agent.cli doctor
PYTHONPATH="$PWD/src" .venv/bin/python -m soc_agent.cli start --preview
PYTHONPATH="$PWD/src" .venv/bin/python -m soc_agent.cli status
```

별도 정확한 B 승인 후에만 같은 프로필로 `soc-agent start --gui`를 사용한다.
사용자 Scope yes와 sudo는 사용자 터미널에서 직접 받는다. 실제 봉인 작업은 준비된
`native-one-hour-final/execution/approve-sealed-models.sh`에서 별도 검토한다.
이번에 start/gui 인증 대기 터미널을 열거나 실행을 예약하지 않았다.

Phase A는 `llm-review/api-approval-review.md`를 승인한 후 기존 APIRunAuthorization을
정확히 발급하고 `run-retained-api.py --authorization <파일> --env-file <선택된 기존 env>`로
수행한다. 키를 채팅에 입력하지 않는다. 결과 GUI는 별도의 `investigation-runtime`에 붙이며
원본 Native Runtime·SCRIPTED 결과를 덮어쓰지 않는다.

## 현재 판정과 남은 검증

- `LLM_ORCHESTRATION_VERIFIED`: **미부여**, 실제 새 API 호출 미승인/미실행.
- `NATIVE_ONE_HOUR_VERIFIED`: **미부여**, 실제 새 Kernel 수집 미승인/미실행.
- `OPERATIONS_VERIFIED`: **미부여**, 두 실환경 검증 이후 판정.
- 현 단계: **BLOCKED_PENDING_INDEPENDENT_HUMAN_APPROVAL**; 비권한 개발·검증 준비 완료.

현재 시험의 실제 수집 시간·Packet/DNS·새 Window·RF/LR·Incident·Task·STOP/cleanup은
모두 NOT_RUN이다. 이전 제한 시험 수치를 이번 결과로 계산하지 않는다.
잔여 위험은 실제 장시간 lease/회전 지연, 자연 DNS 종료의 실환경 증거, Runtime 자원·
디스크 점검 지연, API provider 가용성/구조화된 응답·20초 timeout이다. 실패 시 최초 오류와
후속 Cleanup 오류를 분리 보존하고 자동 Native/API 재실행하지 않는다.
전역 Kernel Cleanup·무중단 장기 운영·실시간 Native Runtime 내부 실제 LLM 호출·DNS9·
Host Authentication은 이 후보로 검증됐다고 주장하지 않는다.

코드 `33778d0`, 최종 lease 보정 `66814fc`와 보고서만 선별 Commit/Push한다. 기존 사용자 변경은 포함하지 않는다.
최종 Push 결과는 세션 종료 응답과 private `git-final.json`에 기록한다.
