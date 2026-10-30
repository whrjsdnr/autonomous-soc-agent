# Final operations and LLM orchestration verification

Date: 2026-10-30, Asia/Seoul. Branch: `feat/one-command-runtime`.

**비권한 준비·수정·검증 완료. 실제 API 및 1시간 Native 시험은 새 승인 대기(BLOCKED).**
기존 제한 Native Orchestration의 `NATIVE_ORCHESTRATION_VERIFIED` 판정은 보존한다.
이번 개발·FAKE_HTTP 검증을 실제 LLM/API/Kernel 성공으로 확대하지 않는다.

## 기준선과 보존

시작 HEAD `7de4794`, 기존 후속 코드 `71377c7`. 실제 이전 Kernel 시험은 별도로 동결한
`c542398`에서 실행됐다. 이번 코드 Commit은 `33778d009f5a35fe44caaec3b22f2492aab25d88`,
Tree `7c42ab9c179ff13416c5aaf08800307083bbbc89`이다. 이후 보고서 Commit은 실행 Source를
바꾸지 않으며, 새 시험은 private `frozen-source`의 이 코드에 결합된다.

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
최종 후보는 **`native-review-ready/`**뿐이다. `native-review`, `native-review-final`,
`native-review-final-v2`는 이전 비실행 초안으로 보존하며 승인·실행에 사용하지 않는다.

## 확인한 결함과 최소 수정

| 확인 사항 | 수정 및 검증 |
|---|---|
| 기존 API 최소화기가 Continuous advisory 및 Adaptive tool/evidence/history 항목을 전달하지 않음 | 기존 `security_ai/api_investigation.minimized`에 UUID·digest·enum·허용 tool catalog만 투영. Raw source와 자유형 error/purpose는 전달하지 않음 |
| 기존 2회 API 계약과 Continuous coordination/planning의 호출 수가 다름 | `continuous/api_investigation.RetainedAPIClient`가 정확한 Task·Source Revision을 고정. Coordination은 명시적 LOCAL_RULE, 계획·평가만 기존 API adapter 호출. 이후 재계획은 HUMAN REVIEW |
| DNS 정책의 정상 유한 종료도 Continuous Runtime이 EARLY_EXIT로 처리 | `DNSProducer.policy_duration_completed`가 정책 종료시각·Counter·인증된 CLOSED·프로세스 종료·durable cleanup을 모두 검증할 때만 종료 허용. 조기 종료·증거 누락·오류는 계속 차단 |
| PRE_ATTACH/POST_DETACH 시간은 실제 capture-enabled 시간보다 넓음 | Root `continuous/native/service.py`가 첫 enable 이후부터 종료/lease 만료 중 이른 시점까지 기록. Lease 공백 발생 시 해당 Window의 enabled duration 주장 금지 |
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
| Runtime Session | `5d4257a5-31fe-403e-90e5-e33884cb6fc8` |
| DNS Session | `8be00d75-d316-401d-9a90-503ced994554` |
| Release | `0.6.3` |
| Source map canonical SHA | `4b34cb528e90696fac359f10a2df74b62762b4f081a80797fd10ca6405b19d7b` |
| Source archive SHA | `743a6a45642f28d24e35eb507f258582ceef3dd17b97fd4bc5cd33381fe79408` |
| Wheel SHA | `a879c0616229f5605075ec7d2c63bf77b9aca5403301cf9fc19a25cba81d4454` |
| Collector service.py SHA | `f30045cb887351493f5f2888b62af57e16c0a6d66260d28c807cf199420132f2` |
| Root Manifest SHA | `87506c515882d4bef3f79bb934f3162ec043ccd9025b68ac72df72aa44664cb8` |
| Native request SHA | `193b3d685e5489c068c586973a0b191943519218ea866f3a6a83cefbd6e198a8` |
| Execution pins SHA | `3a9d95f0a80ecd2047cb3ca8376e0e06332239933f51a7b3359a6006c46034d7` |

전체 Native6개 SHA는 증거 디렉터리의 `final-artifact-identity.json`에 있다.
소유 Cleanup 성공은 TCX STOP ACK·진단/정상 Seal·DNS CLOSED/최종 Counter·durable proof·
Root/Runtime/Audit Drain을 각각 검증해야 한다. 자연 DNS 정책 종료는 owner STOP ACK로
위조하지 않는다. 강제 종료·누락 증거는 UNVERIFIED이며 Exit0만으로 성공 판정하지 않는다.

## 사전 검사·회귀·빌드

| 검증 | 결과 |
|---|---|
| Workspace Continuous/API/Provider 회귀 | 388 PASS |
| Workspace SOCRuntime/Planner/Assessment/GUI/CLI | 402 PASS; 합계790 distinct |
| 독립 Export 같은790개 | 첫 실행789 PASS/1 FAIL; 동일 실패 테스트 무수정 단독 재검증1 PASS |
| Export 최초 실패 | DNS silence 테스트의 전체 시간5.4657초가 기존5초 assertion 초과; 단독3.43초 PASS |
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
전체 테스트를 무한 반복하지 않았으며 마지막 Export 시간조건은 해당 케이스만 재검증했다.

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
export SOC_AGENT_HOME=/home/geonug/kdt-linux/autonomous-soc-agent/.git/final-llm-hour-preflight-20261030T100117Z/native-cli-profile
PYTHONPATH="$PWD/src" .venv/bin/python -m soc_agent.cli doctor
PYTHONPATH="$PWD/src" .venv/bin/python -m soc_agent.cli start --preview
PYTHONPATH="$PWD/src" .venv/bin/python -m soc_agent.cli status
```

별도 정확한 B 승인 후에만 같은 프로필로 `soc-agent start --gui`를 사용한다.
사용자 Scope yes와 sudo는 사용자 터미널에서 직접 받는다. 실제 봉인 작업은 준비된
`native-review-ready/execution/approve-sealed-models.sh`에서 별도 검토한다.
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

코드 `33778d0`과 이 보고서만 선별 Commit/Push한다. 기존 사용자 변경은 포함하지 않는다.
최종 Push 결과는 세션 종료 응답과 private `git-final.json`에 기록한다.
