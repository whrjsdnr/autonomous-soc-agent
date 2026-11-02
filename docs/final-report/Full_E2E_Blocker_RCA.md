# Full E2E 차단 오류와 수정 근거

검증 범위: 2026-11-02 야간 비권한 복구. 실제 Root·Native·DNS·외부 API 재실행은 0회다.

## 서로 다른 시험을 구분한다

| 시험 | 실제 결과 | 해석 |
|---|---|---|
| `research-mvp-short-native-review-20261102T091500Z` | Native 12, DNS 2, Runtime Window 0, 최초 `CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT` | 최초 송신 공백 원인 UNKNOWN. 진단 Seal은 적격 수집 Window가 아니다. |
| `research-mvp-control-validation-retest-20261102T100229Z` | Root 369.161초, 최종 검증 수집 **361.395650895초**, Packet 54, DNS 3, ELIGIBLE 5, Live Prediction 0, 모델 오류 1 | 수집과 소유 범위 Cleanup 성공. 모델·Latency 필수 GUI 값 미충족으로 전체 E2E 실패. 중간 359.319초 관측값을 최종 수집 시간으로 사용하지 않는다. |
| 같은 시험의 별도 보존 입력 진단 | 실제 RF/LR 8 predictions | 호스트의 보존 입력 진단 성공이다. 서비스 안 Live 추론 성공으로 확대하지 않는다. 야간 작업 이전 실행이다. |
| `research-mvp-single-approval-live-20261102T105745Z` | 사용자 취소, Root/Native 0회 | 취소한 Session 재사용 금지. |
| `research-mvp-all-live-20261102T110953Z` | Root 2.474초, 실제 종료 코드 2, 설치 전 `FIXED_INSTALLATION_WRITE_SCOPE` | Collector·Runtime·Helper 미시작. 승인 경로 8개 모두 변경되지 않았다. |

## 1. 설치 변경 개수의 과거 값 복사 — 수정

`execution/root-trial.py::install()`은 `len(rows)==8`과 변경 개수 `==4`를 요구했다. 실제 Manifest는 3개 변경이었다. 행 수나 승인 누락 문제가 아니라, 이전 시험의 숫자를 복사한 Launcher 결함이다. 설치 전 assert에서 실패해 백업·Root 파일 쓰기가 시작되지 않았다.

`agent_native.bind_installation_scope()`는 **새 미승인 Launcher**의 고정 8경로와 변경 경로 집합을 Manifest로 결합한다. `installation_plan()`은 해당 선언뿐 아니라 실제 assert의 AST까지 검사한다. 따라서 선언만 바꾸고 과거 assert를 남기는 우회도 차단한다. 기존 실행 Artifact는 수정하지 않는다.

재현: 원본 설치 함수의 파일 작업 부분을 격리 임시 경로로 매핑했다. Root 소유권 경계만 모사하고 실제 파일 백업·원자 교체·fsync를 실행한다. 3개 교체, 5개 inode/mtime 유지, 8개 원본 백업을 확인했다. 서비스 활성화는 실행하지 않는다.

## 2. 모델 Worker 실패 증거 소실 — 수정, 근본 원인은 UNKNOWN

호스트에서 동일 보존 입력은 추론됐지만 Native Runtime 서비스의 Worker는 실패했다. 당시 자료로 CPU Quota, 메모리, 스레드 생성 또는 경로 중 하나를 확정할 수 없다. OMP/OpenBLAS 스레드 제한은 다음 실행 후보이며 입증된 RCA가 아니다.

`ResearchAdapter.last_failure`는 승인/의존성/요청 저장/프로세스 생성/대기/영수증 검증 단계를 구분한다. 예외 종류·errno·종료 코드만 기록하고 비밀값·stderr·원본 payload는 저장하지 않는다. `tcx_analysis`가 안전한 진단 Artifact와 Audit를 남긴다. `OfflineWorkflow`는 ToolError도 MODEL_ERROR로 보존한다. 진단 기록 실패가 최초 오류를 덮어쓰지 않는다. 자동 재시도는 없다.

## 3. 조사 결과가 별도 GUI에만 존재 — 수정

`gui.api_attachment.attach_api_results()`가 원 Native Session, Task ID, Incident ID, Evidence Revision, Sources를 대조한 뒤 보존 API 조사 결과를 같은 GUI에 표시한다. Native 저장소는 변경하지 않는다. 기존 SCRIPTED 조사도 보존한다. 잘못된 Binding이면 표시를 차단한다. API Runtime을 새로운 Native 수집으로 표시하지 않는다.

## 4. 승인 범위 오해 — 기존 계약을 유지하며 UX 보완

새 GUI 버튼은 **현재 봉인된 적격 작업**을 목록으로 검토하고 기존 ApprovalManager의 작업별 영수증을 생성한다. 미래 입력 자동 승인 기능은 없다. API 버튼은 고정된 Incident/Revision에 대해 기존 APIRunAuthorization을 생성하며, 버튼 자체가 API를 호출하지 않는다.

## 남은 실제 차단 조건

새 코드의 Native 서비스 안 Worker 성공, 실제 LLM Assessment, 해당 실행의 전체 GUI 값과 Cleanup은 아직 재검증하지 않았다. 미승인/만료 패키지나 과거 영수증으로 이를 보완하지 않는다. 고정 Release에서 매 실행 새 Native 패키지를 자동 생성하는 제품 경로도 아직 완성되지 않았다. 전체 준비 판정은 이 한계를 포함한다.

증거: `.git/full-e2e-overnight-recovery-20261102T111600Z/`의 `failed-install-*`, `preservation.json`, 회귀 로그. 원본 시험 디렉터리는 읽기 전용으로 보존한다.

## 5. 실제 Replay 복구에서 중간 디렉터리 권한 실패 — 추가 수정

첫 CLI 시험은 저장 PCAP128레코드를 처리해 Packet70, Prediction46, Incident23을 생성했다. Runtime 오류는 없었으나 보조 시험의120초 안에36작업을 모두 처리하지 못해 정상 Stop했고 PENDING13을 보존했다. 이 시험 제한 초과를 Runtime Heartbeat 실패로 기록하지 않는다.

이어 기존 `setup --recover-from`의 격리 복사본은 `StorageSecurityError: Database directory must be private (mode 0700)`으로 시작 전 차단됐다. `clone_replay()`가 파일의 leaf parent만 mode0700으로 생성하면서 `parents=True`로 생긴 `orchestration/workflows` 중간 디렉터리를0755로 남기는 직접 원인을 확인했다. 기존 회귀는 실제 완료된 조사 Checkpoint의 깊은 디렉터리 구조를 포함하지 않았다.

코드 `9cd24ee`는 대상의 부모 디렉터리를 위에서부터 각각 기존 `create_private_directory()`로 생성한다. 원본 권한 변경이나 검증 완화는 없다. 실제 SOCRuntime 조사·Checkpoint를 포함한 회귀가 수정 전 동일 오류로 실패하고 수정 후 통과했다. 관련38건 PASS.

새 격리 CLI 복구는75.809초에 남은13개 작업을 처리해 DONE36, 새 Prediction22, 새 Incident13, 모델 오류/Drop/Source Gap0, Cleanup VERIFIED를 확인했다. 원본의 PENDING13과 파일은 그대로다. 원본 분석 파일230개의 SHA,23개 SQLite의 논리 dump도 일치한다. SQLite online backup의 물리 header SHA가 달라지는 것은 논리 변조로 판정하지 않는다. JSON result69개는 외부 workflow23개와 모델46개의 파일이며69개 Incident가 아니다. 초기 보조 스크립트가 존재하지 않는 results/를 센0은 별도 analysis-preservation-check.json으로 교정했다.

재시작 시 received256은 복구128 + 재입력128이며, 중복128이 차단됐다. 실제 고유 Packet70을140이나256으로 합산하지 않는다. 원 시험과 복구의 Prediction46/22도 서로 다른 invocation으로 구분한다. 실제 PCAP 결과를 표시한 Tk GUI2회 연결/재연결과 Backend 불변성도 확인했다.

## 6. 실제 보존 모델 결과의 초기 LLM Plan Schema 차단 — 추가 수정

실제 저장 PCAP 모델 결과와 과거 Native DNS 메타데이터를 조사 Worker에 제출한 비권한 추가 시험에서, Network Task의 첫 Plan이 API 호출 전에 `CONTINUOUS_API_RESPONSE_SCOPE_DENIED`로 차단됐다. DNS의 SCRIPTED 조사는 별도로 성공했다.

`InvestigationPlanner(max_steps=2)`는 기본 `LLMInvestigationPlanDraft`의 **더 엄격한 파생 Schema**를 `create_model()`로 생성한다. `RetainedAPIClient`가 기본 클래스와의 identity equality만 허용해 이 정상 Schema를 거부했다. 기존 API Fixture는 `agreement_state=conflicting`에 따른 초기 `ReplanningDraft` 경로를 사용했으므로 통과했다. 이는 실제 모델의 정상 초기 계획 분기를 빠뜨린 통합 결함이다.

코드 `2064af1`은 기존 Planner가 이미 인정하는 Plan Schema 계열만 `issubclass`로 수용하고, 전달된 제한 Schema를 그대로 Provider에 넘긴다. 기본 Schema로 바꿔 단계 제한을 완화하지 않는다. unrelated Root-command Schema는 호출 전에 거부한다. 실제 HTTP 요청 Schema의 `steps.maxItems=2`, Tool 완료, Assessment, Checkpoint, 추가 호출 차단을 검증했다. 새 정상 분기 회귀는 수정 전 실패, 수정 후 관련201건 PASS다.

보존 실제 PCAP 모델 결과 + 보존 Native DNS 메타데이터의 후속 비권한 시험도 통과했다. 실제 외부 API는0, Network 가짜 HTTP Plan/Assessment2회, DNS SCRIPTED 조사이며 서로 다른 시간·Scope 사건은 병합하지 않았다. 실제 Tk GUI2회에서 이 결과와 FAKE_HTTP 표기를 확인했다. 실제 Native/API 전체 성공으로 판정하지 않는다. 이 보조 시험의 첫 DNS origin selector와 최종화 dict 중복 keyword 오류는 시험 스크립트 문제로 따로 보존했고, 완료된 Workflow를 읽어 결과를 확정했으며 호출을 재생하지 않았다.

새 제한 API Launcher는 초기 Adaptive Planner가 `ReplanningDraft`를 사용하는 경우를 최초 PLAN으로 허용한다. 첫 계획 이후의 추가 Replan은 거부하고 기존 최대2호출·20초·재시도0 계약은 그대로다.
