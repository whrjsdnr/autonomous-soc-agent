# Gate B-2 — External Context v2 변경 영향 및 구현 순서

상태: **설계 제안, 구현하지 않음**. 추천 B: Parallel External Context.
정의는 [integration-contract-v2.md](integration-contract-v2.md)를 따른다.
이 단계의 실제 변경은 신규 설계 문서 세 개뿐이다. 아래 Python 파일/SQL/API는
Gate B-3 승인 후 검토할 후보이며 생성·수정되지 않았다.

## 1. 신규 파일 후보

| 후보 | 책임 | 금지된 책임 |
|---|---|---|
| `security_ai/external/models.py` | v2 binding/observation/result/context 및 companion receipt의 frozen typed 계약 | policy/approval 권한, model training |
| `security_ai/external/validation.py` | exact schema/model/artifact/feature/source/time/score binding; integrity 재검증 | 외부 VALID 선언 수용, 임의 threshold/label 변환 |
| `security_ai/external/adapters.py` | 실제 독립 package API 호출, managed inference 출처, typed error mapping | 모델 구현 복제, 새 ML framework/plugin manager |
| `security_ai/external/assembly.py` | 검증된 incident Context 구성, same-observation grouping, dedup/conflict/coverage | score 평균, risk 합산, heuristic incident merge |
| `assessment/external.py` | prompt projection/advisory-only draft/assessment 실행 receipt | 모델 결과의 Evidence/Observation 생성 |
| `review/persistence/external_context.py` | 같은 기존 DB connection에서 versioned rows/refs/digests를 보존·복원 | 별도 DB engine, silent schema adoption, insecure storage |
| `security_ai/external/schema.py` | 명시적 additive external-storage migration 및 feature metadata 검증 | 자동 v14 upgrade, 역사적 JSON/hash 재작성 |
| `tests/unit/security_ai/external/…` | 계약/validation/assembly 오류 oracle | mock로 실제 native inference PASS 주장 |
| `tests/integration/demo/test_external_context.py` | actual package→Context→Assessment→Decision→read-only boundary/restart | privileged response adapter |
| `tests/diagnose_external_decision_pipeline.py` | offline versioned export/compare, exact identity와 normalized trace 분리 | 기존 Gate A trace 계약 재정의 |

가칭 module 분할은 구현 규모에 따라 줄일 수 있다. 빈 layer/placeholder class를 미리
만들지 않는다. 기존 `model_analysis.py`, `FusionResult` 및 existing package loader를 대체하지 않는다.
외부 API의 lazy import를 유지해 opt-out 환경이 heavy backend import를 강제하지 않게 한다.

## 2. 기존 코드의 변경 필요성

| 실제 파일/모듈 | B-3 예상 변경 | 호환성 조건 |
|---|---|---|
| `application.py` | 별도 optional external callback/store capability 주입, v14/v15 startup 분기 | 기존 `model_analysis` 및 기본 구성 유지; profile로 권한 변경 없음 |
| `assessment/assessor.py` | 새 explicit context-aware entry를 추가하고 기존 LLMClient/validator 공유 | 기존 `assess` signature/기본 동작 유지; 정확한 core result 타입 보존 |
| `assessment/prompts.py`, `assessment/external.py` 후보 | 별도 외부 JSON section과 receipt projection | 총 64000자/raw 4096자 제한 그대로; overflow는 호출 전 실패 |
| `investigation/runtime/service.py` | 기존 ANALYZE/DECIDE에 외부 receipt 검증·보존 연결; `_Workflow`의 별도 companion 참조; resume 시 검사 | 기존 orchestrator·step·round limit·attempted guard 재사용; v1 경로 유지 |
| `investigation/runtime/persistence/store.py` | 기존 CAS publish transaction에 companion link/audit atomic append | claim/revision/digest 검증 유지; commit uncertain에서 자동 retry 금지 |
| `review/persistence/store.py`, `session.py` | core assessment와 companion receipt를 같은 transaction에 append하는 entry 후보 | 기존 append_assessment 결과/StateAnchor와 같은 source validation; nested transaction 금지 |
| `review/persistence/database.py` | 승인된 v15 지원과 strict metadata/table 검증 진입 | 기존 v14/secure SQLite creation/open/sidecar/transaction 그대로; 숫자 allowlist만 추가하고 검증 생략 금지 |
| existing migration/startup validators | v15 main schema에 기존 v14 확장 tables가 그대로 있음을 확인하는 compatibility review | exact table/extension versions 검증; `version <= 15` 같은 광범위 수용 금지 |
| `api/service.py` 및 read-model 신규 view 후보 | v2 companion 상태의 명시적 read-only 조회, feature opt-out/foreign object authorization | 기존 v1 endpoints 유지; 새 GUI/HTTP ingestion 구현 금지 |
| `review/service.py`, `response/advisory/planner.py`, `response/promotion` entrypoints | v2-bound decision의 missing lineage 및 B-3 read-only ceiling을 backend에서 거부 | 기존 v1 approvals/PolicyEngine 의미 유지; v2 context를 legacy approval로 승인하지 않음 |
| `experience/capture.py` | v2 workflow의 Context lineage 누락을 거부하거나 별도 versioned capture 설계 | 기존 Experience hash 재작성 금지; B-3에서 개선/학습을 완료로 표시하지 않음 |
| `live.py`, `desktop.py` | 필요 시 external runtime을 별도 opt-in config로 주입 | 기존 packaged 3-model activation, offline default, provider opt-in 유지 |

`review/persistence/store.py`의 `SQLiteGovernanceStore.append_assessment`가 실제 transaction과
exact-type/state append 검증을 소유하고 `GovernanceSession`의 load/save_state를 사용한다.
관측/가설 변화가 없으면 early return하며 assessment 자체는 checkpoint에 보존된다.
신규 companion 보존은 이 early return에서도 누락되면 안 된다. advisory Context만 추가했다고
IncidentState revision이나 기존 assessment_appended event를 억지로 늘리지 않는다.
migration 외 allowlist 검토는 여러 모듈에 걸칠 수 있다.
현재 `open_application_store`가 v14까지 migration을 순서대로 실행하므로, 이미 v15인 DB에
v14 전용 migration을 무조건 재실행하면 안 된다. 정확한 현재 extension metadata를 검사해
지원하는 startup branch를 설계/테스트해야 한다. 이 영향은 단순 callback 한 줄 추가가 아니다.

현재 `WorkflowArtifacts.assessment` union과 exact-type 검사 때문에 새로운 subtype을 그대로
반환하면 오류가 난다. 추천안은 core AssessmentResult/FusionAssessmentResult를 그대로 반환하고
외부 receipt를 별도로 취급한다. 기존 `WorkflowArtifacts`, checkpoint JSON의 `references`,
IncidentDecision 및 FusionResult에 extra field를 주입하지 않는다.

### 변경하지 않을 계약과 모듈

- 기존 Fusion v1 모델 종류/class 방향/profile/SelectionReport/compatibility engine.
- 기존 SOC 모델 artifact/Golden Fixture/Selection Digest/native/reference 평가.
- 기존 5-feature `NetworkEvent` / `SOCEvent` 입력 의미와 serialization.
- `IncidentState` / Evidence / Observation / Hypothesis의 authority 의미.
- `IncidentDecisionEngine`의 v1 규칙, outcome 및 fingerprint 계산.
- `PolicyEngine`, `ApprovalManager`, tool permission/risk, confirmation/RBAC/stable action binding.
- POSIX/Windows secure storage 및 runtime lock implementation.

단, 이 모듈을 호출하는 **boundary의 누락 lineage 거부**는 추가 검증 대상이다.
기존 내용이 그대로라고 해서 v2 입력을 검증 없이 보낼 수 있다는 뜻은 아니다.

## 3. 기존 API 영향

기존 opt-out composition/CLI/read API는 그대로다. 신규 Context는 explicit entry 또는 optional
keyword로 도입한다. unknown context version, unavailable external dependency, unsupported DB는
명시적 실패다. missing config를 mock/legacy inference로 fallback하지 않는다.

새 read view는 `core_checkpoint + external_companion` envelope 형태 후보이며 기존 API payload를
재정의하지 않는다. Object authorization은 incident/store identity로 그대로 검사한다.
새 endpoint 구현 여부는 B-3 최소 read-surface 필요성에 따라 결정하며 collector/GUI는 범위 밖이다.

Gate A의 diagnostic policy fingerprint는 composition/runtime 등의 실제 AST를 포함한다.
B-3 코드 변경 후 Gate A 기존 hash와 새 코드가 같다고 주장해서는 안 된다. 역사적 trace는
보존하고 기존 v1 fixture의 실제 결과 회귀를 재실행한다. 새 진단 계약/version/config hash로
WSL/Windows 동일 코드를 비교하며 이전 oracle를 조용히 바꾸거나 historical report를 덮어쓰지 않는다.

## 4. DB·Serialization·Migration

**예상 migration 필요: YES**. 같은 SQLite, 기존 v14를 기반으로 명시적 additive v15 후보.
v15 번호는 B-3 구현 전 다른 작업과 충돌 여부를 확인한다. external metadata의 계약 버전은 v2다.
대안 B라도 오래된 reader가 Context를 무시하는 문제가 있으므로 “DB 변경 없음”은 채택하지 않는다.

| 저장 대상 후보 | 검증 / 원자성 |
|---|---|
| binding snapshots / source observations | setup/feature/source/actor namespace exact digest; observation ID 충돌 reject |
| results / contexts | immutable typed JSON, envelope transport+canonical SHA, semantic duplicate key, foreign incident/time 검사 |
| assessment runs/receipts | 신규 wrapper에 core assessment snapshot + exact digest + input/output anchor + 실제 request projection + context; 없는 legacy assessment table 참조 금지 |
| decision receipts | core decision ID 및 content digest + assessment/context binding; 사후 재결합 금지 |
| checkpoint companion links | run/revision/core checkpoint digest/receipt refs; existing CAS publication과 같은 transaction |
| bounded reject/audit events | sanitized error code/참조/hash만; raw sensitive payload/exception dump 없음 |

단일 연결의 foreign key/digest graph를 검증한다. 모델 inference/LLM 동안 DB write lock을 유지하지
않는다. 기존 assessment state 검증/no-op과 신규 assessment-run snapshot/receipt 보존은 같은
transaction에서 처리하며 checkpoint publish+link도 atomic이다.
두 commit 사이 실패는 기존 claimed-step recovery가 처리하며 전체 stage exactly-once가 아니다.
첫 commit만 끝난 companion row는 workflow publication이나 authority로 사용하지 않는다.
기존 `WorkflowInFlight`, `CommitOutcomeUnknown`, `StaleSnapshotError`를 catch하여 성공으로 바꾸지 않는다.

v14 historical JSON/ledger/checkpoint/Fusion payload를 rewrite하지 않는다. 새 rows는 explicit
version decoder를 거친다. 모델 weights/joblib/pickle은 DB에 넣지 않는다. metadata/artifact
path는 presentation provenance이며 portability hash에서 OS path를 제거하더라도 exact 원본
audit content를 변조하지 않는다. security event time/StateAnchor/evidence IDs는 비교에서도 보존한다.

### Migration 실행 계획 (아직 미실행)

1. B-3의 기본은 기존 DB를 건드리지 않는 dedicated private validation DB 생성이다.
2. v14 extension graph와 schema를 검증하고, 승인된 explicit migration에서 v2 tables/indexes/foreign keys를
   만들며 같은 DDL transaction 끝에 user_version을 v15로 바꾼다.
3. 중간 실패 rollback, v15 metadata 누락/오버플로/unknown version은 startup 실패로 검증한다.
4. 새 binary의 v14 opt-out 경로와 v15 external-enabled 경로를 따로 검증한다.
5. 기존 사용자 DB in-place migration, backup/export 기능 또는 installer는 이 설계로 실행 권한을
   부여하지 않는다. 기존 backup 기능 유무도 구현 전 확인하며 없는 기능을 있다고 가정하지 않는다.

## 5. Policy / Approval 및 부작용 영향

기존 risk/allow/deny/approval rules를 바꾸지 않는다. 외부 score는 tool permission/approval
identity/authority로 변환되지 않는다. source Evidence는 실제 source tool 결과에서만 생성한다.
External mode는 advisory-only analysis로 새로운 Observation/Hypothesis 생성이 금지된다.

B-3의 v2 decision companion에는 immutable read-only disposition을 둔다. 다음 경계에서 동일
decision digest를 조회해 external disposition 및 lineage를 검사해야 한다:
incident state authorization, response source validation, promotion, execution bridge, tool approval
issuance 및 executor preflight. direct service/API 호출에서도 거부해야 한다.
CLI 옵션/프런트엔드/모델 flag만으로 차단했다고 주장하지 않는다.

decision/context 참조가 없는 직접 ActionProposal도 차단해야 한다. B-3 dedicated v15 validation
DB의 immutable read-only capability를 모든 backend privileged entrypoint에서 검사하고,
등록 tool도 read-only만 허용한다. 실제 response handler는 등록하지 않는다. 같은 validation
store 안의 v1 workflow도 제한되며 기존 합법적인 privileged 경로는 별도 v14 fixture로 검증한다.
request/profile/absence of context로 이 capability를 끄지 못한다. 이후 운영 v15 capability와
context-bound privileged review는 별도 설계/승인 없이 도입하지 않는다.

v2-bound approval scope가 아직 정의되지 않았으므로 B-3에서는 유효한 legacy 승인도 privileged
operation에 사용할 수 없다. 기존 v1 workflow의 합법적 approval 경로는 그대로 유지한다.
Backend를 모두 연결하지 못하면 v2 runtime 활성화를 막고 INCONCLUSIVE로 남긴다.
실제 write handler를 테스트에 연결하지 않고 sentinel로 외부 호출 0을 독립 oracle에서 검증한다.
실제 사람의 승인·권한을 생성하거나 높은 모델 점수로 자동 티켓을 만들지 않는다.

## 6. Gate B-3 구현 순서 및 exit 조건

| 순서 | 범위 | 다음 단계 진입 조건 |
|---|---|---|
| 1 | 승인된 계약, source schema/pins/required models/bounds를 immutable version으로 확정 | 미해결 정책 선택 문서화; artifact/dependency 무조건 설치 금지 |
| 2 | optional typed adapter/validation 및 controlled precomputed source fixture | schema/feature/version/score/provenance tamper unit PASS |
| 3 | actual Quality/Edge/DNS native package inference | 실제 pinned artifact 사용; Mock와 별도 증거, 실패는 fallback 없음 |
| 4 | source incident binding, dedup/conflict/coverage, parallel assembly | 서로 다른 관측 유지; wrong incident/time/content reject |
| 5 | dedicated secure DB 및 migration/companion tables | v14 그대로, v15 strict startup, CAS/fault/reopen checks PASS |
| 6 | existing ANALYZE/ThreatAssessor/DECIDE에 receipt 연결 | empty observations/hypotheses, 실제 request Context 포함, unchanged authority |
| 7 | backend read-only ceiling / resume / audit / read surface | 직접 우회 호출 거부, stale/missing companion 실패, no WRITE/provider |
| 8 | scoped scripted end-to-end trace 및 independent security oracle | 동일하게 잘못 ALLOW해도 FAIL; existing loop guard 유지 |
| 9 | 실제 Windows native dependency/artifact/inference/storage 및 WSL 비교 | exact identity, 실제 label/threshold/policy/guard 판단 차이 검사 |
| 10 | 기존 회귀와 static 검증, 새 결과 및 SHA sync manifest | 기존 fixture/model 보존, 신규 결과 exclusive creation, Gate C 시작 금지 |

필수 테스트 목록과 구체적 commands는 [integration-test-plan.md](integration-test-plan.md)에 있다.
이 목록은 구현 일정이나 검증 완료 기록이 아니다.

## 7. Rollback 전략

활성화 전 기본 external-disabled composition은 기존 v14 경로를 유지한다.
실패 시 새 검증 디렉터리/결과를 보존하고 기존 untouched v14 저장소와 old composition으로 복귀한다.
v15에서 external flag만 꺼서 v2 workflow를 legacy resume하지 않는다.
v15 DB의 user_version을 14로 낮추거나 companion rows를 삭제하거나 insecure file을 고쳐 통과시키지 않는다.

v2 records/workflow 진행 후에는 자동 binary downgrade가 안전하지 않다. 실행 중지 및 격리,
정확한 provenance 재검증/명시적 운영자 recovery가 필요하다. 기존 v14 복사본이 있어도 이를
재사용하는 것이 v15의 새 history를 합치는 것은 아니며, 신규 이력을 숨겨서는 안 된다.
Model artifact rollback/promotion, source code self-modification, hot-reload는 범위 밖이다.

## 8. 이번 설계 검증 및 보호

신규 세 문서 경로의 부재를 먼저 확인했다. 기존 source/test 및 기존 Gate B 문서의
SHA snapshot과 tracked diff를 기준으로 보존을 확인한다. `git diff --check`, `git status --short`를
수행하며 docs의 신규 untracked 파일도 trailing whitespace/fence/link를 별도로 점검한다.
이번에 pytest/Ruff/Windows native tests를 새로 실행한 결과는 없다. 과거 결과는 baseline으로만 재사용한다.
`.env` 접근/수정, ML 수정, 모델 재학습/파일 변경, provider 호출, 승인/실제 response,
commit/push/배포, Gate B-3/Gate C~G 구현은 수행하지 않는다.
