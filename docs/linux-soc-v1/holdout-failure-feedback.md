# Independent Holdout & Failure Feedback

검증일: 2026-10-14. 환경: WSL2 Ubuntu, Python 3.12. 기준 HEAD: `86cdf16e2148be206c4d3ce403e29558beed1cff` (`main`). 최종 판정: **PARTIAL**.

인증된 실패 피드백의 저장·복구, 기존 Candidate 생성기 연결, 선언된 Fixture Split 검증, 동일 데이터의 Baseline/Candidate 비교 및 승인 차단을 구현했다. 독립 운영 Holdout, 확정 FN 및 LLM/Tool 후보의 개선 효과 검증은 **BLOCKED**다. 운영 정책·임계값·코드·모델을 자동 적용하는 경로는 연결하지 않았다.

## 1. Holdout Contract

구현: [`HoldoutContract.validate_dataset()`](../../src/soc_agent/offline_evaluation/holdout.py), 실행: [`HoldoutEvaluation.run()`](../../src/soc_agent/linux_runtime/holdout_evaluation.py).

`soc-independent-holdout:v1`은 다음 정보를 검증한다.

- Dataset ID/Version/Digest: 스냅샷의 콘텐츠 주소. 기존 `EvaluationDataset.dataset_id`의 명칭은 별도로 보존한다.
- Source Identity/Digest: 선언된 출처 namespace와 원본 이벤트 집합의 SHA-256.
- Ground Truth Digest, Label Provenance Digest: 원본 행·라벨·출처 설명의 결합.
- UTC Collection Period, TRAINING/DEVELOPMENT/HOLDOUT membership, Split Identity/Method.
- 평가 단위: `INCIDENT_UTC_FIVE_MINUTE_WINDOW_RULE`.
- Dataset Size 및 Positive/Negative Counts: **Holdout의 Window×Rule 라벨 수**. Event 수와 혼합하지 않는다.
- Contract Digest, `labels_from_detection_output=false`.

Member는 현재 하나의 UTC 정렬된 5분 Window를 표현한다. 여러 Window를 넘는 단일 Case는 지원하지 않으며 거부한다. Source assurance는 `PREAUTHORED_FIXTURE`, `EXTERNAL_REPORTED`, `UNKNOWN`이다. **운영 검증 완료를 선언하는 assurance는 없다.**

`PREAUTHORED_FIXTURE`는 기존 `fixture_dataset()`의 사전 작성 Case와 일치해야 한다. 공격자가 데이터·라벨·Digest를 모두 다시 계산해도 변경한 라벨을 기존 Fixture 정답으로 채택하지 않는다. 외부 라벨 서명/독립 검수/실제 원본 인증 제공자는 아직 없다. Digest는 내용 무결성만 확인하며 출처 진위나 라벨 정확성을 증명하지 않는다.

## 2. Data Leakage Prevention

다음 조건을 거부한다.

- Split 간 동일 Source 또는 Incident.
- 중복 Event ID, Raw Content Digest, Source Snapshot 또는 Case.
- 같은 Source의 시간 Window 중첩.
- 데이터·라벨·Split·출처·건수·UTC 기간의 불일치.
- Candidate를 선택한 Source/Event/Incident가 Holdout에 다시 등장하는 경우.

서로 다른 출처의 독립 사건이 같은 시각에 발생했다는 이유만으로 시간 누수라고 판단하지 않는다. Source 식별의 의미가 불분명한 운영 데이터는 검증된 Holdout으로 인정하지 않는다.

평가 전 `HOLDOUT_CLAIM`을 감사 원장에 Commit한다. 동일 Holdout의 출처·Event·Content가 이미 사용되었으면 다른 Candidate, 설정, Member 순서, 추가/변경된 Development 데이터로 재사용하지 못한다. 비교 도중 실패하거나 Claim 이후 프로세스가 죽어도 사용 기록은 남는다. **재사용 제한의 범위는 동일 Runtime 감사 원장**이다. 별도 DB에서의 사용까지 통제하는 전역 데이터 관리 체계는 없다.

## 3. FN Feedback

구현: [`FailureQuery`, `capture_failure()`](../../src/soc_agent/experience/failure.py).

Finding이 없는 Source에 대해서도 피드백을 작성할 수 있다. 요구 정보는 Incident, Accepted Source Event References, Expected Rule, UTC 5분 Window와 검토 사유다. Queue→Source→Window→Provenance 연결을 재검증하고 현재 실제 `correlate()` 결과도 확인한다. 이미 탐지되었으나 아직 게시되지 않은 결과를 FN으로 잘못 취급하지 않는다.

독립 라벨이 없으면 `SUSPECTED_MISS` / `NO_INDEPENDENT_GROUND_TRUTH`다. 임의 Label Digest만으로 확정 FN을 발급하지 않으며, `independent_label_reference`가 제공되면 검증 제공자 미구현으로 거부한다. **확정 FN 저장 경로는 아직 지원하지 않는다.**

미지원 로그, 외국 Incident, 원본 누락, Digest 변조, 잘못된 Window를 거부한다. PAM sudo 모듈 실패를 OpenSSH 최종 로그인 실패 규칙의 누락으로 분류하지 않는다. 실제 출처와 검토 기록은 유지하지만 운영자의 의견을 공격 정답으로 승격하지 않는다.

## 4. LLM Failure Feedback

실제 `BudgetClient` 호출 원장의 Finding/Attempt와 검증된 결과를 결합한다. 다음 범주만 실제 증거에 따라 사용한다.

| 실제 원장 증거 | Feedback Category |
|---|---|
| `LLMTimeoutError` | TIMEOUT |
| `LLMNetworkError` | NETWORK_ERROR |
| `LLMProviderError` | PROVIDER_ERROR |
| `LLMResponseValidationError` | RESPONSE_VALIDATION_ERROR |
| `LLM_BUDGET_EXCEEDED` | BUDGET_EXCEEDED |
| 일반 조사 실패의 명시적 결과 코드 | INVESTIGATION_FAILED |

Exception 원문, Prompt 원문, Secret, 원본 인증 로그를 복사하지 않는다. 감사 참조·결과 Digest·Attempt·고정 실패 코드만 사용한다. Timeout은 네트워크 요청 취소나 서버 측 미처리를 의미하지 않는다. 기존 호출 불확실성 및 재시도 제한을 유지한다.

`CIRCUIT_OPEN`은 공유 Runtime 상태이며 READ 실패에도 영향을 받을 수 있어 Finding 단위 LLM 실패 증거로 자동 채택하지 않는다. 증거 없는 원인 분류는 거부한다.

## 5. READ Tool Failure Feedback

기존 `Tool`, Registry, AuthenticationReadGuard, GovernedExecutor, InvestigationOrchestrator를 유지했다. 실제 READ Step 실패 시 `READ_TOOL_FAILURE`에 Tool 이름, 실패 코드와 Step Digest를 기록한다.

지원 코드: `TOOL_TIMEOUT`, `TOOL_ERROR`, `READ_CAPABILITY_DENIED`. 현재 조회 대상은 실제 허용된 `read_authentication_context`다. 다른 Tool/LLM 실패를 READ 실패로 바꾸어 제출하면 거부한다. Provenance 훼손은 원본 조회 자체가 Fail-Closed되므로 검증된 Tool 실패 경험으로 우회 채택하지 않는다.

## 6. Feedback Persistence & Candidate Generation

구현: [`FailureFeedbackLoop`](../../src/soc_agent/linux_runtime/failure_feedback.py). 기존 [`OperatorServer`](../../src/soc_agent/linux_runtime/operator.py), `SO_PEERCRED`, same-UID Allowlist, 비공개 Socket, Challenge/Nonce, 8KiB 제한과 Runtime Writer Lock을 재사용한다. Actor/Reviewer를 요청 JSON으로 지정할 수 없다. OS UID는 로컬 계정 신원이며 특정 사람이 직접 검토했다는 증명은 아니다.

`soc-failure-feedback:v1`은 Feedback UUID, Query, 봉인한 Experience Snapshot, Reviewer UID/Assurance, Reason Code, Reviewed At, Feedback Digest 및 Supersedes를 갖는다. Experience는 감사 원장에 Feedback과 함께 하나의 Transaction으로 저장한다. 동일 ID/동일 내용은 멱등이고 다른 내용의 동일 ID는 거부한다. 기존 FP 피드백과 ID 충돌도 거부한다. 정정은 최신 기록을 명시적으로 Supersede하는 추가 기록이다. Audit 저장 실패 시 성공 응답을 내지 않는다.

기존 v1 Experience 및 FP 피드백 v1/Candidate v3는 보존했다. 실패 경험은 불완전한 조사를 완료 Core Experience로 위장하지 않고 별도 `soc-runtime-failure-experience:v1`에 저장한다. Projection은 실패 기록이 있을 때만 명시적 v3를 사용하며, 기존 기록만 있는 경우 기존 v2 출력 계약을 유지한다.

기존 `generate()`와 `ImprovementCandidate`를 확장했다. Candidate Type을 중복 추가하지 않고 버전 **`improvement-candidate:v4`**와 명시적인 Proposal Operation으로 구분한다.

| Trigger | Proposal Category | 기존 Candidate Type |
|---|---|---|
| FP 검토 | DETECTION_RULE_REVIEW | detection_rule_review, 기존 v3 |
| 누락 의심 | MISSED_DETECTION_REVIEW | detection_rule_review, v4 |
| 조사 실패 | INVESTIGATION_STRATEGY_REVIEW | rule, v4 |
| READ 실패 | TOOL_RELIABILITY_REVIEW | rule, v4 |
| LLM 실패 | LLM_RELIABILITY_REVIEW | rule, v4 |

후보는 Feedback/Experience 참조, 고정 Proposed Guidance, 기대 효과의 불확실성, Advisory 권한, 오프라인 검증 및 Human Review 요구를 갖는다. 중복 경험/정정 사본을 추가 Support로 세지 않는다. Source가 바뀌거나 정정으로 Support가 제거되면 기존 Candidate는 Stale로 거부한다. 원장에 Eligibility, Risk, PENDING_REVIEW를 함께 기록한다.

## 7. Offline Evaluation

기존 `evaluation.authentication.evaluate()`가 실제 Detector와 격리 Queue/Source Pipeline을 실행한다. 별도 탐지 엔진은 만들지 않았다.

Fixture 비교 자료: 기존 사전 작성 Case 4개(normal, single, repeated, transition), 고유 Event 9개. TRAINING은 normal, DEVELOPMENT는 transition, HOLDOUT은 single/repeated다. Holdout은 Event 6개, Rule 단위 10개이며 Positive 2/Negative 8이다. **기존 개발 Fixture를 분리한 계약 테스트이며 독립 운영 Holdout이 아니다.**

실제 저장된 비교 Receipt: `1879c2a971939cc8830f0f9bba15cce1878941baa78db18c1884071ccccd16e3`.

| 항목 | Baseline: repeat=3, accounts=3 | Trial: repeat=6, accounts=3 |
|---|---:|---:|
| TP / FP / TN / FN | 2 / 0 / 8 / 0 | 0 / 0 / 8 / 2 |
| Precision | 1.0 | N/A |
| Recall | 1.0 | 0.0 |
| F1 | 1.0 | 0.0 |
| FPR | 0.0 | 0.0 |
| FNR | 0.0 | 1.0 |
| 탐지 지연 | Fixture 시계 10초, 2건 | 탐지 없음, N/A |

지연은 기존 결정적 Fixture Clock이며 운영 속도 측정이 아니다. 단순 임계값 변경의 열화를 보여주는 대조 실험으로, Candidate가 실행 가능한 운영 변경을 갖거나 개선 효과가 입증됐다는 의미가 아니다.

LLM/Tool 후보는 Detector 정확도 지표로 평가하지 않는다. 동일 데이터·Failure Injection·Baseline/Candidate 구현이 연결된 안정성 Replay는 아직 없다. 개선 효과의 Timeout Rate, Failure Rate, Successful Investigation Rate, Tool Call Count, Budget Violations는 `null`이고 비교는 **BLOCKED**다. 별도 `observed_runtime_metrics`는 검증된 실제 원장의 분모를 이용한 로컬 관측치이며 개선 효과나 운영 정확도가 아니다. 실패 조사에서 전체 Tool 호출 수를 복원할 수 없으면 UNKNOWN이다. 시작 기록만 있고 응답/완료 기록이 없는 Invocation 또는 조사도 비율을 0으로 표시하지 않고 UNKNOWN으로 표시한다.

## 8. Regression Gate

현재 Gate는 보수적인 **차단 Gate**다.

- 데이터/라벨/독립성 검증 실패: 비교 실행 거부.
- Holdout 사용 기록 저장 실패: 비교 실행 전 거부.
- FP 또는 FN 증가: `REGRESSED`.
- 단순 지표 비악화: `INCONCLUSIVE_SECURITY_AND_PROSPECTIVE_VALIDATION_REQUIRED`.
- 실제 운영 Source/Label 검증 또는 안정성 Replay 부재: `BLOCKED`.
- 어떤 결과도 자동 Promotion/운영 변경으로 연결하지 않음.

Candidate별 보안·Crash Replay를 묶는 승격 가능한 완전한 Regression Certificate는 아직 없다. 공통 회귀 테스트의 통과를 개별 후보의 개선 효과로 재사용하지 않는다. 모니터 후보를 Core Checkpoint 기반 평가로 위장하여 채택하는 것도 `planning.specify()`에서 거부한다.

## 9. Human Review & CLI

기존 `RuntimeFeedbackLoop.review()` 및 ReviewDecision을 재사용한다. 후보는 PENDING_REVIEW이며 인증된 운영자는 REJECT 또는 DEFER(INCONCLUSIVE)를 기록할 수 있다. 이번 평가 결과는 충분하지 않아 APPROVE를 거부한다. 평가 Digest/후보 참조를 결합하고 중복 결정은 멱등 또는 충돌 거부다. Human Review는 운영 실행 권한이 아니다.

```bash
# 실행 중인 Monitor의 기존 승인 Socket 사용. 실제 대응/LLM 활성화 없음.
.venv/bin/python -m soc_agent.linux_runtime --directory /PRIVATE_RUNTIME operator failure-experience --input query.json
.venv/bin/python -m soc_agent.linux_runtime --directory /PRIVATE_RUNTIME operator failure-submit --input feedback.json
.venv/bin/python -m soc_agent.linux_runtime --directory /PRIVATE_RUNTIME operator failure-list
.venv/bin/python -m soc_agent.linux_runtime --directory /PRIVATE_RUNTIME operator candidates

# Monitor가 정지했을 때만 Writer Lock을 획득해 명시적인 Fixture Trial 수행.
.venv/bin/python -m soc_agent.linux_runtime --directory /PRIVATE_RUNTIME learning-evaluate CANDIDATE_SHA --repeated-failures 6 --multiple-accounts 3 --holdout-contract holdout.json --holdout-data dataset.json

.venv/bin/python -m soc_agent.linux_runtime --directory /PRIVATE_RUNTIME operator candidate-review CANDIDATE_SHA --decision DEFER --evaluation-id EVALUATION_SHA
```

`query.json`은 `FailureQuery` JSON이다. 누락 의심에는 Source Event 참조와 UTC Window, LLM/Tool 실패에는 해당 Incident/Finding ID를 넣는다. `feedback.json`은 UUID, 동일 Query, 조회한 Experience SHA, 고정 Reason Code와 선택적 Supersedes를 갖는다. Reviewer/Actor나 자유로운 명령 필드는 없다. 파일은 현재 UID 소유의 크기 제한된 일반 파일이어야 하고 Symlink를 거부한다. JSON 조회 실패를 정상 Feedback으로 바꾸지 않는다.

## 10. Actual WSL Validation

실제 Kernel: `6.18.33.2-microsoft-standard-WSL2`. 임시 비공개 Runtime DB에서 기존 journald를 읽었다. 신규 인증 시도나 시스템 변경은 하지 않았다. 32개의 제한된 Batch를 읽고 종료했으며 Journal 전체를 읽었다고 주장하지 않는다.

| Stage | 실제 결과 |
|---|---|
| Native Collection / Queue | DONE 512건; 기존 Journal 이벤트 |
| 검증 가능한 인증 Source | Accepted 1건 |
| Authentication Window | 1개 |
| Finding / READ Investigation | DONE_READ_ONLY 1건 |
| 인증된 Operator Feedback | INCONCLUSIVE 1건, OS Peer UID 검증 |
| Failure Feedback | 0건; 검증 가능한 실제 FN/LLM/Tool 실패 미확보 |
| Source/Provenance 재조회 | 성공 |
| 재시작 | 동일 Evidence Digest, Feedback 1건 복원 |
| WRITE Spy | 0 calls, WRITE_DENIED |
| 실제 LLM 호출 | 0회 |
| 독립 운영 Holdout / 확정 FN | BLOCKED |

감사 Digest: `50e9515ad4f43330217999b8b8e8102df792b3cda931899c9e2ed08d6186be24`. 실행 스크립트/증거는 `/tmp/soc-holdout-native-check.py`, `/tmp/soc-holdout-native-evidence.json`에 있다. 임시 DB는 테스트 종료 후 정리했으며 이 경로들은 영구 배포 증거 저장소가 아니다. 실제 사용자 이름·주소·호스트 식별자나 원본 메시지를 보고서에 포함하지 않는다.

## 11. Fixture / Crash Validation

실제 Tool/Execution Guard/Orchestrator/Socket/SQLite를 실행하고 **입력 및 실패만 Fixture로 주입**했다. Fake Client의 Timeout/Network/Provider/Validation Error를 실제 Provider 성공으로 표시하지 않는다. READ 실패에서는 Handler만 교체하고 Guard를 Mock으로 대체하지 않았다.

테스트: [`test_contract.py`](../../tests/unit/holdout/test_contract.py), [`test_loop.py`](../../tests/integration/failure_feedback/test_loop.py), [`test_crash.py`](../../tests/integration/failure_feedback/test_crash.py).

새 프로세스 Crash 4회를 실행했다: FAILURE_FEEDBACK Commit 직전/직후, HOLDOUT_CLAIM Commit 직전/직후. 기존 Harness의 PID/Nonce/Writer Lock 검증 후 해당 자식만 종료했다. Commit 전에는 저장된 기록이 없고 Commit 후에는 기록이 복원됐다. 사용된 Holdout은 재시작 후에도 거부됐다. Source/Window/Provenance Digest는 동일하며 Queue DONE 1건, 중복 집계·증거 손실·WRITE Spy 호출은 0이다. Exactly-once 외부 LLM 호출을 주장하지 않는다.

## 12. Regression & Security Results

최종 실행별 결과이며 서로 중복되는 테스트를 합산하지 않는다.

| 실행 범위 | 결과 | 로그 |
|---|---|---|
| Holdout/Failure, 기존 Runtime Feedback, Budget 검사 | **58 passed, 0 failed**, 67.50초 | `/tmp/soc-holdout-final-focused.log` |
| Runtime, S01~S12, Operator, Feedback Loop, Authentication Crash, LLM Transport, Operational Features, Detection, Approval/Execution | **449 passed, 0 failed**, 335.63초 | `/tmp/soc-holdout-runtime-regression.log` |
| Candidate/Offline/Review/Promotion Unit, Experience/Candidate/Review Integration, Promotion Eligibility | **107 passed, 0 failed**, 111.01초 | `/tmp/soc-holdout-core-regression.log` |
| 이후 미완료 Invocation UNKNOWN 관측 보완 검사 | **3 passed, 0 failed**, 5.34초 | `/tmp/soc-holdout-telemetry-final.log` |
| Ruff `check src tests` | PASS | `/tmp/soc-holdout-lint-complete.log` |
| Ruff `format --check .` | PASS, 796 Python files | `/tmp/soc-holdout-format-complete.log` |
| `git diff --check` | PASS | 콘솔 검사 |

58개 집중 실행은 **신규 43개**와 기존 15개의 검사다. 이후 미완료 Invocation 관측 테스트 1개를 추가하고 해당 테스트 및 직접 관련된 2개를 실행했다. 신규 테스트는 총 **44개**이며 실행별 중복 수치를 합산하지 않는다. 초기 개발 중 잘못된 테스트 Import/DB 컬럼/Tool 변경 방식 및 설정값을 수정했으며 최종 실패는 0이다. 테스트를 삭제하거나 skip/xfail로 바꾸지 않았다. 전체 저장소 회귀·장시간 Soak·전체 Promotion Activation 통합은 재실행하지 않았다.

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q tests/unit/holdout tests/integration/failure_feedback tests/integration/runtime_feedback tests/integration/linux_runtime/test_monitor.py::test_budget_checks_tool_and_call_limit_before_execution
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q tests/integration/linux_runtime tests/integration/scenario tests/integration/live_operator tests/integration/feedback_loop tests/integration/authentication_stability tests/unit/llm tests/unit/operational_features tests/unit/detection_evaluation tests/unit/approval tests/unit/execution
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q tests/unit/improvement_candidates tests/unit/offline_evaluation tests/unit/improvement_review tests/unit/improvement_promotion tests/integration/experience tests/integration/improvement_candidates tests/integration/improvement_review tests/integration/improvement_promotion/test_eligibility.py
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check .
git diff --check
```

## 13. Changed Files & Preserved Boundaries

소스 13개, 신규 테스트 3개, 이 문서 1개. Stage/Commit/Push 없음.

검증 작업 파일 16개(소스·테스트)의 SHA Manifest Digest: `1749a178fcc5fb87b2942861eab441197e75f2c6da6f796bc72637e7f2521bee`. 아래 파일 SHA Mapping을 경로순 compact JSON으로 직렬화한 SHA-256이다. HEAD만으로 미커밋 내용을 식별하지 않는다.

| File | SHA-256 |
|---|---|
| `src/soc_agent/experience/failure.py` | `830ac5c9bd294c428afc5ebdd7eb991b3eef4229e1cf211739320a16fb9f2463` |
| `src/soc_agent/improvement_candidates/generation.py` | `8277a078cc48c3eccf872cb6986db3528ffa19c6c888e0754e7ef1c4adffe47f` |
| `src/soc_agent/improvement_candidates/models.py` | `3bcb39e6c3bd7370de3d40c96ddb6ad7414223ada4b20ac38324906cdaadfeac` |
| `src/soc_agent/improvement_candidates/runtime_models.py` | `171a568c05b47c9a836aea5174ad0c1746dd178410af23a1620816aee1e2fab9` |
| `src/soc_agent/linux_runtime/__main__.py` | `f4c264c3c5e653870d110594325d4045e16c6384b93fd4dbbcbf1eafcefd0ada` |
| `src/soc_agent/linux_runtime/failure_feedback.py` | `ed3348ad561a84f777616c848fe5cb6dda1f0ae865d2b487d53a678b42cbd3c5` |
| `src/soc_agent/linux_runtime/feedback_loop.py` | `cf0344710c5eb8de82298cc9af9e9d5512f51a24f07b026df96724c0d38d46ad` |
| `src/soc_agent/linux_runtime/feedback_projection.py` | `2b8ad2bbc4312276483ba92f62f16462b780e522a341b7c4f0bc4b4307e822b8` |
| `src/soc_agent/linux_runtime/holdout_evaluation.py` | `5bae13363b0db37113f07ef8cb0f47fbf96db96cb916112b3d84a8206df2d7e3` |
| `src/soc_agent/linux_runtime/operator.py` | `4bc3a255306b2162a2e43e2daa61935dc59d11132984f3a6d3fdc572f3208327` |
| `src/soc_agent/linux_runtime/service.py` | `4cd974aef784d137d393bd156e065bddae175d8ea84493406cba718aacbc757d` |
| `src/soc_agent/offline_evaluation/holdout.py` | `fe6dbb28aaca1643e1f1ddb03cafd0f7fe6518a0844215354db85549840dc309` |
| `src/soc_agent/offline_evaluation/planning.py` | `cf3e92598f2d169ffa3ca4b85b5227639dbc00f883799446ea6f000e160c3b40` |
| `tests/integration/failure_feedback/test_crash.py` | `c7b994e4e4709aa513170c1a9edd5e25ee9542c04d4865e5ab620996835d8e02` |
| `tests/integration/failure_feedback/test_loop.py` | `8a830923a6e3ca68dcfdf91b3d890f61db5dd542d62964cc4a62b69b2909d2be` |
| `tests/unit/holdout/test_contract.py` | `7636b3adc095154e437b3df1dcc2fc6bca648ee9a13d8f943021eeb7073ab24e` |

신규 소스:

- `experience/failure.py`
- `linux_runtime/failure_feedback.py`
- `linux_runtime/holdout_evaluation.py`
- `offline_evaluation/holdout.py`

수정 소스(모두 `src/soc_agent/` 아래):

- `improvement_candidates/models.py`, `runtime_models.py`, `generation.py`
- `linux_runtime/__main__.py`, `operator.py`, `feedback_loop.py`, `feedback_projection.py`, `service.py`
- `offline_evaluation/planning.py`

기존 `README.md`, `docs/soc-command-center.md`, `pyproject.toml` 사용자 수정은 시작 시점 SHA와 동일하다. 기존 미추적 파일도 보존했다. 보호 파일 `tests/fusion_support.py` SHA는 `e5f9d10f706f71b82e80261f7633a1504e27ba24499be948d04adb6eeb3a21c9` 그대로다. Synthetic v2의 `external/models.py`, Operational Provenance v3의 `operational/provenance.py` 내용도 시작 SHA와 동일하다.

DB Schema/Migration 없음. 기존 Append-only Hash Chain의 새 Event 종류를 사용하며 기존 Event 의미/Hash를 바꾸지 않았다. READ_ONLY, WRITE_DENIED, Policy/Approval, Incident Binding, Network/DNS NOT_INFERABLE를 유지했다. 자동 정책·승인·코드·모델 변경, Promotion, OS 대응은 연결하지 않았다.

## 14. Remaining Risks / Future Physical Linux Validation

1. 독립 운영 라벨·출처·Training/Development 분리 기록 및 원본 대응 자료가 없다. 외부 라벨 검증 Adapter와 승인된 데이터 관리 절차가 필요하다.
2. 확정 FN 연결은 미구현이며, 지원되는 원본의 누락 의심만 저장한다. 실제 미탐 사례와 독립 라벨을 먼저 확보해야 한다.
3. LLM/Tool 후보는 실행 가능한 Candidate Replay가 없어 개선 효과 비교가 BLOCKED다. 수정 후보를 명시적으로 구현한 뒤 동일 고정 Failure Dataset으로 안정성/회귀를 비교해야 한다.
4. 후보별 보안/Crash/재현성 Certificate와 운영 승인 가능 Gate는 아직 없다. 지표만 좋아졌다는 이유로 승인할 수 없다.
5. 로컬 원장 밖 Holdout 반복 사용, namespace의 외부 진위, 복수 운영자 역할 분리, 큰 감사 원장의 성능·동시 조회·장시간 안정성은 미검증이다.
6. 기존 User Worktree 변경이 있어 HEAD만으로 이번 결과를 재현할 수 없다. 이 문서의 변경 파일과 검증된 작업 트리를 함께 보존해야 한다.
7. 물리 Linux 서버의 최소 권한, 실제 sshd 인증 성공/실패, journald Rotation, 서비스 재시작 및 장시간 부하는 후속 검증이다. Windows/AWS는 실행하지 않았다.

현재 구현은 검토용 실패 경험의 안전한 축적 기반이다. **운영 개선 효과 VERIFIED, 자동 Promotion 가능, 확정 FN 정답 확보를 의미하지 않는다.**
