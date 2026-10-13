# Gate B-2 — External Context v2 검증 계획

상태: **PLANNED / 이번 단계에서 아래 신규 테스트를 구현·실행하지 않음**.
계약: [integration-contract-v2.md](integration-contract-v2.md).
기존 2606/25, 외부 194, Windows 진단 7은 Gate B-1 증거이며 신규 integration PASS가 아니다.
기존 Gate A scripted fixture 판단 동등성은 신규 Network/DNS 판단 동등성과 분리한다.

## 1. 테스트 층과 실제 모델 증거

| 층 | 실제 검증 | Fake 허용 범위 |
|---|---|---|
| Unit | strict types, serialization, binding, score semantics, dedup/errors/bounds | typed predictable fake predictor로 isolation 가능; 실제 ML PASS 주장 금지 |
| Artifact/native | external public loader, pinned package/model/scaler, 실제 CPU inference | 성공 경로 predictor/loader/hash 검증은 Mock 금지 |
| SOC integration | 원본 source Evidence, existing runtime/assessor/decision/guards, durable receipt | LLM은 scripted, read-only tool은 fixed source record를 반환하는 test adapter; domain logic real |
| Security oracle | 허가 없는 실행/변조/stale/범위 위반 차단을 comparator와 별도 판정 | 실제 WRITE handler 대신 호출 시 실패 sentinel; 권한 검증 자체 Mock 금지 |
| Native Windows | 실제 Conda Python + NTFS private storage + model backends | Linux mock 결과로 Windows 지원 PASS 금지 |
| Equivalence | 같은 input/artifact/config/source binding, stage outputs와 policy/guard 비교 | 두 환경에 같은 미리 만든 Decision JSON을 반환하는 Mock 금지 |

새 fixture는 existing Golden Fixture를 수정하지 않는 별도 versioned namespace에 만든다.
Top40/DNS9 precomputed synthetic vector와 source event ID/entity namespace/UTC window/원본
Evidence content를 함께 고정한다. 고정된 bytes SHA와 float32 input fingerprint를 모두 기록한다.
“정상/이상”은 실제 모델 label 기대를 확인한 fixture에서만 모델 분류 의미로 사용하며,
실제 공격 ground truth 또는 모델 정확도 평가로 확대하지 않는다.

## 2. 정상·모델별 입력 검증

| ID | 시나리오 | Oracle / 실제 확인 |
|---|---|---|
| N01 | Quality native Top40 | 40 exact names, pinned LightGBM/metadata, 15-class mapping 및 actual result |
| N02 | Edge native Top40 | checkpoint epoch13/ordered features, actual fitted scaler transform, FP32 native output |
| N03 | DNS native stateless9 | exact scaler names, transform only, INT8 shapes/quantization, probability/label/threshold |
| N04 | Network만 source Evidence 있는 incident | 하나의 source observation + 선택 profile Context, 기존 v1 결과와 병렬 보존 |
| N05 | DNS만 source Evidence 있는 incident | DNS를 Auth/기존 network로 coercion하지 않음; 새 source binding 사용 |
| N06 | Network + DNS 명시적 fixture association | 두 observation 유지, 같은 incident 표시만 검증; causality/common actor 주장 없음 |
| N07 | Quality/Edge 동일 관측 출력이 다름 | 2 model results / 1 observation group, 상충 결과 보존, 평균·double count 없음 |
| N08 | 양 domain의 benign/non-benign model label | prediction 의미만 유지, IncidentState severity/status/approval 불변 |
| N09 | named input dict order 변경 | 외부 canonical ordered matrix 동일, 잘못된 실패 처리 금지 |
| N10 | opt-out legacy composition | existing 3 SOC models/live/demo/dashboard 경로 그대로, heavy import 미요구 |

## 3. 잘못된 Envelope·Artifact·Feature

| ID | 오류 | 기대 결과 |
|---|---|---|
| E01 | outer/nested schema unknown version, unknown field, missing field | validation reject, inference/LLM/execution 없음 |
| E02 | unpinned model ID/version/profile/package code identity | trusted setup mismatch; producer VALID 선언 무시 |
| E03 | Network 39/41 names 또는 DNS 8/10 names | exact contract reject, missing feature 자동 생성 없음 |
| E04 | Top40 rank order/scaler feature order 변경 | actual loader/contract reject; dict 삽입 순서와 구분 |
| E05 | 기존 5-feature를 Top40로 전달 / Auth를 DNS로 전달 | coercion/추정 채우기 없이 거부 |
| E06 | DNS None/negative/NaN/Inf/string/bool/overflow | 입력 거부, scaler/model load가 호출되지 않음 |
| E07 | Network missing explicit null / transport NaN/Inf | null은 기존 외부 missing 규칙으로 native 검증; invalid JSON nonfinite는 admission 거부 |
| E08 | DNS scaler 누락/다른 scaler/model pairing | public verify_bundle/load가 hash/shape/order 검증 후 실패 |
| E09 | model/archive/catalog/member SHA/size 변조 | deserialization 이전 reject, source/기존 artifacts overwrite 없음 |
| E10 | model corruption / DNN weights 구조/epoch 불일치 / INT8 tensor 불일치 | 실제 loader 오류, benign fallback 없음 |
| E11 | duplicate JSON keys, malformed UTF-8, nonfinite probability, invalid sum/argmax/label | existing 외부 validator + SOC admission 거부; tolerance 확대 없음 |
| E12 | score_type/calibrated/attack_confirmed 위조, threat_score 또는 threshold 변경 | 원래 의미와 literal 검증, 임의 risk/approval로 변환 없음 |
| E13 | manifest/path from model request, symlink/reparse/traversal | trusted root/containing path 검증, untrusted file/pickle load 없음 |
| E14 | context/envelope/source size 또는 64000자 prompt 초과 | bounded sanitized diagnostic; provider 호출 전 실패, Context 조용히 누락하지 않음 |

손상 테스트는 dedicated temp copy를 변경한다. 원본 ML/SOC 모델 파일을 고치지 않는다.
현재 실제 모델 artifact checksum과 native 결과 성공은 별도 파일로 기록하고 위 unit fakes와 합치지 않는다.

## 4. Provenance·중복·시간·사건 연결

| ID | 시나리오 | 기대 결과 |
|---|---|---|
| P01 | Artifact/model/scaler/feature/label digest 또는 source provenance 누락 | INVALID, trusted incident Context에서 제외 |
| P02 | shape-valid imported Envelope만 전달 | local managed inference provenance 불명확 → eligible 아님; hash가 authenticity 증명이 아님 |
| P03 | envelope metadata와 payload identity/time/ref 불일치; model_copy 우회 | nested round-trip validator 및 setup 대조가 reject |
| P04 | UUID만 새로 만든 동일 Network 재포장 | 동일 semantic key/output → 한 contribution, bounded aliases; observation 수 불변 |
| P05 | 동일 source ID의 서로 다른 data / 동일 inference key의 다른 prediction | 충돌 저장/거부; 이전 결과 overwrite 또는 평균 없음 |
| P06 | 잘못된 incident/source Evidence ID 또는 같은 ID에 다른 content | existence만으로 통과 안 함; exact snapshot/content/derivation 검증 reject |
| P07 | evidence timestamp/entity/window binding 변경 | 거부; naive time 자동 UTC 추정 금지 |
| P08 | source interval 역전, missing time, inference-before-event, 미래 time | explicit clock/window policy로 거부/UNLINKED; wall clock 비교 제외로 우회 금지 |
| P09 | 같은 IP/비슷한 시각만 있는 Network/DNS | 자동 merge/actor 추정 없음, cross-domain UNVERIFIED |
| P10 | 순서가 다른 source 입력, 정확한 duplicate replay | ID/content identity 보존, context canonical sort와 source order 계약 구분 |
| P11 | new Evidence/snapshot 이후 cached Context/assessment | stale 거부, 새 binding 검증 필요; 기존 approval 재사용 불가 |
| P12 | model unavailable/not configured/not applicable | coverage 보존, fake score/HEALTHY/NORMAL 없음; required 실패 시 analysis fail-closed |
| P13 | UNVERIFIED DNS training/scaler pairing/calibration | 제한을 보존; artifact bytes PASS를 operational reliability로 확대하지 않음 |

time 변조는 `original + timedelta(seconds=1)` 같은 고정 의미 차이 또는 fixture 내 고정 시각을
사용한다. wall-clock `now()`를 연속 호출해 Windows timer precision 때문에 변조가 없어지는
테스트를 만들지 않는다. boundary policy의 exact equality/before/after 사례를 따로 검증한다.

## 5. Assembly / Investigation / Assessment / Decision

| ID | 검증 | 보안 Oracle |
|---|---|---|
| I01 | v1 Fusion 없는 외부 Context | 새 advisory-only draft, observations/hypotheses 빈 배열, state 불변 |
| I02 | v1 Fusion과 v2 Context 동시 | 개별 출처/label/score/coverage 보존; 동일 context로 flatten/average하지 않음 |
| I03 | source Evidence가 없는 incident | 기존 NoEvidenceError 유지, 모델 결과로 Evidence 만들어 진행하지 않음 |
| I04 | actual LLM request projection | 구조화된 v2 section/limitations/ref가 포함됐는지 scripted client에서 관찰; mock Decision 사전 반환 금지 |
| I05 | 모델/metadata/LLM에 실행·승인 지시 포함 | 데이터로 취급, tool schema/permission/authority에 적용하지 않음 |
| I06 | 높은 score / advisory high assessment | v1 engine의 실제 outcome, severity는 advisory; IncidentState 자동 변경 없음 |
| I07 | 외부 모델과 Assessment 상충 | 양쪽 유지, context receipt로 차이 추적, core outcome 임의 override 없음 |
| I08 | 반복 조사 의도 및 round limit | 기존 runtime loop guard/attempted canonical identity 유지, 추가 무한 loop 없음 |
| I09 | exact-type validation 및 store.append_assessment | core result 타입 유지, advisory no-op StateAnchor/기존 audit 의미 보존, early-return에서도 신규 assessment-run/receipt 저장 |
| I10 | DECIDE 및 audit/read surface | 실제 engine 사용, core decision ID + exact content digest + Context receipt 연결 |

첫 planner가 모델 Context를 받았다고 주장하지 않는다. B-3의 실제 모델 호출 시점은 existing
ANALYZE다. prior read-only evidence collection → model analysis → assessment → decision의
수행 stage를 trace에 그대로 기록한다. GUARD/ACT/EVALUATE 미도달은 미도달로 보존한다.

## 6. Policy / Approval / Execution Guard

| ID | 테스트 | 기대 결과 |
|---|---|---|
| S01 | 승인 없는 WRITE | 실제 Policy/Approval/Executor preflight 거부, sentinel call 0 |
| S02 | 금지 tool/action 또는 정책 DENY | model/LLM 권고와 관계없이 실제 guard 거부 |
| S03 | invalid/expired identity 또는 confirmation | 해당 실제 TTL/RBAC validator 거부; legacy ApprovalRequest에 없는 TTL을 있다고 가정하지 않음 |
| S04 | approval incident/tool/input/범위 불일치 또는 forged format/token | 기존 issuance/binding/replay validation 거부 |
| S05 | promoted Stable Action ID 불일치 | existing response bridge/preflight binding validator 거부, 실제 action 실행 없음 |
| S06 | source Evidence/context/assessment/decision receipt 변조 | 권한 평가 이전 provenance failure; 같은 잘못된 ALLOW도 oracle FAIL |
| S07 | valid legacy approval로 v2-bound decision response 요청 | B-3 read-only backend ceiling에서 거부; v1 합법적 경로는 회귀 유지 |
| S08 | direct service/API를 통해 CLI ceiling 우회 | state authorization/promotion/bridge/preflight 각각 거부 |
| S09 | context disabled/missing lineage로 v2 run 재개 | fail-closed, legacy workflow로 downgrade하지 않음 |
| S10 | unknown/UNCERTAIN commit 또는 external execution state | 기존 uncertain semantics와 manual reconciliation 유지, 자동 retry 없음 |
| S11 | context/decision ID를 생략한 direct ActionProposal | dedicated validation DB capability와 read-only registry로 backend 거부; Context 누락으로 ceiling 해제 불가 |

승인 만료 검증은 실제 구현된 principal/session/confirmation 경계에서 수행한다.
legacy ApprovalRequest TTL은 Gate A에서 미구현으로 기록돼 있으므로 해당 케이스는
NOT_APPLICABLE 이유를 보고한다. 기존 approval 검증을 우회하는 fake 만료 테스트를 만들지 않는다.
부작용 sentinel과 별도로 policy outcome/approval validity/blocked reason/state invariance/audit
기록을 확인한다. 양 OS가 같은 잘못된 권한을 부여하면 equality와 무관하게 **FAIL**이다.

## 7. Persistence / Migration / Restart

| ID | 검증 | 성공 조건 |
|---|---|---|
| D01 | untouched v14 기존 기능 | 이전 serialize/hash/Golden/selection 상태 그대로; external opt-out 회귀 |
| D02 | explicit v14→v15 candidate migration | atomic DDL/metadata, 신규 tables 정확히 생성; 실패 rollback |
| D03 | old binary가 v15 open | unsupported-schema 거부; 실제 old executable 없으면 native 결과 NOT RUN |
| D04 | v15 unknown/missing external schema/table/digest | startup 거부; silent adoption/recreate 없음 |
| D05 | assessment-run+receipt transaction 실패 | 신규 core snapshot/receipt는 함께 보존되거나 함께 rollback; original state가 no-op이어도 companion 누락 없음 |
| D06 | checkpoint+companion link CAS 경쟁 | 하나의 revision publication만 성공, stale loser/foreign run 거부 |
| D07 | assessment commit 후 checkpoint publish 전 강제 종료 | claimed workflow는 기존 WorkflowInFlight; 자동 inference/LLM 재실행 없음 |
| D08 | journal/WAL/SHM insecure ACL/mode/reparse/path replacement | 기존 storage 검증 실패, sidecar 삭제/권한 완화로 우회 없음 |
| D09 | reopen/restart | exact original context/assessment/decision hashes 재검증, semantic duplicates 증가 없음 |
| D10 | changed config/model artifact 또는 stale context로 restart | 이전 cached loaded model을 바꾼 artifact와 혼합하지 않음; fail-closed |

migration 테스트는 고립된 DB에서만 한다. 기존 사용자 DB나 Windows 결과 디렉터리를
overwrite하지 않는다. native Unicode/space path, runtime exclusive lock 및 cleanup 테스트도 유지한다.

## 8. 교차 플랫폼 비교 계약

새 proposed export contract: `soc-external-decision-trace:v2`.
기존 `tests/decision_pipeline_contract.py`와 Gate A trace comparator는 그대로 둔다.
새 비교 결과는 `PASS / FAIL / INCONCLUSIVE / NOT_APPLICABLE` 및 검증한 scope를 가진다.

필수 identity: same fixture bytes SHA, source canonical digest, feature float32 input hash,
binding/artifact/scaler/feature/label hashes, package version/code provenance, actual policy 및
configuration SHA, assembly/validation rules. 빠지거나 다르면 PASS로 처리하지 않는다.
OS/native binary build의 exact environment digest는 당연히 다를 수 있으므로 원본을 각각
보존하고 동일한 runtime contract 충족 여부를 검증한다. 이 값 자체가 같다고 요구하지 않는다.
반면 backend/effective inference 설정/필수 dependency version 차이는 편의상 제외하지 않는다.
actual native model artifact/preprocessing mismatch는 numerical tolerance로 통과시키지 않는다.

Numeric: native dtype/bit representation 확인 후 probability/margin/error/ULP 측정. 외부 결과가
float64로 표현돼 있어도 원래 float32를 입증하지 못하면 float32 ULP라고 주장하지 않는다.
LightGBM/FP32 DNN/INT8 DNS 각각의 계약을 따로 검사한다. 임의 새 tolerance는 없다.
DNS threshold 0.5의 직전/동일/직후는 synthetic output validator 테스트와 실제 모델의
quantization-grid output tests를 구분한다. Network는 argmax class tie/order 경계를 검증한다.
실제 score/운영 policy에 없는 threshold를 새 규칙으로 만들지 않는다.

Comparison은 class/threshold/assessment severity/core decision/policy/approval requirement/guard
차이를 반드시 별도로 보고하고, 보안 판단 차이를 작은 ULP라고 무시하지 않는다.
stage result 및 실제 provider request projection을 확인한다. stage 미실행은 INCONCLUSIVE다.

Trace normalization은 run UUID, 생성 receipt UUID, process metadata, temp paths, execution latency 등
명시적 incidental 필드만 대응 관계로 정규화한다. raw trace의 exact SHA는 먼저 검증한다.
source event/observation/Evidence identity, security timestamps, incident linkage, StateAnchor,
approval expiry 및 stable action binding은 편의상 제거하지 않는다. 독립 DB store/run UUID는
검증된 snapshot lineage를 유지하는 mapping으로 대응시키고 source identity와 섞지 않는다.
기존 read-only executor가 생성한 Evidence UUID를 fixture에서 고정할 수 없는 경우에는 양쪽
source namespace/record ID/content digest/time/tool provenance가 정확히 같은 record라는
검증 후 bijective UUID mapping을 만든다. 모든 supporting references도 같은 mapping을 적용하며
foreign/missing/duplicate 참조를 정규화로 숨기지 않는다. 각 환경의 원본 StateAnchor fingerprint와
Decision/Context digest는 먼저 재계산해 검증한다. cross-platform 비교는 검증된 graph를
정규화한 뒤 수행하고 raw digest 자체가 같다고 주장하지 않는다. fixture가 직접 정한 source ID는
mapping 대상으로 삼지 않는다.
실제 clock 정책이 달라 같음을 입증하지 못하면 INCONCLUSIVE다.

Windows/Linux dependency backend/load/root-security 조건을 실제 환경에서 확인한다.
WSL, Windows native, Linux Desktop, Linux Headless 운영 검증을 서로 대체하지 않는다.
원본 같은 artifact를 전송하고 SHA가 다르거나 기존 파일 충돌이면 동기화 전에 중단한다.

## 9. Gate B-3에서 사용할 명령 계획

다음 경로/CLI는 **B-3 신규 테스트/도구 후보**이며 지금 존재/동작한다고 주장하지 않는다.
실제 구현 후 `--help`와 파일 경로를 확인해 최종 실행 명령을 확정한다.

```bash
# Gate B-3 구현 승인 후 집중 테스트 후보
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q \
  tests/unit/security_ai/external tests/integration/demo/test_external_context.py

# 현재 존재하는 v1 회귀 경로
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q \
  tests/integration/demo/test_decision_pipeline_equivalence.py \
  tests/unit/security_ai/fusion tests/unit/assessment tests/unit/decision \
  tests/unit/policy tests/unit/approval tests/unit/execution tests/unit/identity

# 집중 검증 후, 결과를 별도 파일에 보존하는 전체 회귀
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check .
git diff --check
```

Windows는 SHA manifest의 신규 파일만 conflict preflight/exclusive creation으로 동기화한다.
기존 파일이 다른 경우 자동 overwrite하지 않고 충돌로 중단한다. 실제 runtime dependencies는
임의 upgrade 없이 준비하고 configured backend가 없으면 명시적으로 실패한다.

```powershell
# B-3 구현 및 승인된 의존성 준비 후에만
conda activate soc-windows
Set-Location C:\soc-agent-windows-test
$env:RUN_LIVE_LLM_TESTS = "0"
python -m pytest -q --tb=short -rs -rfE `
  tests/unit/security_ai/external tests/integration/demo/test_external_context.py
python -m pytest -q --tb=short -rs -rfE `
  tests/integration/demo/test_decision_pipeline_equivalence.py `
  tests/unit/security_ai/fusion tests/unit/assessment tests/unit/decision `
  tests/unit/policy tests/unit/approval tests/unit/execution tests/unit/identity `
  tests/unit/persistence/test_native_windows_storage.py
# 집중/실제 모델/trace 검증 후 전체 회귀
python -m pytest -q --tb=short -rs -rfE
python -m ruff check src tests
```

Trace export output은 새 private directory이며 기존 결과가 있으면 중단한다.
현재 Gate B-1 standalone smoke 도구만으로 SOC Decision Trace를 검증할 수 없다.
새 diagnostic의 CLI/contract가 구현되기 전 export/compare가 실행 가능하다고 가정하지 않는다.

## 10. 완료 Oracle 및 산출 증거

각 항목은 별도 상태로 보고한다: external package identity, artifact integrity, 실제 Quality/Edge/DNS
inference, adapter validation, Context assembly, SOC assessment/decision 연결, security correctness,
durable resume, Windows native execution, cross-platform equivalence, 기존 v1 regression.
Unit Mock 성공, native standalone 성공, SOC 연결 성공을 각각 분리한다.

보안 Oracle 필수: original Evidence 수/content 불변, 모델 signal이 Observation/Hypothesis에
추가되지 않음, unauthorized severity/status 변경 0, approval/confirmation 자동 생성 0,
privileged sentinel 실행 0, live provider 0, same-observation double count 0, stale/tamper reject,
old reader downgrade/Context 생략 resume 거부. LLM이 모델 우려를 반영했는지와 단순히 request에
Context가 존재했는지를 따로 기록한다.

새 fixture/input/model/policy identity가 없거나 Windows native trace가 없으면 전체 통합/동등성은
INCONCLUSIVE다. source training/calibration/운영 효능 검증은 synthetic E2E 성공으로 PASS가 되지 않는다.
각 결과 파일은 신규 경로 exclusive creation, SHA manifest, 실행 명령/환경/actual stage/범위를
포함한다. 기존 Gate A/B-1 report/trace/Golden/model artifacts는 그대로 보존한다.

이번 Gate B-2는 설계 문서의 completeness/code-contract 일치 및 변경 범위 검사만 수행한다.
위 계획을 승인 또는 구현/실행한 것으로 표시하지 않는다. 설계 완료 후 사용자 검토까지 중단한다.
