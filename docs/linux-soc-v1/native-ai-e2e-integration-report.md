# Native AI E2E Integration

2026-10-27. **INSTRUMENTED — post-capture Native→AI 실행 경로 구현·비권한 검증 완료, 실제 Native E2E는 BLOCKED.**

적격 TCX 벡터가 들어오면 기존 모델 Worker·Incident·조사·Audit로 전달하는 운영 경로를 연결했다. 실제 Native 입력에는 별도의 정확한 모델 분석 Action 승인이 필요하다. 이번 작업은 Root·Capture·DNS 트래픽·실제 LLM API를 실행하지 않았다. 전용 Namespace용 Supervisor는 기존 preview 정책 차단이 남아 있으므로 현재 Artifact를 EXECUTION_READY로 표시하지 않는다.

## 브랜치와 보존

- Native 브랜치 `fix/native-stabilization-batch3`: `a93045cb983900cb64f4f49659ffcc485d429983`.
- AI 브랜치 `feat/ai-pipeline-integration`: `82b1dc1666fde2869df2c037c36bf006cd43ce16`.
- Native HEAD가 AI HEAD의 ancestor임을 확인했다. AI에는 Native 변경이 이미 포함돼 있어 Cherry-pick/Merge 없이 별도 Worktree·`feat/native-ai-e2e-integration` 브랜치를 만들었다.
- 원본 `main` Worktree의 사용자 변경과 이전 AI Worktree의 Batch2/Batch3 보고서 사용자 변경을 SHA로 보존했다. 기존 설치·Rollback·Native 증거·Ledger/Audit를 변경하지 않았다.
- 구현 Commit: `fee04cc2fbbafc165ff681b7ccf9a206d8d0f949`.
- 구현 Tree: `5fdb05b27661d7749b6f87f3a130574e6d73c595`.

## 연결된 운영 데이터 경로

```text
approved Supervisor → supervised-result.json
  → soc-agent analyze-offline (exact file SHA + expected Session/Namespace/Release)
  → TCXAnalysisJob
  → raw CPU snapshots / counters / clock / CLOSED / drain reassessment
  → existing input_receipts, per-candidate ELIGIBLE / INCOMPLETE / INVALID / UNKNOWN
  → exact human-approved post-capture Action (REAL_NATIVE only)
  → existing bounded ResearchAdapter / Worker / pinned RF-LR artifacts
  → InferenceRecord / binary-model comparison / advisory Incident
  → existing Planner / read-only GovernedExecutor / Assessor
  → private result + original model receipts + hash-chained Audit
```

Collector는 기존 Supervisor/TCX/FlowAssembly/Checkpoint를 그대로 사용한다. 저장된 `capture_evidence.status=VERIFIED`를 승인으로 믿지 않는다. 원본 Per-CPU snapshot·counter·clock sample·CLOSED·drain에서 기존 `assess_capture`와 `input_receipts`를 다시 계산하고, 보존된 capture receipt와 일치하는지 확인한다. Session·Namespace·lo/Ingress·Release·Source origin도 검증한다. INCOMPLETE/INVALID/UNKNOWN 벡터는 Worker에 전달하지 않는다. Drain 실패가 INVALID를 INCOMPLETE로 완화하지 않도록 상태를 보존한다.

원본 result에는 이벤트 monotonic timestamp·Counter epoch·Clock·Flow lifecycle이 남고, 입력 영수증에는 Window digest·Source provenance·Flow 완료 상태·Feature fingerprint가 남는다. 모델 영수증은 이 입력 영수증 digest와 전체 source digest, Session·Namespace·Release·Flow·ordered Feature·Artifact/Manifest SHA를 참조한다. Kernel monotonic 시간을 임의 UTC로 변환하지 않으므로 Envelope의 observed_at은 None일 수 있다.

Source file pin은 연속성 검증이며 원본 진위의 암호학적 증명이 아니다. 입력 Source Assurance는 실제 파일이어도 `DECLARED_UNATTESTED`로 남는다. 승인된 Collector 출력/정확한 원본 SHA를 선택하는 것은 trusted 운영 composition의 책임이다. JSON의 source 이름·actor 문자열만으로 인간 권한이나 물리 Capture를 인증했다고 주장하지 않는다.

### 운영 Entry Point

기존 `analyze-offline`에서 일반 Job뿐 아니라 Supervisor 원본 JSON을 직접 받을 수 있다.

```bash
soc-agent analyze-offline \
  --input /private/supervised-result.json --input-sha256 <exact-file-sha> \
  --tcx-namespace 'net:[4026532232]' --tcx-session <capture-session> \
  --tcx-release-manifest <actual-root-manifest> \
  --research-ml-root /home/geonug/kdt-linux/ML \
  --output /private/new-analysis-attempt \
  --tcx-approval /private/human-action-approval.json \
  --tcx-approval-sha256 <human-verified-approval-file-sha>

# No credential load, API call, reservation or model rerun:
soc-agent analyze-offline --verify --output /private/new-analysis-attempt
```

Native 실행 승인은 이 명령의 모델 분석 승인을 대신하지 않는다. 기존 ApprovalRequest/ActionProposal/ApprovalManager/PolicyEngine/GovernedExecutor를 재사용하고 새 승인 체계를 만들지 않았다. `analyze_retained_tcx`는 FILE_READ/MEDIUM으로 기존 정책의 정확한 Action 승인을 요구한다. Approval의 SHA는 운영자가 검증한 trust anchor여야 하며, JSON schema 자체가 승인자 인증은 아니다. 유한 expiry·결정 시각·Incident/Action/Input/Permission/Risk Binding을 검증한다.

`tcx_analysis.analysis_action(job, directory)`가 입력 전체·구현 코드·새 출력 디렉터리·Session·Namespace·Release에 묶인 기존 Action을 생성한다. 승인이 없으면 pending 요청만 보존하고 모델 호출 0회로 끝난다. Codex는 실제 긍정 결정을 발급하지 않았다. Root/R1 receipt는 다른 schema/scope이므로 모델 승인으로 재사용하지 않는다. 같은 출력 디렉터리 재사용은 거부한다. 기존 generic approval 경계의 actor 인증 책임을 우회하거나 강화했다고 주장하지 않는다.

모델 분석은 Capture가 종료된 후 ordinary UID의 별도 process에서 수행한다. Root 프로세스나 격리 Namespace 내부에서 LLM을 실행하지 않는다. Model Worker에는 API key가 전달되지 않고 네트워크가 차단된다. Collector의 `native_ai=BLOCKED`를 덮어쓰지 않는다. 조사 도구 Registry에는 Native 모델 실행 도구를 노출하지 않는다.

## 모델·Fusion·Incident·LLM

Network14는 기존 float32 14개 ordered contract와 대조하고, 원본 fingerprint·유한값·범위·packet count·duration 및 timeout/window 근거를 검증한다. 모델은 기존 RF/LR 타입·14개 입력·버전·threshold·Artifact SHA를 Worker에서 확인한다. XGBoost/Network IF/Authentication IF의 기존 5개 Feature 경로는 보존하며 Network14를 이 모델들에 넣지 않는다.

| Profile | 실제 모델 Artifact SHA256 |
|---|---|
| quality RF | `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` |
| edge LR | `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882` |

기존 live-metadata Worker의 실제 predict 부분을 공유 함수로 추출해 TCX vector 입력도 같은 Loader/검증/추론을 사용한다. 새 모델·학습·다운로드·의존성을 추가하지 않았다. Worker는 기존 Parent binding·timeout30s·CPU15s·RAM3GiB·출력128KiB·네트워크 거부를 유지한다. raw vector 최대4개, profile 최대2개다. 이는 **별도 post-capture 작업**의 상한이며 Native Capture 256MiB/CPU20s/300s 범위를 확대한 것이 아니다. 둘을 합친 전체 시간을 Native300s 안에 보장한다고 주장하지 않으며 별도 분석 Scope로 검토해야 한다.

기존 five-feature Fusion v1은 RF/LR binary 연구 계약과 호환되지 않는다. 잘못된 Kind/label로 끼워 넣지 않고, 같은 source/flow/feature fingerprint의 binary 결과만 비교하는 adapter projection을 추가했다. 기존 Agreement/Confidence/Coverage enum을 재사용한다. `soc-research-model-comparison:v1`은 legacy Fusion v1이나 보정된 위험도가 아니다. 점수 평균·공격 확률·도메인 간 동일 인물 추정을 하지 않는다. 불일치는 `conflicting`, confidence는 `unknown`이다.

Incident 분류·Known-error 1회 재검증·Planner·읽기 전용 도구·Assessor·Audit는 기존 경로를 재사용한다. 모델 출력은 advisory이며 LLM의 observation 승격 거부를 유지한다. 자동 방화벽/서비스/계정 변경은 없다.

실제 LLM API Adapter는 기존 명시적 `--api-authorization`/`--api-env-file`로 연결할 수 있다. 이번 요청에는 새 API 호출 승인을 사용하지 않았으므로 **신규 실제 API 0회**, 조사 결과는 SCRIPTED다. 이전 브랜치에서 실제 API 2회로 완료한 결과 SHA `7b44630fbf54480dc911944b07260c9cfa6c629cdb1e6c88aaae5a7ad981b838`를 읽기 전용 재검증했다. 이를 최종 수정본의 새로운 REAL_LLM 실증으로 바꾸지 않는다. 키·로컬 LLM 설치/다운로드·외부 유료 호출은 추가하지 않았다.

## 실제 증거와 P02·P03·P04

기존 Batch3의 실제 Supervisor 파일을 새 운영 CLI에서 직접 읽었다. 원본은 변경하지 않았으며 이 Capture의 Namespace는 **Host net:[4026531833]**다. 전용 Namespace 실행으로 소급 표시하지 않는다.

| 항목 | 새 Entry Point 재분석 결과 |
|---|---|
| Native 후보 | 9개: INCOMPLETE4 / UNKNOWN5 / ELIGIBLE0 |
| 모델·API 호출 | 0 / 0 |
| P02 | INCOMPLETE. DELIVERY_BUDGET_EXCLUDED / ATOMIC_CAPTURE_WINDOW_NOT_ATTESTED / KERNEL_WIDE_DROPS_UNKNOWN |
| Window | CPU_EMITTED_DELIVERY_MISMATCH / DELIVERED_WINDOW_TRUNCATED |
| P03 | INCOMPLETE. 9개 모두 FLOW_TIMEOUT_OR_WINDOW_NOT_PROVEN |
| P04 | 실제 Native ELIGIBLE0 유지. 5개는 RAW_VECTOR_NOT_RETAINED |
| Audit | 품질 거부·원본 입력·후보별 이유·Source continuity READ·결과 저장 및 재열기 검증 성공 |

기존 12.081초/4,096건 조기 종료를 새로운 성공으로 바꾸지 않았다. 새로 Capture를 실행하지 않았으므로 전용 Namespace의 35~45초 관측과 실제 timeout은 아직 입증되지 않았다.

## DNS 경로

Supervisor의 기존 Sidecar `zeek_summary.dns_transactions`를 원본 result/Session/Namespace/Release와 함께 별도 admission receipt로 보존한다. 과거 실제 결과의 transaction metadata2건은 확인할 수 있지만 raw DNS wire는 이 result에 없다. 없는 wire payload를 만들거나 Native payload-retention 계약을 변경하지 않았다.

Raw DNS transcript가 존재하는 경우 이전 `raw_dns` Job/기존 parser/correlation을 그대로 사용한다. 저장된 실제 PCAP transcript 1,162개에서 strict metadata match331개를 이번 코드로 재검증했다. 실제 UDP이며 TCP는 Fixture 범위다. DNS9의 학습 추출법·단위·window/golden pair가 없어 **Feature INCOMPLETE / DNS9 추론0회**다. 기존 9개 이름을 임의 산술로 채우거나 Fixture INT8 성공을 Native 성공으로 표시하지 않는다.

## E2E 시나리오

| 시나리오 | 실제 구분 | 결과 |
|---|---|---|
| A — 과거 Native 품질 부족 | REAL_NATIVE retained / 모델 미실행 | 9개 거부·이유·Audit, 신규 Capture 없음 |
| B — 실제 PCAP 정상 | REAL_OFFLINE / REAL_MODEL / API0 | RF/LR CLASS_0/CLASS_0 → NORMAL → READ/Audit |
| B — 실제 PCAP 이상 | REAL_OFFLINE / REAL_MODEL / SCRIPTED | CLASS_1/CLASS_1 → UNKNOWN_ANOMALY → 계획·READ·평가·Audit |
| C — 새 실제 Native 적격 입력 | 미실행 | 승인·실제 적격 증거 대기 |
| TCX positive adapter | FIXTURE / REAL_MODEL / SCRIPTED | 같은 Collector Flow/Window 구조 → RF CLASS_0, LR CLASS_1 → conflicting → 조사/Audit |
| Native 승인 positive | SYNTHETIC Native-shaped / MOCK model / SCRIPTED | 기존 정확한 Action 승인·Worker callback·추론 Receipt·조사 연결 테스트. 실제 Native 아님 |
| D — 저장 DNS | REAL_OFFLINE transcript / 모델 미실행 | 거래 metadata 구성 → DNS9 INCOMPLETE |
| E — 알려진 오류 | SYNTHETIC / API0 | FEATURE_EXTRACTION_INTERRUPTED → 입력 재검증1회. Collector 복구/재시작 아님 |

실제 모델은 연구용으로 유지한다. 독립 성능 Ground Truth가 없으므로 정확도/F1을 만들지 않았다. scripted/mock 성공을 REAL_LLM 또는 실제 Native E2E 성공으로 표시하지 않는다.

## 검증과 수정

- Workspace 관련 회귀 **1,670 PASS**, 280.49초.
- 독립 frozen Export 동일 회귀 **1,670 PASS**, 284.03초.
- 신규 TCX 통합 테스트25개 포함. 기존 Approval/Ledger·Supervisor·Namespace/DNS·Checkpoint/Clock/Flow·모델·Incident/API 경계 회귀를 함께 실행했다.
- Ruff PASS / Format1,419개 PASS / Diff PASS. 기존 assertion/승인 조건/적격성 임계값을 삭제·완화하지 않았다.
- Wheel A/B 바이트 동일, 678 entries. Packaged Wheel에서 실제 Native 거부 결과와 Fixture 모델 결과 재열기 PASS, 모델/API 재실행 없음.
- Capture Stage/A/B **26/26 파일명·SHA 동일**. 기존 Builder/SourceGuard/Installer manifest를 재사용한 비권한 빌드다.

실패 주입: Namespace/Session/Release/source 변조, Counter/Clock/epoch/window 누락, fingerprint/schema 오류, STOP/UNKNOWN/drain, 승인 누락·만료·다른 Action·미결정·unbound 입력, 동일 출력 재사용, 코드/입력 변경에 따른 Action ID 변경, DNS receipt 변조. Native 형식의 성공 승인 테스트는 임시 Mock 모델/승인에 한정하고 운영 승인으로 쓰지 않았다.

초기 실패는 공유 predict 함수 추출의 SPECS import 누락과 승인 Binding 예외가 Workflow 오류 결과에 반영되지 않은 결함이었다. 최소 수정 후 전체 회귀를 통과했다. 새 Mock 테스트의 digest import 누락도 수정했다. 빌드 Wrapper의 출력 key 오타는 빌드 완료 후 진단 출력만 실패한 것으로 분리했으며 Stage 파일은 보존하고 A/B로 검증했다. 실제 Root/Native를 실패·재시도한 일이 아니다.

## Namespace·Artifact·실행 준비

Namespace lease/boot/inode를 일반 사용자 읽기로 검증했다. SOC `net:[4026532232]`, Host `net:[4026531833]` 불변이다. Namespace 진입을 하지 않아 현재 내부 lo/route/socket cookie/DNS 응답을 새로 관측했다고 주장하지 않는다. 기존 Namespace·WSL·VS Code·서비스·사용자 프로세스를 종료하거나 바꾸지 않았다.

| Review Artifact | SHA256 |
|---|---|
| Frozen Source (1,762 inputs) | `a3f9504c920e2d548537dc3ab06cd676f8ba2df82f2fb95d5a6d68e9c36aa2fa` |
| 통합 Manifest | `9a7234462751484833f02f33a10c516625b3efadfd12eb821d93a651e09d37a8` |
| 통합 Bundle JSON | `172f5d8ef709d5a676e816363b911a1c6af468860a975237701945fe9ab0c83d` |
| Capture Manifest | `948a174f18e41c6366e2b78c7d28ff7ea2f76d77c5bf0f532ad25b5e0f9af5f0` |
| Capture Bundle | `a7c87c580fd227c617580e50af4b3a583879912826816e6cbf2af059c6eab1b4` |
| Supervisor Execution Image | `987a0556a7fd86a9f25b7df301a1c2a3e01526d6398d561b96d019eecfcbfad5` |
| Root Manifest | `6752b8ccd9dfae3770d6a2f40e3a331890280365a0a00cdb8e291baacb74460c` |
| AI Wheel | `4c5df4522284aea3103e4594b4d87e672244be402a606282ce6c39f91a645924` |
| Runtime Identity | `981a360752621395afea273416ea196f833730f6bf590d6910896476039206a2` |

통합 Manifest는 Capture 배포물·비권한 AI Wheel·모델 SHA·실제 Namespace lease·Runtime Dependency를 연결한다. Bundle은 content-addressed JSON이며 실행 권한이 아니다. 현재 zlib 보안 업데이트 및 libbpf/libelf closure는 기존 dependency inventory/Root Manifest로 검증했다. 시스템 패키지 변경/다운그레이드는 없다. Source Snapshot은 자체 참조하는 새 보고서와 기존 Native 보고서2개를 제외하며 문서 Commit은 구현 Tree와 구분한다.

**현재 이미지는 `SOC_PHASE_D_NAMESPACE_PREVIEW_V1`이며, `ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED` 차단이 유지된다.** 기존 CLI의 비소비 `native-recovery check`는 `PHASE_D_RELEASE_OR_SOURCE_MISMATCH`, reserved=false/executed=false를 반환했다. 독립 Source/Artifact SHA 검증 성공과 operational readiness를 혼동하지 않는다. 원인은 전용 Namespace preview 계약과 기존 Host 운영 계약 차이다. 별도 정책 활성화·새 실행 Artifact 준비가 필요하며, 그 과정에서 SHA가 바뀌면 현재 review SHA를 실행 승인에 재사용하면 안 된다.

실행 승인 전 남은 조건:

1. AGENTS.md §33의 인간 검토에 따른 전용 Namespace Supervisor 정책/Scope 활성화. 기존 guard를 이 작업에서 제거하지 않았다.
2. 현재 Runtime·Namespace·Source에 맞는 공식 실행 Session/Release Binding과 fresh 정책/R1 위험 수용/R2 로컬 트래픽 승인.
3. 운영 이미지 확정 후 정확한 Root/Native SHA 승인, 현행 예산·Replay 검증, 비소비 check PASS, 사용자 직접 Scope 확인·OS 인증. 자동 재실행 없음.
4. Capture 후 적격 벡터에 대한 별도 `analyze_retained_tcx` Action 승인. 새 API 사용에는 별도 명시적 호출 한도/승인. 이전 승인·이전 API 호출 권한은 재사용하지 않는다.

계획 Capture Scope는 SOC Namespace의 lo/Ingress, 최대300s·4,096 events·Queue32·50ms Admission·10ms 재정렬·16KiB Checkpoint·256MiB·CPU20s다. R2는 로컬 127.0.0.53:53 UDP2/TCP1, TCP close 후35s 관측·약45s STOP, Sidecar 분석10s를 유지한다. 실제 측정 전 35~45초와 ELIGIBLE 확보를 보장하지 않는다. post-capture 모델/LLM Scope는 위 Capture 권한과 분리한다.

현재는 정식 Root/Native 실행 승인을 요청할 EXECUTION_READY 상태가 아니다. 정확한 현재 review Scope와 미충족 조건을 단일 `native-execution-review-package.json`에 정리했다. 권한·인간 위험 수용·양의 승인을 생성하지 않았다.

## 예산·무결성·Git

Campaign Native4/10·Root5/10, Batch3 Native1/2·Root2/4 유지. 신규 예약/실행/환급0건. DNS 검증 Root1회와 후속 설치 Root1회를 사용할 수 있는 잔여량은 그대로이며 각각 별도 승인이 필요하다.

Ledger26행 SHA `7f61dbdcd8e589e40f8b11d405a435c4057223ab6738005984abbd5902b59c5f` 불변. 보호 파일112개·과거 Native 증거55개·설치9개·Rollback9개 SHA와 두 기존 Worktree의 사용자 변경을 재검증했다. FAILED·원본 false·Program1145 UNKNOWN·과거 EVIDENCE_INCOMPLETE/Root UNKNOWN/Native UNKNOWN을 보존했다. 실제 Native AI·DNS9·운영 승격은 계속 BLOCKED다.

Private 증거: 원본 저장소 `.git/native-ai-e2e-integration-20261027-1/`의 `historical-native/`, `tcx-fixture-real-models/`, `real-pcap-*/`, `real-stored-dns/`, `source-export/`, `capture-stage/`, `capture-A/`, `capture-B/`, `artifact-identity.json`, `native-execution-review-package.json`, `native-recovery-check.json`, `integrity-verification.json`. 키와 원시 민감 증거는 Git에 넣지 않는다.

이번 구현9개 파일과 이 보고서만 별도 Commit/Push한다. 기존 사용자 변경·설치·Ledger·Namespace는 포함하지 않는다. 최종 remote 확인은 같은 private 증거 디렉터리의 `git-and-verification.json`에 기록한다.
