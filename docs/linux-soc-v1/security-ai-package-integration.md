# Security AI Package Integration — WSL2 Ubuntu

검증일: 2026-10-15. 기준 main `6cc6643a9e2b1964178956d2b8bd3782b0583b78`.

**판정: PARTIAL.** 패키지 Import·공식 입력 계약·기존 Adapter/Context/Runtime
연결과 READ-only 상태 조회를 확인했다. 기존 ML 환경의 Network Quality/Edge 실제
추론은 합성 사전 계산 Feature에 한정한다. 현재 SOC 가상환경에서 3개 모델의
Native Adapter→Agent 전체 실행은 BLOCKED다. DNS native backend와 기존 설치 번들이
없다. 과거 Gate B/C의 Native E2E를 이번 실행으로 계상하지 않는다.
Network Top40/DNS9 운영 입력은 계속 **NOT_INFERABLE**, 조사 WRITE는 **WRITE_DENIED**다.

## 1. 조사 및 재사용

`AGENTS.md`와 다음 실제 구현을 대조했다. 새 Feature 계산·Fusion·모델·GUI는 구현하지 않았다.

- `security_ai/external/metadata.py::{package_code_identity,reviewed_binding}`:
  세 배포 패키지 0.1.0 및 검토된 계약 파일 pin 확인.
- `external/inference.py::infer`: 공식 Predictor, 설치 Artifact 검증 전후,
  float32 입력 fingerprint, Typed Evidence Adapter. `service.py::ExternalSecurityAIService`
  → `api/service.py::analyze_external` → `application.py::compose_application`에 이미 연결됨.
- `external/validation.py::{validate_setup,feature_input_digest,validate_source}`:
  Binding/Feature/Incident/원본 Evidence 재검증. `adapters.py::ExternalEvidenceAdapter`
  → `assembly.py::assemble` → `projection.py::project` 재사용.
- `external/runtime_integration.py::{ContextLLMClient,RuntimeIntegration}`와
  `runtime_guard.py::RuntimeBoundary`: 실제 SOCRuntime의 Assessment/Decision/Resume 연결.
  `diagnostic.py`의 비실행 시험 경로와 실제 Runtime 경로를 구분한다.
- `operational/{native_authentication,authentication_pipeline,source_store,provenance}.py` 및
  `authentication_investigation.py::read_authentication_view`: Native Authentication →
  Queue → Source → 5분 Window → v3 → READ 조회. 이번에는 실제 journald를 재수집하지 않았다.
- `security_ai/authentication/anomaly.py::AuthenticationAnomalyDetector`는 별도 내부
  IsolationForest 계약이다. 외부 Network/DNS 모델과 동일한 입력으로 취급하지 않는다.
  실제 Native Authentication Window가 모델 추론 허가를 얻는다고 표시하지 않는다.
  `linux_runtime/service.py`의 기존 Authentication 조사 연결을 보존했다.

위 소스 경로의 접두사는 `src/soc_agent/`다. 기존 미커밋 Reliability Replay 및
README/pyproject/Command Center 변경은 검토 대상에서 별도 보존하며 커밋 의존성으로 사용하지 않는다.

## 2. 실제 패키지 및 Artifact Inventory

SOC `.venv`에서 Python 3.12.14, 실제 Import 확인:

| Distribution | Version | Python Import | 역할 |
|---|---|---|---|
| security-ai | 0.1.0 | security_ai | Typed EvidenceEnvelope 및 Artifact Catalog |
| network-security-ai | 0.1.0 | network_security_ai | Quality LightGBM / Edge PyTorch |
| dns-security-ai | 0.1.0 | dns_security_ai | DNS INT8 LiteRT Predictor |

패키지 소스는 ML 저장소 `packages/{security-ai,network-security-ai,dns-security-ai}`에 있다.
SOC는 실제 설치된 `site-packages`를 Import했다. ML의
`packages/dns_security_package/dns_security_package/dns_security`는 원본 Artifact 보존 경로이며,
canonical Python 패키지인 `dns-security-ai`와 구분한다. ML 저장소는 수정하지 않았다.

모델·Scaler 원본 파일의 SHA와 크기를 공식 `security_ai/artifact_catalog.json`과 비교했다.
아래 5개 모두 일치한다. 이 사실은 완성된 설치 번들 검증과 다르다.

| Binding | 파일 (Catalog 상대 경로) | Bytes | SHA-256 |
|---|---|---:|---|
| network-quality | `models/network/lightgbm_top40_v4b2.txt` | 48637456 | `eb28cc855a65d336cd1b2720ec4fcc2958874444e33fae5b78c1cae4e4c62924` |
| network-edge | `models/network/dnn_top40_v4_best.pt` | 398041 | `85cbc702d1b0a137c4f44b23be6911691cc89d5bfef0c388cf282e9500c49160` |
| network-edge | `models/network/dnn_top40_v4_scaler.joblib` | 1543 | `528cfa770181bb61bdcc5d30b2cae8a171dfa63399f3fd33f9a15ab5fbc67d32` |
| dns | `dns/model/dnn_int8.tflite` | 9288 | `28e089af363dd565a4fb3d3f202de9e9f9804bd14a164de4fd7b61adb1201e33` |
| dns | `dns/preprocessor/scaler.joblib` | 1135 | `2735f7650a7d7888ee68f2df870b4e29d83666962931ae2aecb9aa339f40266a` |

Network 원본은 ML `models/network/`, DNS 원본은 위 legacy DNS 경로에서 읽었다.
모델을 복사·변경·다운로드하지 않았다. ML root에는 설치용 `metadata/`와 `dns/`
구조가 없으므로 `verify_install(ML_ROOT)`는 성공하지 않는다. 개별 SHA 일치를 근거로
설치 번들 검증을 우회하지 않았다.

검토된 계약 코드 pin:
`56293972d069dffaf564a390ab7a4c4554c2a2a5b2ab6be6f6f758b5ea3cce44`.
이는 `package_code_identity()`가 열거한 계약 파일 범위의 pin이며 전체 패키지 코드 서명을 뜻하지 않는다.

## 3. Feature / Model Contract

| Binding | Model ID / Version | Schema | 실행 Backend |
|---|---|---|---|
| network-quality | `network_cse2018_lightgbm_v4b2` / `v4-b2` | `cse-cic-ids2018-top40-v1` | LightGBM |
| network-edge | `network_cse2018_dnn_fp32` / `v4-fp32-epoch13` | `cse-cic-ids2018-top40-v1` | PyTorch + sklearn + joblib |
| dns | `dns_cicbell_dnn_int8` / `int8-sha256-28e089af363d` | `cic-bell-dns-stateless9-v1` | ai-edge-litert + sklearn + joblib + pandas |

입력 이름·순서는 `reviewed_binding().feature_identity.ordered_names`에서 읽는다.
공식 `Top40Contract` / `DNSFeatureContract`와 `feature_input_digest()`의 float32
행렬 변환·비정상 수치 검증을 그대로 사용한다. 내부 Network 5-feature Extractor로
Top40을 대체하지 않았다. DNS9에는 TTL이 없으며 임의 Feature를 추가하지 않았다.

Network Top40 공식 순서:

`Fwd Act Data Pkts`, `Fwd Seg Size Min`, `Fwd Header Len`, `ECE Flag Cnt`, `Init Fwd Win Byts`, `URG Flag Cnt`, `RST Flag Cnt`, `Dst Port`, `Fwd PSH Flags`, `Fwd Pkts/s`, `Fwd Pkt Len Mean`, `Pkt Len Max`, `SYN Flag Cnt`, `Fwd Seg Size Avg`, `Bwd Header Len`, `Init Bwd Win Byts`, `Fwd IAT Std`, `Fwd IAT Max`, `Pkt Size Avg`, `Fwd IAT Tot`, `Bwd Pkt Len Max`, `PSH Flag Cnt`, `Flow IAT Mean`, `Bwd IAT Min`, `Bwd Pkt Len Std`, `Pkt Len Mean`, `Bwd IAT Max`, `Fwd Pkt Len Std`, `ACK Flag Cnt`, `TotLen Bwd Pkts`, `Pkt Len Std`, `FIN Flag Cnt`, `Bwd IAT Mean`, `Flow Duration`, `Flow IAT Max`, `Subflow Bwd Byts`, `Idle Max`, `Fwd URG Flags`, `Bwd Pkts/s`, `Bwd IAT Std`.

DNS9 공식 순서:

`FQDN_count`, `subdomain_length`, `numeric`, `entropy`, `special`, `labels`, `labels_max`, `labels_average`, `len`.

학습 Producer revision/config 및 Raw↔Feature Golden Pair 미확보 상태는 유지한다.
`docs/gate-dg-operational-pipeline/{top40-training-parity,dns9-training-parity}.md`,
ML `reports/Security_AI_Integration_Report.md`, 각 패키지 `feature_contract.json` /
`artifact_manifest.json`의 제약을 대조했다. DNS 공급 DNN의 학습/export provenance와
scaler pairing·실효성은 UNVERIFIED다. 확률은 미보정 모델 점수이며 실제 공격 확률이 아니다.

## 4. 이번 실행의 Import / Inference / 연결 Matrix

| 단계 | Network Quality | Network Edge | DNS |
|---|---|---|---|
| INSTALLED / IMPORTABLE (SOC .venv) | VERIFIED | VERIFIED | VERIFIED |
| 계약 pin / Feature validation | VERIFIED | VERIFIED | VERIFIED |
| 원본 Model/Scaler SHA | VERIFIED | VERIFIED | VERIFIED |
| 현재 SOC 설치 번들 ARTIFACT_VERIFIED | BLOCKED | BLOCKED | BLOCKED |
| 현재 SOC Backend dependencies | UNAVAILABLE | UNAVAILABLE | UNAVAILABLE |
| 별도 기존 ML .venv 패키지 실제 추론 | VERIFIED, 합성 Top40 | VERIFIED, 합성 Top40 | NOT_TESTED: LiteRT 없음 |
| Adapter / Context 연결 | Fixture 회귀 | Fixture 회귀 | Fixture 회귀 |
| 실제 SOCRuntime / Assessment / Decision / Resume | Fixture 모델 출력 + MockLLM 회귀 | 동일 | 동일 |
| 이번 Native 추론→SOC Runtime 연속 E2E | BLOCKED | BLOCKED | BLOCKED |
| OPERATIONAL_INPUT_VERIFIED | NOT_INFERABLE | NOT_INFERABLE | NOT_INFERABLE |

SOC `.venv`에는 LightGBM, torch, ai-edge-litert, pandas가 없다. 기존 ML `.venv`에는
LightGBM 4.7.0 / torch 2.14.1 / sklearn 1.9.1 / joblib 1.6.0 / numpy 2.5.3이 있다.
그 환경에서 `create_network_security_ai(NetworkSecurityAIConfig(enabled=True,
profile=PROFILE, artifact_root=ML_ROOT)).predict(features)`를 각각 1회 실제 호출했다.
`features`는 공식 순서의 각 값 1.0인 **합성 사전 계산 입력**이다. 실제 Flow나
PCAP 추출 결과가 아니다. 출력은 각각 15개 class probability를 가진 공식 Prediction이다.
모델과 Scaler는 기존 패키지 검증 로더로 읽었으며 새 환경 설치나 모델 복사는 하지 않았다.

재현 가능한 직접 패키지 실행 (기존 ML 환경 필요):

```python
from pathlib import Path
from network_security_ai import NetworkSecurityAIConfig, Top40Contract, create_network_security_ai

root = Path("/configured/read-only/ML-root")
contract = Top40Contract(NetworkSecurityAIConfig(artifact_root=root))
features = dict.fromkeys(contract.names, 1.0)  # SYNTHETIC_PRECOMPUTED_FEATURE_FIXTURE
for profile in ("detection_quality", "edge"):
    model = create_network_security_ai(
        NetworkSecurityAIConfig(enabled=True, profile=profile, artifact_root=root)
    )
    prediction = model.predict(features)
    assert len(prediction.class_probabilities) == 15
```

DNS도 현재 SOC 환경에서 기존 legacy 원본을 `DNSPredictor(..., runtime="litert")`로
실제 로딩/추론 시도했으나 `DNSInferenceError`로 BLOCKED였다. Mock 결과로 대체하지 않았다.
기존 `tests.diagnose_external_context` 실행은 `RUNTIME_BACKEND_UNAVAILABLE`로 종료했다.
이는 환경 차단 진단이며 통과 테스트가 아니다.

이 직접 호출은 SOC의 `verify_install`을 통과하는 Adapter E2E가 아니다.
과거 Gate B/C의 3모델 Native Runtime/Resume 증거는
`docs/security-ai-final-integration-20261012/release-readiness.md` 및
`docs/gate-c-soc-integration/report.md`에 있다. 현재 삭제된 `/tmp` 설치 경로를
그대로 재사용했다고 주장하지 않는다. 실제 LLM 요청 0, 운영 보안 WRITE 0.

## 5. Runtime READ-only 조회 및 GUI 연결

신규 계약: `soc-security-ai-package-status:v1`.
`src/soc_agent/security_ai/external/package_status.py`:

- `inspect_packages(artifact_root=None)`는 설치·Import·계약·선택적 Artifact 검증만 수행한다.
  추론·DB·LLM·다운로드·Runtime 상태 변경·Capability 발급이 없다.
- `verify_fixture_demo(artifact_root, inputs, incident)`는 **명시적 호출**에서만 기존
  `infer` → `ExternalEvidenceAdapter` → `assemble` → `project`를 재사용한다.
  환경/계약/Artifact 미검증 또는 UNLINKED는 실패한다. 현재 환경 성공 증거는 없으며,
  테스트의 공급 Prediction은 해당 함수의 연결 계약 검증일 뿐 Native 추론 증거가 아니다.
- `ApplicationService.security_ai_status()`는 기존 composition의 명시적 Artifact root를
  사용한다. 새 HTTP route/server를 만들지 않았다. GUI는 기존 ApplicationService를
  인증된 호출 경로로 사용한다. 이 응답으로 승인/실행 권한을 얻을 수 없다.

```bash
.venv/bin/python -m soc_agent.security_ai.external.package_status
.venv/bin/python -m soc_agent.security_ai.external.package_status --artifact-root /configured/bundle
```

응답은 current interpreter만 검사한다. 별도 Native interpreter 설정이 있더라도
그쪽 Backend까지 검증됐다고 표시하지 않는다. `backend_dependencies=VERIFIED`는
배포 메타데이터 존재 확인이며 실제 모델 로딩 완료가 아니다. `demo_inference`는
기본 UNKNOWN이고, 실제 opt-in probe가 성공한 모델만 VERIFIED가 된다.
모델 절대 경로·Secret·원본 인증 로그를 반환하지 않는다. 원본 검증 함수 위치,
Feature order/digest, Catalog digest를 제공한다. 파일 해싱은 GUI 렌더링/짧은 polling
루프 밖에서 명시적 새로고침으로 실행한다. 응답을 장기간 캐시해 현재 사실로 표시하지 않는다.

GUI 권장 표시:

| 항목 | 현재 표시 | 설명 |
|---|---|---|
| Quality / Edge 패키지 | Import·계약 확인, 현재 SOC 시연 BLOCKED | 별도 ML 환경의 합성 추론 성공과 구분 |
| DNS 패키지 | Import·계약 확인, Native 시연 BLOCKED | LiteRT와 설치 번들 준비 필요 |
| 운영 Network / DNS | NOT_INFERABLE | Producer parity/Golden Pair 없음 |
| Authentication | Native source-chain 경로 존재, NOT_QUERIED | 실제 상태는 기존 read_authentication_view로 별도 확인 |
| Advisory | 관측 사실/실행 권한 아님 | 미보정 점수, cross-domain UNVERIFIED |

Authentication 조회 계약은 원본 Source/Window/Provenance를 기존 방식으로 재검증한다.
패키지 상태만으로 인증 이벤트 처리 완료나 내부 Authentication AI 추론을 선언하지 않는다.

## 6. Security / Runtime Regression

기존 `tests/unit/security_ai/external/test_adapter.py`, `tests/unit/external_context`,
`tests/integration/external_runtime/test_runtime.py`, `external_read_only_backend/test_guard.py`,
`external_context_storage/test_store.py`, `external_context_diagnostic/test_diagnostic.py`를 재사용한다.
실제 Guard와 SQLite, scripted LLM/공급 모델 출력을 사용한다. 실제 OS 또는 LLM 시험과 구분한다.

Artifact/Binding/Feature order/schema/provenance 불일치, Source/Incident/위조 Evidence,
Context/Receipt 변조, MODEL_FACT_PROMOTION, 허용되지 않은 Tool, 직접 Executor 및
승인으로 WRITE 권한 얻기, Resume/CAS 무결성을 확인한다. Quality/Edge의 동일 관측
중복 계산 금지, DNS 별도 관측, UNLINKED projection 배제 계약을 유지한다.
Operational v3와 Synthetic v2의 혼용 차단 및 NOT_INFERABLE/WRITE_DENIED를 재검증한다.
신규 테스트는 상태 조회의 DB 불변성·경로/Secret 비노출·환경 실패·opt-in·원본 재검증을 확인한다.

## 7. 실행 결과

| 실행 | 결과 | 범위 |
|---|---|---|
| 최초 신규 조회/연결 테스트 | 17 passed, 3.37초 | Fixture/조회 계약, Native 추론 아님 |
| 최종 신규 + 내부 Authentication AI | 62 passed, 6.75초 | 신규 20 + 기존 Authentication 42; 다른 실행과 합산 금지 |
| Adapter/Context/실제 Runtime/READ Guard/Storage/Operational 보안 회귀 | 576 passed, 233.89초 | Fixture 모델 출력 및 MockLLM, 실제 SQLite/Guard |
| 독립 기준 HEAD Export + 이번 변경 | 169 passed, 4 deselected, 124.06초 | 신규/Adapter/Runtime, 선택 필터로 interruption 및 CAS 충돌 제외; 별도 원본 회귀에는 포함 |
| 최종 코드/테스트 Export 재검증 | 20 passed, 3.54초 | 최종 입력 수 제한·타입 힌트 및 추가 무결성 테스트 반영 |
| 공식 Network Quality / Edge 패키지 추론 | 각각 1회 성공 | 기존 ML 환경, 합성 Top40; pytest 수치 아님 |
| DNS Native 시도 / 기존 Native Context 진단 | BLOCKED | DNSInferenceError / RUNTIME_BACKEND_UNAVAILABLE; 통과 시험 아님 |
| Ruff `check src tests` | PASS | 전체 소스/테스트 |
| Ruff `format --check .` | PASS, 822 files | 기존 사용자 변경 포함 검사만 수행 |
| `git diff --check` | PASS | 기존 변경 보존 |

보안 회귀의 실제 명령:

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest --import-mode=importlib -q \
  tests/unit/security_ai/external tests/unit/external_context \
  tests/integration/external_runtime/test_runtime.py \
  tests/integration/external_read_only_backend \
  tests/integration/external_context_storage \
  tests/integration/external_context_diagnostic/test_diagnostic.py \
  tests/unit/operational_features/test_adapter_boundary.py \
  tests/unit/operational_features/test_operational_provenance.py \
  tests/unit/operational_features/test_reported_network.py \
  tests/unit/operational_features/test_reported_dns.py \
  tests/unit/operational_features/test_authentication_investigation.py
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest --import-mode=importlib -q \
  tests/unit/package_status tests/integration/package_status \
  tests/unit/security_ai/authentication
```

실행 로그는 로컬 `/tmp/soc-package-{new,final-new,security-regression,export,export-final-new}.log`,
`/tmp/soc-package-{ruff,format}.log`에 저장했다. 비밀 정보/모델/DB/로그는 커밋하지 않는다.
아래 SHA는 이번 로컬 검증 로그의 무결성 참고이며 향후 재실행 결과의 digest와 같을 필요는 없다.


테스트 중복 수치는 합산하지 않는다. 전체 WSL/Windows 회귀, 실제 LLM, 실제 journald,
새 Native DNS 추론, 실제 OS 대응, 물리 Linux 서버·Windows·AWS 검증은 실행하지 않았다.

## 8. 변경 범위 및 Git 독립 재현

1. `src/soc_agent/security_ai/external/package_status.py` (신규)
2. `src/soc_agent/api/service.py` (READ-only 메서드만 추가)
3. `tests/unit/package_status/test_status.py` (신규)
4. `tests/integration/package_status/test_application_status.py` (신규)
5. 이 보고서 (신규)

기존 미커밋 Replay 및 사용자 변경은 Stage/커밋 대상이 아니다.
독립 검증은 기준 HEAD의 `git archive`에 위 코드·테스트만 overlay하고 기존 `.venv`의
의존성을 재사용한다. `soc_agent.__file__`이 Export의 src 아래인지 확인하여 editable
설치 경로 누출을 배제한다. 클린 의존성 설치 시험은 아니다.

## 9. 남은 Blocker / 다음 단계

- 별도 승인을 거쳐 신뢰된 공식 설치 번들과 Native Backend 환경을 준비한 후
  `ExternalSecurityAIService`→SOCRuntime의 3모델 Native E2E를 현재 환경에서 재실행한다.
  이번에는 대규모 설치·가상환경 재구성·Artifact 복사/자동 다운로드를 하지 않았다.
- Producer revision/config 및 학습 Raw↔Feature Golden Pair 확보 전 Network/DNS
  운영 추론을 활성화하지 않는다. DNS 학습/export/scaler pairing도 별도 검증한다.
- GUI는 이 READ-only 모델과 기존 Authentication 조회를 소비하되 Fixture·Operational,
  현재 실행·과거 기록, 시뮬레이션·실제 조치를 각각 표시해야 한다. GUI 자체는 미구현이다.
- 물리 Linux 서버의 패키징/Backend/파일 권한/장시간 자원 사용 검증은 후속 단계다.
- Artifact 디렉터리는 신뢰된 읽기 전용 배치가 전제다. 전후 stat/SHA 검증은 악의적인
  Writer에 대한 OS sandbox나 원본 데이터 진위·모델 효능 증명이 아니다.

- 이번 `soc-package-security-regression.log` SHA-256: `96665f83ba2932dcfb6528c0e39b7b65b7d38efcdd7363184493eabc70b644d2`.

- 이번 `soc-package-export.log` SHA-256: `2cd2a127c9e5b08a2e3df8233bacf41bc831c64ef7e00fe86b5acbde5bd74b86`.

- 이번 `soc-package-export-final-new.log` SHA-256: `18a12f238760b465d04acb6b4a6a5b6496279a37742e788f74fafc7bcc745f0c`.

- 이번 `soc-package-final-new.log` SHA-256: `7921fe5febfb3a51dbb486e80fe9f15907f594ba874507cfcf11a1bec1599cd8`.

- 이번 `soc-package-ruff.log` SHA-256: `82b3e6a6c090a57601d22943bd23fca9218d1031dbe5a7b754092f9a156b4f18`.

- 이번 `soc-package-format.log` SHA-256: `a801fbd5e7d8770d1b2880b72203ab84a7d9639d578cfa2717738cbda1833c5d`.
