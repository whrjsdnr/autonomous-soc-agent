# Native Security AI Integration & Runtime Hardening

검증 환경: WSL2 Ubuntu, 2026-10-15. 기준 main
`1a0dba79c22a51e0031c94a9039fea91b5c72788`.

**최종 판정: VERIFIED — WSL2의 합성 Feature Native 시연·Authentication READ-only·복구/조회 범위.** 운영 Network/DNS는 계속 **NOT_INFERABLE**이며,
Native 추론 성공은 합성 Feature 시연 경로의 성공이다. GUI는 구현하지 않았다.

## 1. 환경 Inventory 및 변경 범위

SOC `.venv`와 ML `.venv`는 모두 Python 3.12.14,
`cpython-312-x86_64-linux-gnu`, WSL Ubuntu glibc 2.39다.
SOC에는 원래 LightGBM/torch/LiteRT/pandas가 없고, ML에는 Quality/Edge Backend가 있다.
SOC의 `python -m pip list`는 pip 모듈 부재로 실행 불가였으므로 `uv pip list --python`
및 `importlib.metadata`로 실제 배포 버전을 확인했다. pip를 기존 환경에 설치하지 않았다.

별도 `/tmp/soc-native-validation-6uxdtrx9/inference`에 `uv venv`로 Python 환경을 만들었다.
그 환경의 `.pth`가 기존 ML/SOC site-packages를 읽기 전용으로 참조한다.
기존 두 환경에 설치·삭제·업데이트하지 않았다. 이는 **독립 클린 설치가 아니다**.
공유 의존성이 사라지거나 변경되면 재검증이 필요하다. 배포용 환경 관리 플랫폼은 추가하지 않았다.

공식 패키지 의존성과 PyPI Release metadata를 확인하고 설치 전
`/tmp/soc-native-environment.json`, `/tmp/soc-native-litert-plan.json`에 범위를 기록했다.
설치 대상은 다음 5개뿐이다. PyTorch 재다운로드나 TensorFlow 설치는 하지 않았다.

| 격리 환경에 추가한 배포 | 버전 |
|---|---|
| ai-edge-litert | 2.3.0 |
| backports.strenum | 1.3.1 |
| flatbuffers | 25.12.19 |
| protobuf | 7.36.2 |
| ml_dtypes | 0.6.0 |

LiteRT Wheel: `ai_edge_litert-2.3.0-cp312-cp312-manylinux_2_27_x86_64.whl`,
21,781,762 bytes, SHA-256
`dc9f56c23e0dcf182b6c35f23fbb102ed048296588882b806d5eff7654c04c88`.
CPU 플랫폼 호환성을 확인했다. GPU/NPU extras, 대규모 Backend 또는 자동 패키지 갱신은 사용하지 않았다.
PyPI 근거: https://pypi.org/pypi/ai-edge-litert/2.3.0/json .

실제 추론 환경에서 확인한 나머지 버전:

| 배포 | 버전 |
|---|---|
| network-security-ai | 0.1.0 |
| dns-security-ai | 0.1.0 |
| security-ai | 0.1.0 |
| numpy | 2.5.3 |
| pydantic | 2.13.5 |
| lightgbm | 4.7.0 |
| torch | 2.14.1 |
| ai-edge-litert | 2.3.0 |
| scikit-learn | 1.9.1 |
| joblib | 1.6.0 |
| pandas | 3.0.6 |

## 2. 공식 Artifact 설치 및 불변성

기존 `security_ai.artifacts::{create_bundles,install_local,verify_install}`만 사용했다.
ML `models/network/`와 legacy DNS 원본에서 공식 Catalog가 고정한 3개 Bundle을
새 임시 경로에 생성했다. Archive SHA도 Catalog와 일치해야 설치가 진행된다.
별도 `artifacts/`에 **10개 파일**을 설치하고 검증했다. 원본 모델·Scaler는 변경하지 않았다.

- Quality: `lightgbm_top40_v4b2.txt`, model SHA
  `eb28cc855a65d336cd1b2720ec4fcc2958874444e33fae5b78c1cae4e4c62924`.
  공식 Quality 경로는 별도 Scaler를 사용하지 않는다.
- Edge: `dnn_top40_v4_best.pt`, SHA
  `85cbc702d1b0a137c4f44b23be6911691cc89d5bfef0c388cf282e9500c49160`;
  Scaler SHA `528cfa770181bb61bdcc5d30b2cae8a171dfa63399f3fd33f9a15ab5fbc67d32`.
- DNS: `dnn_int8.tflite`, SHA
  `28e089af363dd565a4fb3d3f202de9e9f9804bd14a164de4fd7b61adb1201e33`;
  Scaler SHA `2735f7650a7d7888ee68f2df870b4e29d83666962931ae2aecb9aa339f40266a`.
- Metadata/Feature/Label Manifest도 같은 공식 검증 대상이다. 계약 code pin은
  `56293972d069dffaf564a390ab7a4c4554c2a2a5b2ab6be6f6f758b5ea3cce44`다.

## 3. Native 추론 결과

`tests.diagnose_external_context`를 실제 격리 interpreter에서 실행했다.
공식 순서의 각 값 1.0인 **SYNTHETIC_PRECOMPUTED_FEATURE_FIXTURE**를 사용한다.
각 모델 1회, 총 3회 실제 추론과 Adapter/Context 검증을 완료했다.
이후 Native E2E 테스트에도 추론이 반복되므로 이를 전체 호출 횟수 3회라고 주장하지 않는다.

| Binding | 공식 Model ID / Version | 실제 추론 | 입력 / 출력 |
|---|---|---|---|
| dns | `dns_cicbell_dnn_int8` / `int8-sha256-28e089af363d` | VERIFIED | `cic-bell-dns-stateless9-v1` → `VALIDATED_FOR_ADVISORY` |
| network-edge | `network_cse2018_dnn_fp32` / `v4-fp32-epoch13` | VERIFIED | `cse-cic-ids2018-top40-v1` → `VALIDATED_FOR_ADVISORY` |
| network-quality | `network_cse2018_lightgbm_v4b2` / `v4-b2` | VERIFIED | `cse-cic-ids2018-top40-v1` → `VALIDATED_FOR_ADVISORY` |

Quality/Edge는 공식 Top40 순서와 float32 입력을 유지했다. Quality는 LightGBM,
Edge는 저장 Scaler를 사용하는 **FP32 PyTorch** 모델로, Edge를 INT8 모델이라고 표시하지 않는다.
DNS는 공식 DNS9 → 저장 StandardScaler → INT8 quantization → LiteRT → 공식
Prediction Schema 경로다. Feature를 추정 생성하거나 결측값을 임의 보완하지 않았다.

## 4. Adapter → Context → Agent

기존 `external/inference.py`, `service.py`, `adapters.py`, `assembly.py`, `projection.py`,
`runtime_guard.py`, `runtime_integration.py`를 재사용했다.

- Artifact/Binding/Schema/order/float32 input digest와 원본 Evidence 연결을 재검증한다.
- Native 3모델 Context는 결과 3개, 관측 Correlation Group **2개**다. Quality/Edge의
  같은 Flow는 1관측이고 DNS는 별도 관측이다. 점수를 합산·평균하지 않는다.
- Native Model → 기존 ApplicationService → 실제 SOCRuntime → READ Tool → Assessment
  → Decision → Receipt/Checkpoint → Restore를 검증했다. CLI Desktop/SERVER 및
  Loopback ASGI 인증·권한 경계도 기존 테스트로 검증했다. GUI 또는 운영 배포가 아니다.
- LLM은 **MockLLM/scripted**이며 실제 API 요청은 0이다. Native 모델 추론과 구분한다.
- UNLINKED 제외, Source/Incident Binding, MODEL_FACT_PROMOTION, READ-only Tool 및
  WRITE_DENIED 경계는 유지된다. Native 출력은 관측 Evidence나 실행 권한이 아니다.

## 5. 실제 WSL Authentication Runtime

기존 journald/PAM Collector를 그대로 사용했다. 새로운 로그인 시도나 실패 이벤트를
생성하지 않았으며 아래 기록은 **기존 실제 Journal 기록의 재수집**이다.
독립 기준 HEAD Git Export에서 실제 Continuous CLI를 시작하고 종료·재시작했다.

| 항목 | 실제 결과 |
|---|---|
| 입력 기록 | 512 |
| 지원 인증 이벤트 | 1 |
| 지원하지 않는 기록 | 511 |
| 거부 이벤트 | 0 |
| 5분 Window | 1 |
| Provenance v3 | 1 |
| Queue | {'DONE': 512} |
| READ-only 조사 완료 | 1 |
| 정상 종료 후 Cursor | RESUMED_EXACT |
| 재시작 후 Cursor | RESUMED_EXACT |
| SQLite integrity_check | ok, ok, ok |
| Audit 검증 | True |

첫 실행은 **30초 제한 Smoke**, 실제 시작/종료 벽시계 **31.609초**다.
재시작한 소유 자식 Runtime에만 SIGTERM을 보냈고 Exit 0,
전송 후 종료까지 **0.469초**였다. 보편적인 종료 SLA를 주장하지 않는다.
최종 수정 Export로 3초 제한 재시작도 수행했고 Runtime uptime 3.628초,
Cursor RESUMED_EXACT, 완료 READ 조사 1건 및 backlog 0을 유지했다.
최종 원본 재조회에서도 Queue DONE 560건, 인증 이벤트·Window·Provenance·완료 조사
각 1개와 Audit 검증 성공을 확인했다. 추가 Journal 기록을 처리한 증가이며 검증 인증 이벤트의 중복 집계는 없었다.

지원 이벤트는 sudo PAM 모듈 인증 실패이며 최종 로그인 실패나 공격 사실로 승격하지 않는다.
이번 실제 로그에서 SSH 성공·실패나 일반 로그인 성공까지 검증한 것은 아니다.
지원하지 않는 511개 기록은 인증 성공/실패로 추정하지 않는다. Source/Window/v3 재조회·
Digest 검증을 통과했다. 실제 WSL 이벤트로 탐지 정확도나 장기간 안정성을 추정하지 않는다.
실제 LLM 0, 실제 OS 보안 조치 0이다. 멈춘 Runtime은 NOT_READY로 표시된다.

실제 실행 방식 (새 전용 디렉터리, 테스트 임계값임을 기록):

```bash
.venv/bin/python -m soc_agent.linux_runtime --directory /private/new-runtime init \
  --repeated-failures 5 --multiple-accounts 3 --poll-seconds 0.2 --assessment-mode READ_ONLY
.venv/bin/python -m soc_agent.linux_runtime --directory /private/new-runtime start --duration-seconds 30
.venv/bin/python -m soc_agent.linux_runtime --directory /private/new-runtime status
# 재시작/SIGTERM은 이 진단이 소유한 자식 프로세스에만 수행했다.
```

## 6. Runtime Hardening — 재현 결함과 최소 수정

기존 CLI status가 Response Simulation UNCERTAIN은 확인하지만 Restricted Response
UNKNOWN을 확인하지 않았다. 승인 후 STARTED reservation을 남기고 기존 recovery를
호출하면 UNKNOWN이 되는데도 CLI는 **READY**였다.
`tests/integration/native_hardening/test_readiness.py`의 최초 실행은 **1 failed**로 재현했다.

수정:

- `restricted_response.py::RestrictedResponseExecutor.read_records`로 기존 append-only
  레코드 검증을 공유한다. 실행 경로는 같은 검증 함수를 계속 사용한다.
- `read_restricted_status`는 실제 기존 Audit/Binding/상태 이력을 읽기 전용으로 검증한다.
  STARTED/UNKNOWN 또는 Recovery Conflict를 별도 표시한다. Marker를 변경하지 않는다.
- CLI `status`는 Restricted UNKNOWN/BLOCKED와 Simulation STARTED/UNCERTAIN에서
  NOT_READY를 반환한다. UNKNOWN을 성공·실패로 덮어쓰거나 재실행하지 않는다.
- 조회 전후 DB dump와 Marker bytes가 동일함을 테스트했다. 재시작·충돌·변조는
  기존 Crash/Guard 테스트와 함께 검증했다. 승인·정책·실제 OS 대응 권한은 변경하지 않았다.

LLM timeout/불확실한 호출은 기존 Runtime 원장의 BLOCKED/UNKNOWN 상태로 보존하고,
자동 재시도하지 않는 회귀를 실행했다. Restricted filesystem 효과와 SQLite Commit은
원자적이지 않다. Exactly-once 외부 호출/파일 효과를 주장하지 않는다.

## 7. GUI Status Contract

기존 `ApplicationService.security_ai_status()`를 확장했다. GUI/HTTP 서버는 추가하지 않았다.

- Native interpreter가 설정돼 있으면 고정된 metadata-only Python 모듈을 호출한다.
  Shell·모델 입력 명령·LLM은 사용하지 않는다. Child에 Provider Secret을 전달하지 않는다.
  Timeout 30초, 응답 크기/Schema/세 모델 목록 및 추론 주장 금지를 검사한다.
- 다른 interpreter 실패를 현재 SOC 환경의 성공으로 대체하지 않는다. UNKNOWN/BLOCKED를
  반환한다. 모델 경로·원본 로그·Secret·stderr 원문은 조회 결과에 넣지 않는다.
- `environment_scope`는 CURRENT_INTERPRETER / CONFIGURED_NATIVE_INTERPRETER다.
- `security_ai_status(incident_id=...)`는 기존 Runtime binding 및 Context/source/digest를
  재검증하고 `last_validation`에 **저장된 이력**만 반환한다. 조회 실패는 BLOCKED다.
  Recorded timestamp/model bindings/result/environment digests와
  `native_inference_this_query=false`로 현재 추론과 구분한다.
- 일반 조회의 `demo_inference`는 UNKNOWN이다. 실제 추론 확인은 명시적인
  `verify_fixture_demo`를 Native 환경에서 실행한 결과에만 VERIFIED를 부여한다.
  실제 probe 4개 사례를 실행했다. 모델/Feature 운영 정합성은 부여하지 않는다.
- `backend_dependencies=VERIFIED`는 배포 metadata 존재를 뜻하며, 실제 모델 로딩
  성공은 별도 probe/검증 이력으로 표시해야 한다. 이 응답은 실행 Capability가 아니다.

| GUI 항목 | 이번 검증 환경에서 표시할 근거 |
|---|---|
| Package Installed / Import | 세 배포 0.1.0, VERIFIED |
| Artifact Verified | 공식 설치 10파일 검증 |
| Backend Available | 설정된 격리 환경, 배포 metadata 확인 |
| Native Inference / Fixture Demo | 명시적 probe VERIFIED, 입력은 synthetic Feature |
| Last Validation | 저장된 Context lineage, RECORDED; 새로운 추론이 아님 |
| Operational Input | Network/DNS NOT_INFERABLE |
| Approval / 실제 대응 권한 | 부여하지 않음, WRITE_DENIED |

현재 설정은 trusted composition에만 전달한다:
`compose_application(..., external_artifacts=artifact_root, external_interpreter=python_path)`.
경로를 GUI 사용자 입력에서 받아 명령 실행하는 기능을 추가하지 않는다.
조회는 파일 해싱/자식 실행이 있으므로 GUI 렌더링 thread 또는 빈번한 poll에서 직접 호출하지 않는다.

## 8. Tests / Quality / 독립 재현

| 실행 | 실제 결과 | 증거 로그 |
|---|---|---|
| 최초 UNKNOWN Readiness 결함 재현 | 1 failed (수정 전), 즉시 수정 재검증 1 passed | soc-native-readiness-before/after.log |
| 신규/기존 조회 계약 테스트 | 34 passed, 6.99초 (추가 경계 2개는 아래 최종 Export에서 검증) | soc-native-new-tests.log |
| Native 3모델 → Adapter/Context → Runtime/CLI/ASGI | 8 passed, 70.78초 | soc-native-native-e2e.log |
| Native Runtime + GUI 조회/저장 이력/Restore | 4 passed, 49.71초 | soc-native-status-e2e.log |
| 실제 Native Fixture probe | 4 passed, 7.34초 | soc-native-fixture-probe.log |
| Native CLI 실패 경로 / 중복 프로세스 | 6 passed, 28.39초 | soc-native-faults.log |
| 관련 Runtime/Restricted/Scenario/Approval/Execution/LLM/Adapter/Operational 회귀 | 522 passed, 229.81초 | soc-native-regression.log |
| 독립 Git Export 최종 코드 | 59 passed, 145.76초 | soc-native-export-tests.log |
| 독립 Export의 Native Fixture probe | 4 passed, 3.59초 | soc-native-export-fixture-probe.log |
| Ruff / Format / Git Diff | PASS | soc-native-ruff/format.log |

최종 Export에는 신규 Readiness 3개 및 상태 13개, Native 상태/이력 4개,
기존 Package Status/LLM invocation recovery/Restricted Crash/Native Runtime을 포함했다.
기존 실패는 해결됐으며 위 최종 테스트 실행에는 실패/Skip이 없다.
최초 34개 실행과 다른 실행은 중복되므로 합산하지 않는다.

관련 회귀 실행:

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest --import-mode=importlib -q \
  tests/integration/linux_runtime tests/integration/restricted_response \
  tests/integration/scenario tests/unit/approval tests/unit/execution tests/unit/llm \
  tests/unit/security_ai/external tests/unit/external_context \
  tests/integration/external_read_only_backend \
  tests/unit/operational_features/test_native_authentication.py \
  tests/unit/operational_features/test_pam_authentication.py \
  tests/unit/operational_features/test_authentication_investigation.py \
  tests/unit/operational_features/test_operational_provenance.py \
  tests/unit/operational_features/test_adapter_boundary.py
```

모든 테스트 로그는 `/tmp/soc-native-*.log`에 저장했다. 실제 API 호출은 비활성이다.
테스트 실행별 수치는 중복되므로 합산하지 않는다. 전체 프로젝트 회귀를 반복하지 않았다.

Git Export는 기준 HEAD의 git archive에 이번 소스/테스트만 overlay했다.
`__main__.py`에는 미커밋 Replay 코드가 있어 **status 함수 수정만** 분리했다.
해당 수정만 제거하면 작업 시작 시 사용자 파일 SHA가 복원되는지 확인했다.
Export 안의 soc_agent Import 경로도 확인했다. 기존 가상환경/격리 Native 환경을
재사용하며, 모델 파일은 읽기 전용으로 사용했다. 의존성 클린 설치 시험은 아니다.

검증 명령 (Native 환경 변수는 `/tmp/soc-native-environment.json`의 승인된 로컬 설정):

```bash
RUN_LIVE_LLM_TESTS=0 SOC_EXTERNAL_ARTIFACT_ROOT=/configured/artifacts \
  SOC_EXTERNAL_INFERENCE_PYTHON=/configured/inference/bin/python \
  .venv/bin/python -m pytest --import-mode=importlib -q \
  tests/integration/external_security_ai/test_native_context.py \
  tests/integration/external_context_diagnostic/test_native_subprocess.py \
  tests/integration/external_runtime/test_native.py \
  tests/integration/external_runtime/test_gate_c_entrypoints.py \
  tests/integration/external_runtime/test_gate_d_fail_closed.py \
  tests/native_package_status_checks.py
# Native interpreter로 직접 실행하는 명시적 Fixture probe:
RUN_LIVE_LLM_TESTS=0 SOC_EXTERNAL_ARTIFACT_ROOT=/configured/artifacts \
  /configured/inference/bin/python -m pytest --import-mode=importlib -q \
  tests/native_fixture_probe_checks.py
```

## 9. 변경 파일 / 보존

- `src/soc_agent/security_ai/external/package_status.py`
- `src/soc_agent/api/service.py`
- `src/soc_agent/linux_runtime/restricted_response.py`
- `src/soc_agent/linux_runtime/__main__.py` — status 함수의 이번 변경만 Stage.
- `tests/integration/native_hardening/test_readiness.py`
- `tests/integration/native_hardening/test_status.py`
- `tests/native_package_status_checks.py`
- `tests/native_fixture_probe_checks.py`
- 이 보고서.

README/pyproject/Command Center/미커밋 Reliability Replay/모든 기존 미추적 파일은
이번 Stage 대상이 아니다. Artifact, 가상환경, DB, 원본 로그, 임시 Manifest도 제외한다.
`tests/fusion_support.py`와 Synthetic v2/Operational Provenance v3 의미를 보존한다.

## 10. 남은 제한 및 후속 단계

- Network/DNS Producer revision/config와 Raw↔Feature Golden Pair 미확보다.
  Native 추론 성공이 운영 Feature/모델 학습 정합성 또는 공격 탐지 효능을 증명하지 않는다.
- DNS DNN 학습/export/scaler pairing과 calibration은 여전히 UNVERIFIED다.
- 환경은 임시 경로 및 기존 ML/SOC 의존성에 연결된다. 물리 Linux 서버에 배포 가능한
  독립 lock/설치 재현성과 Native ABI 검증은 후속이다. 이번 환경을 보존하거나 명시적 재구성 후 검증해야 한다.
- 단기 Smoke만 수행했다. 장시간 Soak, 부하/메모리/디스크 증가의 새 검증은 하지 않았다.
- 실제 LLM API·실제 운영 대응·GUI·물리 서버·Windows·AWS는 이번에 검증하지 않았다.
- Resource UNKNOWN은 수동 reconciliation 대상이며 자동 재실행/자동 성공 확정하지 않는다.
- GUI는 입력 Origin, 현재 Backend 환경, 과거 이력, synthetic Native 시연 및 운영 차단을
  별도로 표시해야 한다. 패키지 상태는 Human Approval이나 실행 권한이 아니다.

## 검증 로그 무결성 참고

- `soc-native-native-e2e.log` SHA-256: `0aa5b0c37fd029550a23efea0b3d16559ec28af3803095a6df8d90c185cfaf75`.
- `soc-native-status-e2e.log` SHA-256: `5e556d3a0a1fc012281e8339ed7c21d9061c017d9a030c9981c64dc2a264a5bb`.
- `soc-native-fixture-probe.log` SHA-256: `1bd5111cee90ff598e7098dae0177efd3370d9ed15d008ccf4e7d003c34c7cec`.
- `soc-native-faults.log` SHA-256: `c10a13473cb9a67beb7ce842ca3c4773938dd66f1e84bbf6cbd1875303ad00d9`.
- `soc-native-regression.log` SHA-256: `7cc34872285e4eb2fbbad1e9103ed10a23b1cdeeb886146b3b7520ba1503fc0d`.
- `soc-native-export-tests.log` SHA-256: `4c539f384ff691f52363861562db1ec2bc3cd1f8b5d42e4d04f8fb83b58a3343`.
- `soc-native-export-fixture-probe.log` SHA-256: `29d5f001aad8140574443506f96dc283b28de12c643ec5fcb3e2f222070576c4`.
- `soc-native-auth-probe.log` SHA-256: `bf73eab20a132feb03b96f346e4c544caf54b2bff1780b2e19fa26dc588811f7`.
- `soc-native-auth-final-restart.log` SHA-256: `28d703a7e0c5804c39494b659659ab63b4f8c7d8a68ab0f1b474ef128851586b`.
- `soc-native-ruff.log` SHA-256: `82b3e6a6c090a57601d22943bd23fca9218d1031dbe5a7b754092f9a156b4f18`.
- `soc-native-format.log` SHA-256: `4d4fa0e6bdd46a69b3bb2dda89d8b5548e33e9243cf9eabdc0ca598a42477ef6`.
