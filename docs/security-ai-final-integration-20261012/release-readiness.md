# Security AI Integration — 릴리스 준비 검증 (2026-10-13)

## 1. 판정 및 허용 범위

**READY_FOR_CONTROLLED_RELEASE** — 검증된 Python CLI/ASGI 기반 오프라인,
합성 입력·격리 Handler 테스트 릴리스에 한정한다.
**운영 배포 준비: INCONCLUSIVE**. 최신 Windows 전체 회귀와 별도 운영 호스트,
실제 서비스 listener/인증 Provider 배포는 미검증이다.
통제된 테스트 릴리스와 운영 배포 준비 상태를 구분한다. 검증 범위는 합성/사전 계산
입력, 공식 모델 native 추론, scripted LLM, 격리된 SQLite와 READ/WRITE 테스트 Handler다.
실제 운영 보안 조치, 실제 사용자 데이터, 외부 LLM 및 운영 배포는 수행하지 않았다.

## 2. 기존 증거 재사용

`validation-results.json`, `report.md`, `windows-validation.md`, `remaining-risks.md`와
SHA manifest를 확인했다. 최종 변경 파일 33개 모두 현재 WSL SHA와 일치한다.
전체 source-copy manifest에 최종 변경 SHA를 적용한 617개 파일도 WSL 및
`C:\soc-agent-final-native-20261013`에서 모두 일치했다. `evidence-sha256.json`의
기존 증거 파일도 모두 일치한다. 따라서 아래 이전 실행 결과를 재사용하며 이번
신규 실행 결과로 중복 계상하지 않는다.

- WSL 전체 회귀: **3104 passed, 25 skipped, 0 failed** (1018.98초).
- Windows Native Runtime/모델/NTFS/Decision 집중: **121 passed, 2 skipped**.
- Windows 최종 private artifact/READ binding: **12 passed**; 동일 Runtime CAS: **4 passed**.
- 실제 Quality LightGBM / Edge DNN FP32 / DNS LiteRT 추론 및 Runtime 저장·복원.

기존 `C:\soc-agent-windows-test`의 동기화 대상 33개도 기록된 preimage와 일치하며
수정하지 않았다(신규 파일 부재 포함). 사용자가 지정한 첫 번째 격리본
`C:\soc-agent-final-integration-20261013`은 최종 변경 파일 14개가 달라 최신 검증에
사용하지 않았다. 최신 격리본은 `C:\soc-agent-final-native-20261013`이다.

이번 작업에서 소스/테스트 코드 변경이 없어 전체 WSL 회귀는 **재실행하지 않았다**.
전체 Windows 회귀는 과거 약 60분 실행 비용과 이미 확보한 집중 증거를 고려해
재실행하지 않았다. 최신 전체 Windows 범위는 **INCONCLUSIVE**다.

## 3. 이번 실제 실행

| 검증 | 결과 | 로그 |
|---|---|---|
| WSL API / Execution / Approval / Policy / Durable Execution | 265 passed, 0 failed (67.05초) | `/tmp/soc-release-focused-wsl.log` |
| WSL Headless ASGI lifespan / 인증 READ / 미인증 거부 / 잘못된 WRITE 요청 / Restore | 4 passed, 0 failed (17.94초) | `/tmp/soc-release-headless.log` |
| Windows 동일 API / 실행 경계 집중, 보완 전 | 249 passed, 16 failed (586.95초) | 최신 격리본 `windows-release-focused.log` |
| Windows 실패 16개 환경 보완 후 | 16 passed, 0 failed (47.33초) | 최신 격리본 `windows-release-repaired.log` |
| Ruff `check src tests` | PASS | `/tmp/soc-release-ruff.log` |
| Ruff `format --check .` | PASS, 672 files | `/tmp/soc-release-format.log` |
| `git diff --check` | PASS | 실제 실행 |

Headless 추가 진단은 `/tmp/test_soc_release_headless.py`에서 기존 실제
SOCApplication, SOCRuntime, Companion Store와 네 가지 Context fixture를 사용했다.
테스트 인증 Provider와 scripted LLM을 사용하며 Guard는 대체하지 않았다.
ASGI startup/shutdown을 두 번 수행하고 READ 200, 미인증 401, 잘못된
approval-requests 422, Restore의 사람 대기, 저장된 Decision Receipt/Audit,
WRITE Spy 0을 확인했다. 임시 진단의 TestAccess 클래스 수집 경고 1개는
동작 실패가 아니다. 별도 운영 호스트, 실제 네트워크 listener 배포 및 운영 인증
Provider 검증은 수행하지 않았다. 프로세스 재시작/강제 종료 복구는 기존
Runtime/CLI 실제 프로세스 검증 증거를 재사용한다.

## 4. 대표 실제 모델 E2E

`wsl-headless-smoke-evidence.json`, `wsl-desktop-smoke-evidence.json`,
`windows-desktop-smoke-evidence.json` 및 기존 native Runtime 테스트를 재사용한다.
공식 Predictor → Envelope 검증 → Context v2 → 실제 SOCRuntime → Assessment →
Decision → Receipt/Checkpoint → 재시작/Resume 경로다.
Quality/Edge는 같은 Network 관측 아래 유지되고 DNS는 별도 관측이다.
모델 결과는 관측 사실로 승격되지 않고 점수를 임의 합산하지 않는다.
기존 Decision ID/Payload 생성 계약과 Context digest/Resume 무결성을 유지한다.

WSL Headless 기록: 관측 2개, correlation group 2개, 모델 3개, publication 11개,
assessment run 2개, decision receipt 2개, security audit 14개, execution record 0개.
Windows Desktop 기록: publication 12개, run/receipt 각각 2개, audit 16개,
execution record 0개. 두 기록 모두 `waiting_for_human=true`, `terminal=false`다.
이 대기는 조사 loop guard에 따른 사람 검토 경계이며, 새로운 유효 ApprovalRequest
발급/승인 완료를 의미하지 않는다. 이번 작업에서 WSL/Windows 전체 Decision
동등성을 새로 증명한 것으로 해석하지 않는다.

## 5. Backend 보안 경계

기존 `security-boundary.md`의 WRITE 진입점 inventory를 확인했다. Tool dispatcher,
Tool/실제 Handler 직전, GovernedExecutor, proposal 검증, DurableExecutor,
Approval/HumanReview/Confirmation, Promotion/ExecutionBridge, state CAS,
Self-improvement activation/rollback, ApplicationService/ASGI, Runtime
start/restore/advance에서 같은 보호 경계를 사용한다. 별도 autonomous action
queue는 구현되어 있지 않다. Desktop/Headless profile은 실행 권한을 부여하지 않는다.
최종 실제 READ incident binding과 task-local CAS 회귀도 기존 최종 증거에 포함된다.
이번 조사에서 새 지원 API의 Guard 누락은 발견하지 않았다.

READ_ONLY Capability는 Approval이 있어도 WRITE 권한을 얻지 못한다.
Guard/Policy/승인/NTFS/POSIX/SQLite/Provenance 제한을 변경하지 않았다.
신뢰되지 않은 임의 Python 코드, raw SQL 및 OS 조작을 막는 sandbox를 주장하지 않는다.
그 범위에는 별도 OS 권한/프로세스 격리가 필요하다.

## 6. 발견 및 조치

Windows 추가 API 테스트 최초 실행에서 `src/soc_agent/api/dashboard/style.css`
누락으로 **수집 오류 5개**가 발생했다. 이는 격리본 준비 시 Python 파일 위주로
복사하면서 리소스를 제외한 검증 환경 결함이다. 프로덕션 JSON/ACL/Guard 문제로
오인하거나 검증을 완화하지 않았다.

원본 SHA-256:
`084d22ea571803722bcf7df100d301f94c535c5f5d25685cb71b123909354087`.
해당 신규 파일만 최신 격리본에 `CreateNew`로 복사했고 복사 후 같은 SHA를 확인했다.
원본 Windows 검증본과 기존 파일은 덮어쓰지 않았다.
복사 기록: `/tmp/soc-release-resource-sync.json`.
후속 실행의 16개 실패는 모두 `tests/fusion_support.py:20`에서 역사적
`docs/evaluation/synthetic-phase3-5.json`을 찾지 못한 `FileNotFoundError`였다.
환경/Fixture 누락 16건, Windows 플랫폼 제약 0건, Legacy 코드 결함 0건,
신규 Security AI 통합 회귀 0건으로 분류한다. 유효한 원본은 ASCII JSON이며
SHA-256 `f9525ade3ef733eab87e3d95ac6fd40a0da72a7c02b12e51d665c85551df8ca7`이다.
원본 바이트 그대로 격리본에 `CreateNew`로 추가하고 SHA를 다시 검증했다.
역사적 보고서/Selection Digest 및 보호 helper는 수정하지 않았다.
기존 실패 로그의 정확한 node ID 16개만 재실행해 **16 passed, 0 failed**를 확인했다.
통과한 249개는 재사용한다. 따라서 해당 Windows 집중 범위는 합산 **265 passed**이며
이는 전체 Windows suite를 새로 실행한 결과가 아니다. 미해결 실제 실패는 0개다.
보완 전 로그와 보완 후 로그를 따로 보존해 실패 이력을 숨기지 않았다.

**프로덕션 코드/테스트 변경 없음**. 저장소 신규 산출물은 이 문서 하나다.
Conda base 및 기존 Conda 환경은 변경하지 않았다.

## 7. 미검증 및 릴리스 제한

- 최신 Windows 전체 회귀: INCONCLUSIVE (집중 검증으로 대체한 범위 명시).
- 별도 Linux Desktop 및 Linux Headless 운영 호스트 배포: INCONCLUSIVE.
- 실제 HTTP listener/service 설치·운영 인증 Provider: 미검증.
- 신규 외부 모델의 전체 교차 플랫폼 판단 동등성: 미검증; 기존 SOC Gate A 결과와 구분.
- 실시간 Collector/실제 feature extraction 및 production detection efficacy: 미검증.
- GUI, PyInstaller, installer/제거: 부재; Python CLI/API 수준의 검증만 수행.
- 원자적 v16 Runtime 저장은 opt-in 전용 신규 저장소이며 운영 v14/v15 자동 Migration 없음.
- 중단된 READ claim은 명시적 reconciliation, 기존 stale writer lock은 수동 확인 필요.
- 운영 대응/WRITE는 실행하지 않았으며 운영 배포 준비 완료를 주장하지 않는다.

## 8. 사용자 다음 명령

최신 격리본에서 기존 환경을 그대로 사용한다. 기존 Windows 검증본에 반영할 때는
`windows-sync.json` 및 `windows-validation.md`의 source/preimage SHA 확인과
백업 절차를 따른다. 다른 내용의 기존 파일은 충돌 처리하고 무조건 덮어쓰지 않는다.
전체 소스 복사에는 CSS 등 package resource도 포함해야 한다.

```powershell
conda activate soc-windows
Set-Location C:\soc-agent-final-native-20261013
$env:RUN_LIVE_LLM_TESTS = '0'
$env:PYTHONPATH = "$PWD\src"
$env:SOC_EXTERNAL_ARTIFACT_ROOT = Join-Path $env:LOCALAPPDATA 'AutonomousSOCFinalArtifacts20261013'
$env:SOC_EXTERNAL_INFERENCE_PYTHON = 'C:\soc-native-inference-final-20261013\Scripts\python.exe'
python -m soc_agent.external_runtime --help
# 비용이 큰 전체 검증은 필요 시 별도로 실행
python -m pytest -q --tb=short -rs -rfE *> windows-release-full.log
python -m ruff check src tests
python -m ruff format --check .
```

새 전용 private data directory와 검증된 JSONL fixture에 대해서만 Runtime CLI를
실행한다. 명령 예시는 기존 `windows-validation.md`를 사용한다. Server profile은
Linux에서만 사용하며 Windows Server 지원을 주장하지 않는다.

외부 Provider 요청 0, 실제 운영 보안 WRITE 0, commit/push 0.
`tests/fusion_support.py` SHA:
`e5f9d10f706f71b82e80261f7633a1504e27ba24499be948d04adb6eeb3a21c9` (보존).

## 검증 로그 SHA-256

- `windows-release-focused.log` (최신 격리본, UTF-16): `e32f19f723442dd82d305b519eb99101eab95a202b991f024355d87fb1bee760`
- `windows-release-repaired.log` (최신 격리본, UTF-16): `6c22fe1cabf183b3668b115a5b77bc5b9e1829cd50566e49c7d2dbfb84079088`

## Gate B RC 기준선 커밋 검토

사용자가 허용한 이전 단계 필수 의존성과 SHA 일치 helper 예외를 적용한다.
139개 소스·테스트 후보와 helper/문서까지 총 149개를 파일별로 아래에서 분류했다.
독립 Native/Selection 비교 테스트 3개와 live-provider 테스트 2개는 Gate B 실행에
필수이지 않아 제외하고 원본 working tree에 보존한다. 실제 사용되는 진단 모듈은
Gate A 및 Gate B 진단의 import 의존성이므로 포함한다. 모델 바이너리, DB, 로그,
가상환경, Windows 복사본, 개인 설정, 임시 JSON/SHA manifest는 포함하지 않는다.
기존 README/pyproject 및 기타 문서의 사용자 변경도 포함하지 않는다.

추가 포함 문서는 `windows-validation.md`로 Windows 실행 절차를 보존한다.
Conda 업데이트 대기 언급은 현재 요청과 무관하며 업데이트는 수행하지 않는다.
Ruff/Format/Diff 및 자격 증명 패턴 검사는 PASS. `.env`는 읽지 않았다.
검증된 helper SHA 일치 확인 후에만 Stage하며 내용은 수정하지 않는다.
기존 full/E2E 증거를 재사용하고 전체 회귀를 실행하지 않는다.

| 파일 | 분류 | 선택 |
|---|---|---|
| `src/soc_agent/api/dashboard/self_improvement_models.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/api/dashboard/self_improvement_query.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/api/dashboard/self_improvement_render.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/application.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/demo/__main__.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/demo/command_center.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/demo/local_server.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/demo/model_analysis.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/demo/scenarios.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/deployment.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/desktop.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/execution/security.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/external_runtime.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/ingestion/network.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/live.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/llm/openai_compatible.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/local_events.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/review/persistence/secure_storage.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/review/persistence/self_improvement.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/review/persistence/windows_storage.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/runtime_driver.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/runtime_lock.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/security_ai/evaluation/reference_probability.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/security_ai/external/__init__.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/adapters.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/assembly.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/diagnostic.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/inference.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/inference_worker.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/metadata.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/models.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/projection.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/read_only_backend.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/records.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/runtime_guard.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/runtime_integration.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/runtime_store.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/service.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/storage.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/storage_schema.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/external/validation.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/model_analysis.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/security_ai/packaging/windows_files.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/tools/guard.py` | Gate B 직접 구현 | 포함 |
| `tests/decision_pipeline_contract.py` | 테스트 | 포함 |
| `tests/diagnose_decision_pipeline.py` | 테스트 | 포함 |
| `tests/diagnose_external_context.py` | 테스트 | 포함 |
| `tests/diagnose_gate_b_packages.py` | 테스트 | 포함 |
| `tests/diagnose_native_inference.py` | 테스트 | 포함 |
| `tests/diagnose_windows_selection.py` | 테스트 | 포함 |
| `tests/external_advisory_support.py` | 테스트 | 포함 |
| `tests/fixtures/decision_pipeline_events_v1.json` | 테스트 | 포함 |
| `tests/fixtures/synthetic_network_draws_v1.json` | 테스트 | 포함 |
| `tests/integration/api/test_self_improvement.py` | 테스트 | 포함 |
| `tests/integration/demo/test_command_center.py` | 테스트 | 포함 |
| `tests/integration/demo/test_decision_pipeline_equivalence.py` | 테스트 | 포함 |
| `tests/integration/demo/test_deployment_composition.py` | 테스트 | 포함 |
| `tests/integration/demo/test_desktop_runtime.py` | 테스트 | 포함 |
| `tests/integration/demo/test_live_runtime.py` | 테스트 | 포함 |
| `tests/integration/demo/test_live_security_ai.py` | 테스트 | 포함 |
| `tests/integration/demo/test_native_artifact_portability.py` | 무관한 사용자 변경 | 제외 |
| `tests/integration/external_context_diagnostic/test_diagnostic.py` | 테스트 | 포함 |
| `tests/integration/external_context_diagnostic/test_native_subprocess.py` | 테스트 | 포함 |
| `tests/integration/external_context_storage/test_store.py` | 테스트 | 포함 |
| `tests/integration/external_read_only_backend/test_guard.py` | 테스트 | 포함 |
| `tests/integration/external_runtime/test_native.py` | 테스트 | 포함 |
| `tests/integration/external_runtime/test_runtime.py` | 테스트 | 포함 |
| `tests/integration/external_security_ai/test_native_context.py` | 테스트 | 포함 |
| `tests/live/conftest.py` | 무관한 사용자 변경 | 제외 |
| `tests/live/test_live_llm_boundaries.py` | 무관한 사용자 변경 | 제외 |
| `tests/native_external_decision_checks.py` | 테스트 | 포함 |
| `tests/native_inference_compare.py` | 테스트 | 포함 |
| `tests/platform_support.py` | 테스트 | 포함 |
| `tests/selection_equivalence.py` | 테스트 | 포함 |
| `tests/unit/__init__.py` | 테스트 | 포함 |
| `tests/unit/external_context/test_assembly.py` | 테스트 | 포함 |
| `tests/unit/llm/test_openai_compatible.py` | 테스트 | 포함 |
| `tests/unit/persistence/test_native_windows_storage.py` | 테스트 | 포함 |
| `tests/unit/persistence/test_secure_storage.py` | 테스트 | 포함 |
| `tests/unit/persistence/test_windows_storage_contract.py` | 테스트 | 포함 |
| `tests/unit/ruff.toml` | 테스트 | 포함 |
| `tests/unit/security_ai/evaluation/test_reproducible_inputs.py` | 테스트 | 포함 |
| `tests/unit/security_ai/external/conftest.py` | 테스트 | 포함 |
| `tests/unit/security_ai/external/test_adapter.py` | 테스트 | 포함 |
| `tests/unit/security_ai/packaging/test_windows_files.py` | 테스트 | 포함 |
| `tests/unit/test_demo_json_encoding.py` | 테스트 | 포함 |
| `tests/unit/test_gate_b_diagnostics.py` | 테스트 | 포함 |
| `tests/unit/test_native_inference_comparison.py` | 무관한 사용자 변경 | 제외 |
| `tests/unit/test_runtime_lock.py` | 테스트 | 포함 |
| `tests/unit/test_selection_diagnostics.py` | 테스트 | 포함 |
| `tests/unit/test_selection_equivalence.py` | 무관한 사용자 변경 | 제외 |
| `tests/unit/test_test_storage_fixtures.py` | 테스트 | 포함 |
| `tests/windows_storage_support.py` | 테스트 | 포함 |
| `src/soc_agent/api/dashboard/render.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/api/http.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/api/service.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/approval/manager.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/demo/authentication.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/demo/composition.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/demo/tools.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/execution/durable/service.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/execution/durable/store.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/execution/executor.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/improvement_promotion/eligibility.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/improvement_promotion/service.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/ingestion/authentication.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/ingestion/models.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/ingestion/store.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/investigation/runtime/persistence/store.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/investigation/runtime/service.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/planning/planner.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/response/promotion/service.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/review/persistence/confirmations.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/review/persistence/database.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/review/persistence/incident_detail.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/review/persistence/security_ai_monitor.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/review/persistence/service.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/review/persistence/store.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/security_ai/evaluation/experiments.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/security_ai/network/classifier.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/security_ai/packaging/files.py` | 이전 단계 필수 의존성 | 포함 |
| `src/soc_agent/tools/base.py` | Gate B 직접 구현 | 포함 |
| `src/soc_agent/tools/registry.py` | Gate B 직접 구현 | 포함 |
| `tests/conftest.py` | 테스트 | 포함 |
| `tests/evaluation_support.py` | 테스트 | 포함 |
| `tests/integration/api/test_dashboard.py` | 테스트 | 포함 |
| `tests/integration/api/test_incident_detail.py` | 테스트 | 포함 |
| `tests/integration/api/test_security_ai_monitor.py` | 테스트 | 포함 |
| `tests/integration/demo/conftest.py` | 테스트 | 포함 |
| `tests/integration/improvement_promotion/test_activation.py` | 테스트 | 포함 |
| `tests/packaging_support.py` | 테스트 | 포함 |
| `tests/scenarios/test_security_ai_packaging.py` | 테스트 | 포함 |
| `tests/unit/adaptive/test_coordinator.py` | 테스트 | 포함 |
| `tests/unit/persistence/conftest.py` | 테스트 | 포함 |
| `tests/unit/persistence/test_storage.py` | 테스트 | 포함 |
| `tests/unit/security_ai/features/test_features.py` | 테스트 | 포함 |
| `tests/unit/security_ai/packaging/conftest.py` | 테스트 | 포함 |
| `tests/unit/security_ai/packaging/test_packages.py` | 테스트 | 포함 |
| `tests/unit/security_ai/test_investigator.py` | 테스트 | 포함 |
| `tests/fusion_support.py` | 테스트 | 포함 |
| `docs/security-ai-final-integration-20261012/report.md` | 문서 | 포함 |
| `docs/security-ai-final-integration-20261012/validation-results.json` | 문서 | 포함 |
| `docs/security-ai-final-integration-20261012/architecture.md` | 문서 | 포함 |
| `docs/security-ai-final-integration-20261012/security-boundary.md` | 문서 | 포함 |
| `docs/security-ai-final-integration-20261012/remaining-risks.md` | 문서 | 포함 |
| `docs/security-ai-final-integration-20261012/release-readiness.md` | 문서 | 포함 |
| `docs/gate-b-validation-20261012/integration-contract-v2.md` | 문서 | 포함 |
| `docs/gate-b-validation-20261012/integration-change-impact.md` | 문서 | 포함 |
| `docs/gate-b-validation-20261012/integration-test-plan.md` | 문서 | 포함 |

공유 Runtime/READ API의 이전 self-improvement projection/eligibility 변경은 현재
ApplicationService가 사용하는 read snapshot API의 필수 의존성으로 포함한다.
새로운 자율 개선 기능을 구현하거나 활성화하지 않는다.
커밋/태그 생성은 staged 의존성·무결성 검사 후 수행하며 push/운영 배포는 하지 않는다.

### 최종 staged 검사

선택 파일: **145개 (소스 74 / 테스트 61 / 문서 10)**.
Stage allowlist와 실제 index 목록 일치, `git diff --cached --check` PASS,
내부 import 누락 0, 모델/DB/로그/가상환경/임시 manifest 포함 0,
자격 증명 패턴 검출 0, staged helper SHA 일치를 확인했다.
Stage 내용만 `/tmp`에 복원한 격리본에서 **3085 tests collected, 0 collection errors**
(3.18초)를 확인했다. 이는 실행 결과가 아니며 기존 3104 passed/25 skipped의
working-tree 전체 회귀 증거와 구분한다. 제외된 독립 연구/live 테스트는 기준선에
포함하지 않았으므로 테스트 수가 다르다. 전체 회귀 재실행 없음.
Ruff / Format / Diff는 PASS다.

기준선 태그는 `gate-b-integration-rc1`을 사용한다. 기존 태그 덮어쓰기와 push는
수행하지 않는다. 정확한 커밋 SHA는 해당 태그의 대상 Git commit에서 확인한다.
운영 배포/최신 전체 Windows 회귀/별도 Linux 호스트 검증은 여전히 미완료다.
