# Gate C — 기존 SOC Integration 검증

## 판정: GATE_C_PASS

현재 Gate C의 SOC 통합 필수 계약을 **오프라인 합성 입력·공식 Native 모델·기존
scripted LLM·격리된 DB·READ tool 및 테스트 인증 Provider** 범위에서 확인했다.
이는 실시간 Collector, 운영 인증, 실제 대응 권한 발급 또는 운영 배포 완료가 아니다.
Gate D는 별도 사용자 지시 후 진행할 수 있으며 이번에는 시작하지 않았다.

## 기준선과 보호

- Commit: `787dff886c203cd14e351021f7d72b08fae17147`.
- Annotated tag: `gate-b-integration-rc1` (변경 없음).
- 기존 WSL 전체: 3104 passed / 25 skipped; Windows 집중: 249 + 복구 후 16 passed.
- Gate B 기존 공식 모델/Runtime/원자적 publication/프로세스 종료·복원 및 보안 증거 재사용.
- 현재 branch main 유지; commit/tag/push 및 운영 DB Migration 없음.
- 기존 tracked 수정 3개 및 untracked 사용자 항목을 보존했다.
- 기존 모델, Golden Fixture, Selection Digest, Fusion v1, Decision ID/Payload,
  Policy/Approval, POSIX/NTFS 및 SQLite fail-closed 정책에 변경 없음.

## 실제 인벤토리

| 구성 요소 | 상태 | 실제 구현 / 이번 검증 |
|---|---|---|
| External Network/DNS Adapter 및 공식 Envelope | IMPLEMENTED_AND_VERIFIED | external/adapters.py, validation.py; 공식 native 결과와 Adapter 오류 회귀 |
| Network Quality / Edge / DNS Predictor | IMPLEMENTED_AND_VERIFIED | external/inference.py, service.py, inference_worker.py; CLI native 실행 |
| Provenance / Observation Identity | IMPLEMENTED_AND_VERIFIED | external/models.py, metadata.py; pinned 파일 SHA와 execution environment digest 검증 |
| Fusion v1 | IMPLEMENTED_AND_VERIFIED | 기존 security_ai/fusion 계약·회귀 증거 재사용; 변경 없음 |
| External Context v2 | IMPLEMENTED_AND_VERIFIED | external/assembly.py; 3개 모델 결과, 관측 2개, group 2개 |
| SOCRuntime / Investigation | IMPLEMENTED_AND_VERIFIED | investigation/runtime/service.py; external/runtime_integration.py, 실제 source-report READ |
| ThreatAssessment / IncidentDecision | IMPLEMENTED_AND_VERIFIED | 기존 assessor/decision engine; 실제 CLI checkpoint 및 Decision Receipt |
| Policy / Approval / Execution Guard | IMPLEMENTED_AND_VERIFIED | runtime_guard.py, 기존 executor/approval; 우회·Incident redirect·모델 지시 거부 회귀 |
| SQLite / Audit / Checkpoint / Resume | IMPLEMENTED_AND_VERIFIED | runtime_store.py, storage.py; 별도 프로세스 재시작과 API resume |
| Windows Desktop CLI | IMPLEMENTED_AND_VERIFIED | external_runtime.py DESKTOP; Windows 11 Native 이번 실행 |
| Linux SERVER CLI / ASGI | IMPLEMENTED_AND_VERIFIED | external_runtime.py SERVER, api/http.py, api/service.py; WSL 실제 실행 |
| 운영 Linux Headless host / 설치된 HTTP 서비스 | IMPLEMENTED_NOT_VERIFIED | 이번 WSL ASGI 실행으로 운영 배포를 대체하지 않음 |
| Desktop GUI / 실시간 Collector | NOT_APPLICABLE | 이번 SOC Integration 범위에 포함하지 않음 |
| Windows Server | NOT_APPLICABLE | 지원하지 않음; Windows 테스트는 DESKTOP만 수행 |

## 실제 E2E 실행과 모델

신규 `test_gate_c_entrypoints.py`는 진입점을 재구현하지 않는다.
공식 entrypoint `python -m soc_agent.external_runtime`을 별도 Python 프로세스로
실행하며 DESKTOP/SERVER 각각 한 번 시작하고 같은 입력으로 다시 실행한다.
모델 학습/복사/승격 없이 기존 공식 모델 및 별도 Native Python 환경을 재사용한다.

```
Synthetic Network event + 별도 Top40 / DNS 9-feature record
 → LocalJSONLSource / EventIngestor
 → FeatureRow / SourceFeatureObservation validation
 → official Quality / Edge / DNS native predictors
 → official EvidenceEnvelope → Typed Evidence Adapter / provenance validation
 → External Context v2 (Network 한 관측에 Quality/Edge, DNS 별도 관측)
 → shared compose_application / SOCRuntime
 → Investigation source-report READ
 → ThreatAssessor (OfflineDesktopClient scripted structured output)
 → IncidentDecisionEngine
 → Decision Receipt / security audit / atomic checkpoint
 → 별도 프로세스 재시작 → 동일 Context digest / checkpoint 복원
 → authenticated SOCApplication ASGI workflow read / resume
```

실제 모델 ID:
- `network_cse2018_lightgbm_v4b2`: LightGBM Top40.
- `network_cse2018_dnn_fp32`: DNN FP32 Top40.
- `dns_cicbell_dnn_int8`: LiteRT INT8 + 기존 Scaler, 9 features.

외부 패키지는 Gate B에서 고정한 0.1.0 계약과 release artifact identity를 재사용한다.
이번 테스트는 Context 각 모델의 모든 artifact file을 실제 root에서 SHA-256으로
다시 검증했다. 공식 모델 로딩/Envelope/Provenance 경로를 실행했고 모든 결과가
VALIDATED_FOR_ADVISORY이며 execution environment digest가 존재한다.
원격 Release 게시 상태를 이번에 새로 조회한 것은 아니다.

입력은 의미가 명시된 합성 값이다. SourceFeatureObservation의 synthetic provenance는
운영 extractor 검증을 의미하지 않는다. Network event에 별도 synthetic DNS feature
record를 명시적으로 연결한 시나리오이며 실제 DNS query collector를 실행하지 않았다.
두 observation/group을 보존했으며 Network와 DNS의 인과 관계를 확정하지 않는다.
Native 모델 추론과 scripted LLM의 위협 판단을 혼동하지 않는다.

## 필수 계약 및 보안 Oracle

1. 원본 Source Evidence와 model advisory 구분: Context v2 별도 저장/LLM projection,
   runtime_integration이 외부 경로의 model-derived observation/hypothesis 승격을 거부.
2. Model ID / file SHA / feature identity / source event·observation 및 시간 보존:
   신규 CLI 검증 + Adapter 검증 72개.
3. 모델 점수 평균/합산 없음: 기존 assembly의 개별 결과·semantics 보존, source 변경 없음.
4. Quality/Edge 중복 사건 없음: 결과 3개지만 관측 2개/group 2개.
5. DNS/Network 구분: 독립 observation type 및 group; 별도 causal correlation 주장 없음.
6. Fusion v1은 변경하지 않았으며 External Context를 관측 사실로 위장하지 않음.
7. Decision ID/Payload: Gate B에서 검증한 기존 engine 경로 및 contract 그대로 사용.
8. 실행 권한: 기본 CLI registry는 READ source-report tool만 사용; execution_records 0.
   실제 WRITE spy가 등록된 기존 executor/approval 우회 회귀에서도 호출 0을 확인.
9. Incident 혼입: 실제 dispatcher에서 다른 Incident payload redirect 거부 회귀.
10. 재시작: 두 CLI 프로세스 간 Context digest 동일, 실제 checkpoint/receipt 복원;
    ASGI resume 이후 중복 old-revision 요청 409.

## 진입점별 이번 결과

| 진입점 | 검증 결과 |
|---|---|
| WSL Desktop CLI | 실제 3개 predictor, 시작/재시작/사람 대기, 파일 SHA 확인 PASS |
| WSL SERVER CLI | 동일 모델/서비스, 시작/재시작/Receipt/Audit 보존 PASS |
| Windows 11 Desktop CLI | 기존 soc-windows + 별도 Native venv 재사용; 동일 신규 테스트 PASS |
| 실제 SOCApplication ASGI | lifespan startup/shutdown, 인증 READ 200, 미인증 401, 권한 거부 403, 잘못된 approval 요청 422, resume 200, 중복 revision 409 PASS |
| Runtime tamper / Incident binding / model instruction | 기존 실제 Guard를 사용하는 관련 회귀 PASS |

ASGI 테스트는 실제 production ASGI application을 통해 실행한다. 테스트용 opaque
인증 Provider와 AccessPolicy를 주입했고, Guard/Runtime/모델 로직은 mock으로
대체하지 않았다. 실제 TCP listener 또는 운영 인증 Provider 배포를 주장하지 않는다.
API가 Top40/DNS inference 전용 HTTP 수집 endpoint를 제공한다고 주장하지 않는다.
검증된 모델 Context를 공유 backend에서 사용하는 기존 workflow API를 검증했다.

## 테스트와 변경

- WSL 신규 진입점: **2 passed** (30.29초), 실제 CLI 4회/Native 3모델 × 2 profile.
- WSL 관련 회귀: **100 passed, 56 deselected** (42.40초).
  Adapter 72개 및 직접 executor/WRITE 거부, model instruction, resume tamper,
  Incident redirect, 같은 Runtime CAS 경쟁 28개.
- Windows Native 신규 진입점: **1 passed** (43.74초), DESKTOP만 실행.
- 전체 WSL/Windows 회귀는 재실행하지 않았다. 기존 증거를 재사용한다.
- 단순 test collection을 이번 실행 성공으로 계산하지 않았다.

초기 신규 테스트 2개 실패는 테스트가 composition 전 RuntimeGovernanceStore.boundary를
참조한 harness 오류였다. 실제 CLI 시작/추론은 성공했다. guard는 composition 시
구성되는 실제 계약에 맞춰 typed persisted binding을 검증하도록 수정했다.
확인된 모델 ID 철자도 metadata.py에 맞췄다. 최종 실패 0, production 결함 0.
검증을 완화하거나 skip/xfail을 추가하지 않았다. Windows SERVER는 지원 대상이 아니므로
Windows parametrization은 DESKTOP만 포함하며, WSL에서는 두 profile 모두 실행한다.

신규 파일:
- `tests/integration/external_runtime/test_gate_c_entrypoints.py`
- `docs/gate-c-soc-integration/report.md`

프로덕션 소스 변경 없음. Windows 원본 C:/soc-agent-windows-test 변경 없음.
최신 격리본 C:/soc-agent-final-native-20261013에 신규 테스트만 SHA 확인 후 추가했다.
기존 가상환경, OS 보안 설정, 모델 artifact 및 사용자 파일을 변경하지 않았다.

## 미검증 / Gate D 이관

- 별도 Linux Desktop/Headless 운영 호스트와 실제 서비스 설치·TCP listener·운영 인증.
- 최신 전체 Windows regression (이번 신규 진입점과 기존 집중 증거로 범위를 명시).
- 신규 external 모델의 두 OS 수치/최종 Decision equivalence 전용 comparator 실행.
- 운영 feature extraction/real-time data/production detection quality; 특히 DNS scaler
  pairing efficacy의 기존 UNVERIFIED 제한은 이번 계약 테스트로 해소되지 않는다.
- 사람 대기는 기존 investigation loop guard에 따른 review boundary다. 유효 승인
  발급 완료 또는 response execution을 뜻하지 않는다.
- arbitrary hostile Python/raw SQL/OS 권한 sandbox는 제공하지 않는다.
- 기존 stale writer lock 및 interrupted READ의 명시적 operator reconciliation 유지.

위 항목은 운영/실시간/추가 플랫폼 검증 범위로 분리한다. 이번에 Gate D 기능은
구현하지 않았으며, Gate D 착수는 사용자 지시가 필요하다.

## 재현 명령

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q tests/integration/external_runtime/test_gate_c_entrypoints.py
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q tests/unit/security_ai/external/test_adapter.py tests/integration/external_runtime/test_runtime.py -k 'test_adapter or external_read_tool_cannot_redirect or same_runtime_cas_collision or real_resume_rejects or no_model_facts or direct_executor'
```

```powershell
conda activate soc-windows
Set-Location C:\soc-agent-final-native-20261013
$env:RUN_LIVE_LLM_TESTS = '0'
$env:PYTHONPATH = "$PWD\src"
$env:SOC_EXTERNAL_ARTIFACT_ROOT = Join-Path $env:LOCALAPPDATA 'AutonomousSOCFinalArtifacts20261013'
$env:SOC_EXTERNAL_INFERENCE_PYTHON = 'C:\soc-native-inference-final-20261013\Scripts\python.exe'
python -m pytest -q --tb=short -rs -rfE tests/integration/external_runtime/test_gate_c_entrypoints.py
```

ログ（今回のみ、기존 증거と別）:
- `/tmp/soc-gate-c-entrypoints.log`
- `/tmp/soc-gate-c-related.log`
- 最新 Windows 격리본 `windows-gate-c-entrypoints.log` (UTF-16)

## SHA-256

- 신규 테스트: `66872e01ad0bd1b619cc7e94bfe056c450d07c46a17955f64d9fe9621e3b2a42`
- `soc-gate-c-entrypoints.log`: `0ba5191fd94e3b2e9653d60365ad221ade7376d0f6e30ebdcb5cc27e27e0c942`
- `soc-gate-c-related.log`: `63406e5aeb21efe36f4287bc82b43797e1a8c036dd8c9af137dc707db98d5916`
- `windows-gate-c-entrypoints.log`: `d375be2628d19ba722ec4731401c8fa9d7beb5fe4dde43a15425a55075176623`

최종 정적 검증: Ruff check PASS, Ruff format --check PASS (674 files), git diff --check PASS.
