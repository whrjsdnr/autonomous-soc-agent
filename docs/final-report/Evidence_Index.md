# Evidence Index — 근거의 범위와 재검증

조사 기준일 2026-11-02. SOC 기준 HEAD `253dc0c21bf095ca091ad4a49e31aa3ec145780e`, Tree `ed5ce6016b35404983e9eb5bcd4923c593668e6d`. ML 기준 `e1a01260f0463a38d4d778859bc2a86f8e9cfbde`. ML에는 기존 사용자 변경이 있으므로 committed history와 현재 작업 파일을 동일시하지 않는다. 모델 분석은 파일·저장 결과의 읽기로 수행했다. 비권한 회귀에는 기존 OFFLINE/FIXTURE Worker의 실제 로컬 모델 실행이 포함될 수 있으나 Native Model Action·Capture·외부 API는 수행하지 않았다.

`Evidence_Manifest.json`은 실제 읽은 코드·모델·학습 문서·실험 파일의 SHA와 크기 목록이다. SHA는 변조 탐지용이며 서명이나 실험 성공의 증명이 아니다. Git 외부 Artifact 경로는 이 개발 머신에서만 유효하다. 외부 배포 시 민감 정보 검토 후 필요한 사본을 별도 제공해야 한다. 원본 패킷·로그·API Key는 보고서에 복제하지 않았다.

## E01

[AGENTS.md](../../AGENTS.md), [pyproject.toml](../../releases/research-mvp/pyproject.toml), [README](../../releases/research-mvp/README.md). Human-Governed Autonomous SOC, Single Orchestrator+Tools, deterministic policy, Python/Pydantic/uv, CLI 선언 근거. §32의 초기 Foundation 계획을 현재 완료 범위로 해석하지 않는다. §33은 자기 개선 로드맵이며 현재 승인 CLI 구현 그 자체가 아니다.

## E02

[Continuous 서비스](../../releases/research-mvp/src/soc_agent/continuous/service.py), [Native Windows](../../releases/research-mvp/src/soc_agent/continuous/native_windows.py), [Source](../../releases/research-mvp/src/soc_agent/continuous/source.py), [Store](../../releases/research-mvp/src/soc_agent/continuous/store.py), [모델](../../releases/research-mvp/src/soc_agent/continuous/models.py). 수집·저장·분석·Control·종료 경로의 현재 소스다. 함수 이름·상태를 확인하는 1차 근거이며 실행 성공은 별도 시험 근거가 필요하다.

## E03

[Packet Producer](../../releases/research-mvp/src/soc_agent/security_ai/collectors/packet_producer.py), [Feature 순서/Zeek 차이](../../releases/research-mvp/src/soc_agent/security_ai/collectors/parity.py), [Native Window Admission](../../releases/research-mvp/src/soc_agent/continuous/native_windows.py). Network14 계산·정렬·첫 관측 방향·완결성 제한의 근거. `parity.py`의 BLOCKED는 Zeek conn summary의 자동 대체 차단이며 모든 Native Network14를 영구 차단한다는 뜻이 아니다.

## E04

[Network14 연구 평가](../../../ML/docs/network-research-training-evaluation.md), [학습 소스](../../../ML/src/ml/network_research/training.py), [고정 학습 증거](../../../ML/docs/network-research-training-evidence.json), [Artifact Manifest](../../../ML/docs/network-research-artifact-manifest.json), SOC [research/environment.py](../../releases/research-mvp/src/soc_agent/security_ai/research/environment.py)·[research/worker.py](../../releases/research-mvp/src/soc_agent/security_ai/research/worker.py). CTU/IoT23 Network14 RF/LR와 신뢰 경계. ML 문서 당시의 “SOC 미연결”은 역사 기록이며 현재 연결 여부는 SOC 현재 코드로 판정한다.

## E05

[ML 독립 Network 패키지](../../../ML/packages/network-security-ai/README.md), [DNN 구현](../../../ML/packages/network-security-ai/src/network_security_ai/predictors.py), [재현 순서](../../../ML/docs/network_security_ai/reproducibility.md), [DNN notebook](../../../ML/notebooks/dnn_top40_v4.ipynb), [V3 비교](../../../ML/results/model_comparison_v3/top40_model_comparison.csv), [V4 비교](../../../ML/results/v4_model_comparison/overall_metrics.csv), [DNN full validation](../../../ML/results/dnn_top40_v4/dnn_fp32_full_valid_metrics.csv). Top40 계열이며 E04 Network14와 호환 계약이 아니다. [Notebook 발췌](Notebook_Extracts.md)는 실행하지 않은 코드 발췌다.

## E06

[DNS 패키지](../../../ML/packages/dns-security-ai/README.md), [DNS Manifest](../../../ML/packages/dns-security-ai/src/dns_security_ai/artifact_manifest.json), [TFLite 검사 결과](../../../ML/reports/security_ai/dns_tflite_review.json), [SOC 학습 추출 계약](../../releases/research-mvp/src/soc_agent/security_ai/dns9_training_contract.json), [Raw Transaction](../../releases/research-mvp/src/soc_agent/security_ai/dns_transactions.py), [DNS Source](../../releases/research-mvp/src/soc_agent/continuous/dns_source.py). Artifact 구조와 Raw 추출 계약 부재를 구분한다. ML의 untracked 공급 bundle을 새로운 정식 학습 소스로 승격하지 않았다.

## E07

[Authentication 집계](../../releases/research-mvp/src/soc_agent/security_ai/authentication/aggregation.py), [학습](../../releases/research-mvp/src/soc_agent/security_ai/authentication/training.py), [추론](../../releases/research-mvp/src/soc_agent/security_ai/authentication/anomaly.py), [공통 설정](../../releases/research-mvp/src/soc_agent/security_ai/anomaly_common.py), [Native 읽기 경로](../../releases/research-mvp/src/soc_agent/security_ai/operational/native_authentication.py). 300초 계정 Window·5개 Feature·정상 baseline fit. 실제 Host 이벤트 IF 성공에 대한 새로운 실환경 증거는 이번 조사에서 확보하지 않았다.

## E08

[오케스트레이션 통합 보고](../../releases/research-mvp/docs/linux-soc-v1/continuous-ai-orchestration-integration.md), [Continuous 조사](../../releases/research-mvp/src/soc_agent/continuous/investigation.py), [Task Store](../../releases/research-mvp/src/soc_agent/continuous/investigation_store.py), [ApplicationService](../../releases/research-mvp/src/soc_agent/api/service.py), [SOCRuntime](../../releases/research-mvp/src/soc_agent/investigation/runtime/service.py), [Planner](../../releases/research-mvp/src/soc_agent/planning/planner.py), [Adaptive](../../releases/research-mvp/src/soc_agent/adaptive/planner.py), [Investigation](../../releases/research-mvp/src/soc_agent/investigation/orchestrator.py). 실제 연결 경로와 core 재사용의 근거.

## E09

[Selector](../../releases/research-mvp/src/soc_agent/security_ai/selector.py), [Fusion](../../releases/research-mvp/src/soc_agent/security_ai/fusion/engine.py), [Threat Assessment](../../releases/research-mvp/src/soc_agent/assessment), [LLM Adapter](../../releases/research-mvp/src/soc_agent/llm/openai_compatible.py). Selector/Fusion 코드 존재와 Continuous의 추가 모델 자동 실행 여부는 별개다. LLM 외부 호출 증거는 E10으로 한정한다.

## E10

[최종 API/운영 보고](../../releases/research-mvp/docs/linux-soc-v1/final-operations-and-llm-orchestration-report.md), 원본 공통 Git 디렉터리 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/final-llm-hour-preflight-20261030T100117Z/approved-execution-records/`의 `api-final-summary.json`, `native-final-summary.json`. 실제 Plan 성공/Assessment Timeout, 18분 Native와 API 시험을 서로 독립된 A/B로 보존한다. 보고서의 비용은 당시 가격 계약에 따른 기록이며 현재 가격표가 아니다.

추가 최신 API 근거: 공통 Git `reliability-live-validation-review-20261102T001146Z/llm-assessment/future-attempt/{result,api-failure-0}.json` 및 `gui-audit-verification.json`. 이는 11월2일의 별도1회 Assessment Timeout이며 이전10월30일 API2회와 분리한다.

## E11

[Native 오케스트레이션 보고](../../releases/research-mvp/docs/linux-soc-v1/native-ai-orchestration-e2e-report.md), [Continuous 개발 보고](../../releases/research-mvp/docs/linux-soc-v1/continuous-runtime-integration-report.md), [Producer Timeout](../../releases/research-mvp/docs/linux-soc-v1/tcx-producer-timeout-cleanup-report.md), [릴리스 보고](../../releases/research-mvp/docs/linux-soc-v1/soc-agent-release-candidate-report.md). Native54·Prediction8·Incident2 등 과거 특정 시험 결과와 BTF/verifier 개발 이력. 서로 다른 시험의 카운터를 합하지 않는다.

## E12

[최신 전체 통합 실패](../../releases/research-mvp/docs/linux-soc-v1/native20-full-integration-retest-result.md), [DNS 상태 격리](../../releases/research-mvp/docs/linux-soc-v1/native20-dns-status-isolation.md), 공통 Git `native20-full-integration-review-20261102T073720Z/full-integration-failed-result.json` 및 `native/dns-session/transport-failure.json`, `verified-closed.json`, `cleanup.json`, `native/execution/`. 실행 HEAD aead2e9, 사후 terminal-state 수정 ac33af8. `253dc0c`는 결과 문서 Commit이며 실패 실행 코드 Commit과 다르다.

## E13

공통 Git `dns-heartbeat-native-diagnostic-review-20261102T054245Z/`: 진단 시험 전체370.838988초·봉인 수집361.041373925초, Packet54/DNS3, Window3, Heartbeat1.107664714초. 원본115개 증거 pin과 session queue를 보존한다. 이 6분 성공을 20분 또는 1시간 성공으로 확장하지 않는다.

## E14

[Native20 저장 경합 실패](../../releases/research-mvp/docs/linux-soc-v1/native20-storage-recovery-result.md), [비권한 안정화](../../releases/research-mvp/docs/linux-soc-v1/final-runtime-reliability-integration-report.md), 공통 Git `native20-dns-storage-isolation-20261102T071948Z/`. db5e8dc의1449 PASS/1 SKIP 및 ac33af8의집중42 PASS는 서로 검증 범위가 다르다. 이번 신규 최종 회귀는 Validation_Results.md에서 별도로 기록한다.

## E15

[CLI](../../releases/research-mvp/src/soc_agent/agent_cli.py), [Backend](../../releases/research-mvp/src/soc_agent/agent_runtime.py), [단일 명령 운영](../../releases/research-mvp/docs/linux-soc-v1/one-command-runtime.md), [CLI 검증](../../releases/research-mvp/docs/linux-soc-v1/one-command-cli-verification.md). 서브커맨드 존재와 Native 정책 입장 가능 여부를 분리한다. `start --preview`는 실행·영수증 소비가 아니다.

## E16

[Helper](../../releases/research-mvp/src/soc_agent/security_ai/operational/network_capture/stream_helper.py), [Transport](../../releases/research-mvp/src/soc_agent/security_ai/operational/network_capture/helper_transport.py), [Stream schema](../../releases/research-mvp/src/soc_agent/security_ai/operational/network_capture/stream_transport.py), [Heartbeat 회귀](../../releases/research-mvp/tests/unit/continuous/test_dns_heartbeat_diagnostics.py), [Helper 회귀](../../releases/research-mvp/tests/unit/streaming_network/test_helper.py), [Storage 격리 회귀](../../releases/research-mvp/tests/unit/continuous/test_storage_control_isolation.py). 이번 stage timing은 peer diagnostic일 뿐 admission/cleanup authority가 아니다.

## E17

기존 Ledger 공통 Git `native-stabilization-batch1/execution-v1/execution-ledger.jsonl`:81행, SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`. 원본 UNKNOWN/FAILED/UNVERIFIED 및 과거 false를 그대로 보존했다. 신규 시험 영수증을 발급·소비하지 않았다.

## E18

[실제 보존 GUI](assets/native-failure-dashboard.png). 원본 E12 `gui-live-witness/finished-dashboard.png`를 byte-identical 복사했다. 종료된 최신 실패 Session 화면이며 현재 Live 화면이 아니다. 과거 DNS STOPPING 표시 결함도 당시 스크린샷에 남아 있다. 새 Fixture/생성 이미지를 실환경 Screenshot으로 제시하지 않는다.

## E20 — 역사 Blob과 실제 경과 Replay

[7de4794의 당시 Native 성공 보고](assets/native-orchestration-report-7de4794.md)는 Git blob 그대로 추출한 사본이다. 새로 작성한 성공 증거가 아니다. [Replay20 검증 요약](assets/replay20-summary.json)은 원본 공통 Git `runtime-storage-isolation-20261102T013653Z/soak20-recovery/verified-result.json`의 JSON 값 사본이며 새 실행이 아니다. 원본 `replay-soak-final.json`·`heartbeat-observer-result.json`과 함께 wall/event-time·관측 범위를 해석한다.

## E19 — 개념 정의의 공식 자료

[eBPF/BTF/verifier 공식 문서](https://docs.kernel.org/bpf/index.html), [IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html), [Average Precision](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.average_precision_score.html), [CrossEntropyLoss](https://docs.pytorch.org/docs/stable/generated/torch.nn.CrossEntropyLoss.html). 일반 원리만 보조하며 프로젝트 성과의 근거로 대체하지 않는다.

## 근거 부족 목록

| 질문 | 현재 판정 | 필요한 증거 |
|---|---|---|
| Helper 4.181초 공백의 정확한 작업 | UNKNOWN | 동일 clock 단계별 Helper timing과 cgroup/scheduler 동시 관측 |
| DNS9 학습 추출 동등성 | EVIDENCE_REQUIRED | 원본 extractor·canonicalization·golden raw pairs·scaler fit/export |
| Host Auth IF 실제 운영 성공 | EVIDENCE_REQUIRED | 승인된 읽기 source/cursor·완결 Window·실제 model receipt |
| 20분/1시간 Native 안정성 | PARTIALLY_VERIFIED | 새 Binding의 승인 시험·실측 수집 시간·모든 종료 증거 |
| 실제 LLM Assessment 완료 | UNKNOWN/Timeout | 새 API 승인·단일 요청/비용 상한·response/usage/평가 |
| 전역 Kernel Cleanup | UNKNOWN/UNVERIFIED | 소유 밖 자원까지 증명할 별도 Scope; 현 목표로 확대하지 않음 |
