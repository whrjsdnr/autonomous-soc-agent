# Producer Recovery & Operational AI Integration Audit

검증 환경은 WSL2 Ubuntu다. SOC 기준 HEAD는
`a78a080d863ca383cd1a24931a9bdd3104782330`, ML HEAD는
`1800bd013edefd448671c97a8b7114409f639481`이다.

**최종 기능 판정: BLOCKED.** Network Quality / Network Edge / DNS Security의
원본 학습 Feature Producer를 복원할 증거가 부족하다. 모델별 복원 판정은 모두
**INSUFFICIENT_EVIDENCE**다. 이는 전 세계에서 영구히 복원할 수 없다는
NOT_RECOVERABLE 판정이 아니다. 로컬 ML 경로와 접근 가능한 Git 이력에서 확인한 결과다.

Collector·Queue·Source Store·진단 Flow·Adapter·GUI를 새로 만들지 않았다.
추론 환경 Import/Artifact 확인, 실제 저장 Capture 재검증, 차단 회귀를 수행했다.
검증된 운영 Producer가 0개이므로 새 운영 추론 Worker / Finding 연결은 구현·활성화하지
않았다. 기존 패키지의 합성 시연 경로와 운영 데이터 차단을 구분한다.

기계 판독 근거는 [audit evidence](producer-recovery-operational-ai-evidence.json)다.
이 파일은 조사 기록이며 Producer Attestation, Human Approval, 추론 권한이 아니다.

## 1. Baseline 및 소유권

Git status/HEAD/log/diff/cached diff와 AGENTS.md를 확인했다. 기존 Stage는 비어 있었다.
기존 추적·미추적 파일 1,020개의 SHA를 작업 시작에 기록했다. README.md,
pyproject.toml, docs/soc-command-center.md 및 Runtime/Scenario/Tool 사용자 변경과
미커밋 Reliability Replay는 이 작업에 포함하지 않는다. ML의 제공 DNS 패키지 미추적
디렉터리도 보존한다. 모델/Scaler/학습 데이터는 읽기 전용으로 조사했다.

기존 생산 코드의 보안 계약이 올바르게 닫혀 있어 변경하지 않았다. 추가 범위는
이 보고서, 비민감 조사 JSON, Producer 권한 승격 차단 통합 테스트다.

## 2. Training Producer 탐색 범위

`~/kdt-linux/ML`의 가상환경·Git 내부·캐시를 제외한 파일명과 Python/Notebook 소스를
조사하고, 로컬의 도달 가능한 모든 Git 이력 경로도 확인했다. Notebook은 JSON의
code cell을 읽었으며 실행하지 않았다. 작은 배포 wheel/tar의 멤버 목록도 확인했다.
원본 Producer 실행, 데이터 다운로드, 의존성 설치, 재학습은 수행하지 않았다.

| 발견 자료 | 확인 결과 | 원본 Producer 증거 |
|---|---|---|
| Python 55개 / Notebook 11개 | 패키지 추론, CSV/Parquet 전처리·학습·평가 코드 | PCAP/FQDN 추출 Revision/Config 미발견 |
| PCAP / PCAPNG / CAP | 0개 | Raw↔Feature 검증 불가 |
| Network TrafficForML CSV | 10개, 합계 6,886,649,507 bytes | 이미 계산된 Feature, 패킷 원본 아님 |
| 전체 CSV/Parquet 등 조사 파일 | 418개, 26,079,187,461 bytes | 복수 가공본·결과·배포 파일 포함; 독립 Raw corpus 크기 아님 |
| Network V4-B2 학습 Parquet | 1,946,494행 / 43컬럼, Top40 40개 순서 일치 | 기존 Feature 기반 학습 입력 |
| V4 validation Parquet | 2,390,002행 / 41컬럼, Top40 순서 일치 | 검증용 Feature, Producer Golden Pair 아님 |
| DNS Notebook 참조 CSV | 현재 경로에 없음 | DNS Raw/학습 행 대응 미확보 |
| 배포 wheel/tar | inference package 멤버만 확인 | 별도 Producer/Golden Pair 미발견 |

Parquet은 기존 ML .venv의 pyarrow로 Footer 메타데이터만 읽었다. SOC 환경에 새 패키지를
설치하거나 행 전체를 로드하지 않았다. 위 CSV는 Header만 확인했으며 전체 CSV SHA를
계산한 것으로 보고하지 않는다. 조사 전체 용량은 저장된 여러 파생본을 합한 값이다.

Network CSV 9개는 80컬럼, 1개는 84컬럼이다. 84컬럼 파일에는 Flow ID/Source IP가 있지만
나머지 9개에는 없다. 어떤 경우에도 PCAP/Producer Revision/설정/행 대응이 없어 Golden
Pair가 되지 않는다. 실제 IP·Flow ID·Payload 행은 출력·커밋하지 않았다.

## 3. Network Top40 복원 판정

Quality와 Edge는 같은 Top40 순서를 사용하지만 Artifact와 모델별 전처리는 독립적이다.

| 단계 | 근거 | 판정 |
|---|---|---|
| Dataset 계열 | CSE-CIC-IDS2018 명칭과 TrafficForML_CICFlowMeter 파일 | REPORTED_ONLY; 파일명은 Producer 버전 증거가 아님 |
| 원본 Producer / 버전 | 정확한 CICFlowMeter source commit/binary 없음 | MISSING |
| Flow 설정 | 양방향 매칭, forward 기준, active/idle timeout, 분할·재전송·종료 처리 | MISSING |
| Raw 계산 | IAT 분산/평균, length/header 단위, flags/window, rate의 0-duration 처리 | MISSING |
| Feature Selection | preprocessing.ipynb cell 67/68: importance의 head(40) | 확인; raw 추출과 별개 |
| 학습 입력 | model_sample_v4.ipynb cells 32/33/56: rank 순서, Parquet→float32 | 확인 |
| Quality 추론 전처리 | Top40Contract.matrix: None/nonfinite→NaN, float32; LightGBM native missing | 검토 코드 확인; Scaler 없음 |
| Edge 추론 전처리 | dnn_top40_v4.ipynb cells 1/2/43, preprocess_dnn_batch | float32→nonfinite mean imputation→저장 Scaler→float32 |
| Raw PCAP↔기대 Feature | 원본 PCAP·원 Producer 실행 결과·설정 없음 | MISSING |

이름/순서의 Digest는
`ac252fd93d3c5504803695fc609e8209701c74c812b163508b001490cb31b649`다.
전체 40개 이름·순서와 Feature별 원본 계산 증거 상태는 JSON에 기록했다.
**학습 원본 계산식 Parity가 검증된 Feature는 0/40**이다. 일반적인 TCP/통계 지식은
해당 학습 Producer와의 동일성 증거로 사용하지 않는다.

기존 Diagnostic Flow는 FIRST_OBSERVED_NOT_TRAINING_PRODUCER이고 항상 incomplete다.
현재 idle=30초/active=120초는 진단 설정이며 학습 설정이 아니다. frame_length 평균,
packet count, bytes, flags를 유사한 Top40 이름에 맞춰 임의로 매핑하지 않았다.

**Network Quality: INSUFFICIENT_EVIDENCE.**
**Network Edge: INSUFFICIENT_EVIDENCE.**
원본 Feature 이후의 모델 입력 전처리는 검토 코드로 재현 가능한 부분이 있지만,
이를 원본 Producer의 PARTIALLY_RECOVERABLE 증명으로 자동 승격하지 않는다.

## 4. DNS9 복원 판정

DNS_Security_EDA.ipynb cell 4와 DNS_Security_ML.ipynb cells 2/5는
stateless_features-*.pcap.csv를 읽고 9개 컬럼을 선택한다. 파일명의 pcap.csv는 PCAP
파싱 코드가 아니다. ML Notebook의 RF/XGB/LGBM 실험은 공급 INT8 DNN의 학습/export 코드가 아니다.

| Feature | 미확보된 원본 계산 경계 |
|---|---|
| FQDN_count | 입력 문자열 표현, byte/codepoint, case, trailing dot, IDNA |
| subdomain_length | 등록 Domain/Suffix 경계, multi-label suffix, 길이 단위 |
| numeric | ASCII/Unicode 숫자 집합, 전처리 순서 |
| entropy | log₂ 식·계산 대상 문자열/기호 빈도·dot/case/빈 값 처리 |
| special | 특수문자 집합·escape·punycode 처리 |
| labels | root/빈 Label/trailing dot/malformed 처리 |
| labels_max | Label 길이 단위 및 정규화 |
| labels_average | 분모·빈 Label·rounding·float 변환 시점 |
| len | FQDN_count와 차이, Domain/Subdomain 경계 |

전체 이름/순서 Digest는
`3276c1b595ec566677bce530f2839247b7fa1320dc5e3549f85c0c17c959edd0`다.
확보된 것은 feature_contract.json과 제공 detector.py의 **이미 계산된 9개 수치 이후**
float32→named StandardScaler.transform→round/clip INT8 처리다.
입력 quantization은 scale 0.0387900173664093 / zero -40,
출력은 scale 0.00390625 / zero -128이다. 공급 Manifest의 training_version 및
DNN training/export, calibration, upstream extractor 단위는 UNVERIFIED다.

현재 DNS parser의 case-preserving wire label 파싱은 transport 관측이다. 이를 기존 DNS9의
정규화 규칙으로 간주하지 않았다. Query Name을 보존하지 않는 관측의 Digest만으로
문자열·Entropy를 복구하거나 0을 채우지 않는다. DNS9에 TTL Feature를 추가하지 않았다.

**DNS Security: INSUFFICIENT_EVIDENCE.** 원본 FQDN/Producer/Config/학습 대응 행이 없어
9개 모두 Formula Parity BLOCKED다. 외부 원저자의 자료 존재 여부까지 부정하지 않는다.

## 5. Golden Pair / Feature Parity

| 필수 구성 | Quality / Edge | DNS |
|---|---|---|
| 원본 Raw 입력 | 학습 PCAP 없음 | 원본 FQDN/PCAP 없음 |
| Original Producer Identity / Revision | 없음 | 없음 |
| Producer Configuration / Digest | 없음 | 없음 |
| Expected Training Feature | CSV/Parquet은 있으나 Raw 대응 없음 | 참조 CSV 없음 |
| Schema / Order / 모델 전처리 | 검토 패키지 코드/리소스 존재 | 검토 패키지 코드/리소스 존재 |
| Raw→Feature 허용 오차 | 미정, 원본 기준 없음 | 미정, 원본 기준 없음 |
| Artifact Binding | 개별 SHA 일치 | 개별 SHA 일치 |
| 완전한 Golden Pair | **0** | **0** |

실제 Golden Pair 비교는 **BLOCKED / 미실행**이다. 기존 compare_exports 및
reported Network/DNS Validator의 Numeric/float32/NaN/Inf/순서/변조 테스트를 재사용한다.
그 Fixture의 numerical PASS는 원본 학습 정합성 PASS가 아니다. 기존 정확 수치 비교
정책을 원본 Producer의 허용 오차로 발급하지 않았다.

## 6. Artifact / Native 환경

원본 ML 패키지 Manifest에 대해 다음 7개 리소스/Artifact를 실제 읽고 SHA를 대조했다.

| Artifact | SHA256 | 결과 |
|---|---|---|
| Top40 CSV | feef58ff01b7d9a8b992fb4475ebaeb910b11ebdf23cd9ff5658c10e86865b3d | MATCH |
| Label Mapping | 1c2b006bca8d80d86670d2f133f9f53864294c541a0f805fc6ab8d794f2677fd | MATCH |
| Quality LightGBM | eb28cc855a65d336cd1b2720ec4fcc2958874444e33fae5b78c1cae4e4c62924 | MATCH |
| Edge FP32 DNN | 85cbc702d1b0a137c4f44b23be6911691cc89d5bfef0c388cf282e9500c49160 | MATCH |
| Edge Scaler | 528cfa770181bb61bdcc5d30b2cae8a171dfa63399f3fd33f9a15ab5fbc67d32 | MATCH |
| DNS INT8 DNN | 28e089af363dd565a4fb3d3f202de9e9f9804bd14a164de4fd7b61adb1201e33 | MATCH |
| DNS Scaler | 2735f7650a7d7888ee68f2df870b4e29d83666962931ae2aecb9aa339f40266a | MATCH |

프로젝트의 기존 .security-ai-demo 격리 환경으로 package_status CLI를 **READ-only** 호출했다.
세 모델 모두 package_import / contract / artifact / backend_dependencies가 VERIFIED다.
이는 Import/Manifest/설치 배포 메타데이터 확인이며 이번 모델 로딩/Native predict 성공의
증거가 아니다. demo_inference는 UNKNOWN이고 새로운 Native 추론은 0회다.
과거 Native Fixture 검증을 이번 운영 E2E 검증으로 대체하지 않았다.

현재 추론 환경의 배포 메타데이터는 Python 3.12.14, security-ai/network-security-ai/
dns-security-ai 0.1.0, LightGBM 4.7.0, torch 2.14.1, ai-edge-litert 2.3.0,
NumPy 2.5.3, pandas 3.0.6, scikit-learn 1.9.1, joblib 1.6.0이다.
이는 **현재 추론 환경** 정보이며 학습 Raw Producer 라이브러리/버전을 입증하지 않는다.

## 7. 모델별 Operational Gate

| 조건 | Network Quality | Network Edge | DNS |
|---|---|---|---|
| 실제 수집 Source | 저장 lo 세션 검증 | 저장 lo 세션 검증 | 실제 DNS 0건, 미검증 |
| Producer Revision | MISSING | MISSING | MISSING |
| Producer Config | MISSING | MISSING | MISSING |
| Golden Pair | MISSING | MISSING | MISSING |
| Feature Contract | Numeric/Order만 확인 | Numeric/Order만 확인 | Numeric/Order만 확인 |
| Artifact Integrity | PASS | PASS | PASS |
| Adapter Binding | 기존 Synthetic v2 계약 | 기존 Synthetic v2 계약 | 기존 Synthetic v2 계약 |
| Provenance | 저장 Network Source chain 검증 | 저장 Network Source chain 검증 | 실제 DNS Source chain 미검증 |
| 운영 허용 | **BLOCKED** | **BLOCKED** | **BLOCKED** |

각 모델의 기존 model_gates()는 다음 상태를 계속 반환한다.

```text
Operational Input: NOT_INFERABLE
Inference: BLOCKED
Finding Promotion: BLOCKED
Feature Generation: DIAGNOSTIC_ONLY
```

SOURCE_CHAIN_VALIDATED_UNATTESTED는 학습 계산 정합성이나 전역 수집기 진위 증명과 다르다.
Caller-set verified Boolean, producer 이름 문자열, 재계산한 Digest로 Gate를 해제하지 않는다.

## 8. Native Inference / SOC Agent 최소 연결 지점

| 기존 경로 | 실제 계약 / 현재 상태 | 후속 연결 조건 |
|---|---|---|
| network_capture/capture.py:PacketCapture | AF_PACKET 관측 및 Kernel Clock | 별도 승인된 수집 권한 |
| parsing.py:parse_packet / dns_message | transport metadata, 제한된 wire DNS | 현재는 진단 관측 |
| flows.py:FlowTable / pipeline.py:NetworkPipeline | 중복 방지, 진단 Flow, Queue/Source/Receipt | 학습 Producer로 승격 금지 |
| external/service.py:ExternalSecurityAIService | 관리 Native 추론/예산/실패 경계 | 현재 입력은 Synthetic v2 전용 |
| external/models.py:SourceFeatureObservation | synthetic: Literal[True] | 실제 운영 입력을 true로 위장 금지 |
| external/adapters.py:ExternalEvidenceAdapter.adapt / assembly.py:assemble | 결과·Source·Artifact·Incident 검증 | Producer 및 운영 입력 계약 검토 후 |
| external/projection.py:project / runtime_integration.py:ContextLLMClient | Advisory 분리, MODEL_FACT_PROMOTION 거부 | 검증 결과만 조사 Context에 연결 |
| linux_runtime/service.py:LinuxMonitor | 기존 인증 Finding/조사/정책 경로 | Network/DNS Finding bridge 현재 미구현 |

이벤트 기반 운영 추론에는 검증된 Producer뿐 아니라 **실제 Source를 받을 명시적인 운영
입력 계약**이 필요하다. 현재 v2의 synthetic Literal을 바꾸거나 v3 Receipt에 model_result를
붙이는 것으로 해결하지 않는다. 향후 별도 검토에서 기존 서비스의 제한·Timeout·Audit를
재사용하고, Event×Model×Artifact/Feature Digest 단위의 영속 멱등성/UNKNOWN 복구를 설계한다.
현재 검증된 Producer가 없어 이 작업에서 불필요한 대기 Worker/새 Queue/새 Agent를 만들지 않았다.

새 운영 자동 추론·Finding·Investigation·LLM 호출은 모두 **미실행 / BLOCKED**다.
모델 결과를 관측 사실로 승격하거나 Network Quality/Edge 점수를 평균하지 않는다.

## 9. GUI Live Monitoring

기존 gui/backend.py의 models()→ApplicationService.security_ai_status() 경로와
linux_runtime/network_monitor.py:network_status(), gui/charts.py:MetricHistory,
gui/app.py의 network_rate / dns_rate / ai_count 차트를 조사했다.

- 환경 READY/PREFLIGHT_ONLY_NO_INFERENCE와 운영 NOT_INFERABLE은 별도 상태다.
- 상태 조회는 추론을 실행하지 않는다. Native 결과 Distribution은 데이터가 없으면 NO_DATA다.
- STOPPED/오래된 Heartbeat의 rate는 None/UNKNOWN이며 저장된 과거 수집을 현재 Live로 표시하지 않는다.
- Source/Queue/Gap/Drop와 AI Invocation은 서로 다른 지표다. AI count는 새 운영 호출 0건이다.
- 새 GUI 코드는 추가하지 않았다. 이번에는 실제 WSLg 창/스크린샷 검증을 수행하지 않았으며,
  기존 GUI 단위/통합 회귀로 표시 경계를 확인한다. 새 Model Result 화면을 구현했다고 보고하지 않는다.

## 10. WSL 저장 데이터 E2E 재검증

사용자가 앞서 직접 실행한 lo Manual Capture v2의 저장 결과를 재사용했다.
원본 파일 SHA를 기록한 후 별도 private 복사본에서 기존 manual_capture.verify를 실행했다.
해당 함수의 Queue recovery/enqueue 검사는 쓰기를 할 수 있으므로 원본에는 호출하지 않았다.

| 항목 | 이번 재검증 |
|---|---|
| Capture / Queue / Source / Provenance | VERIFIED: 32 Packet / 4 Flow / DONE 36 / Receipt 36 |
| SQLite / 중복 방지 / Audit | PASS, 원본 증거 SHA 유지 |
| 실제 DNS | 0건, 실제 DNS 서비스 수집 미검증 |
| Gap | 1, Kernel replay 불가 경계 보존 |
| Feature / Native Inference / Finding / LLM | **BLOCKED**, 0회 |
| 새 권한 Capture / 트래픽 / sudo | 0회 |
| WRITE | WRITE_DENIED |

Audit Digest는
`a65e1ec434cf3f6bfc7bf69c3d4d799e38517ffe33c5540d0acb3194d21d75b1`다.
이 결과는 학습 Dataset PCAP의 Golden Pair나 실제 네트워크 공격 탐지 정확도의 증거가 아니다.
실제 Kernel 패킷 검증과 아래 Synthetic Fixture 회귀를 구분한다.

## 11. Security / Regression

신규 test_producer_recovery_gate.py는 기존 Packet→Queue→Source→v3 경로를 호출한다.
Source/Receipt가 유효하고 재시작·중복 처리가 성공해도 세 모델 Gate가 닫혀 있음을 확인한다.
진단 Flow의 producer_revision/golden_pair_verified/feature_status/방향 위조,
이름 미보존 DNS의 운영 권한 주장, Digest를 재계산한 v3 model_result 추가를 거부한다.
테스트 입력은 EXPLICIT_PACKET_FIXTURE이며 실제 Capture 성공으로 표시하지 않는다.

기존 Feature 순서·값·Artifact·Incident/Source Binding·Context 변조·Model Fact Promotion,
Approval/WRITE_DENIED·Runtime Crash/Restart·LLM Timeout 회귀를 재사용한다.
실제 원본 Golden Pair 변조·원 Producer Revision 불일치 비교는 기준 자료가 없어 미실행이다.
대신 검증됐다는 문자열/Flag와 재계산 Digest의 권한 승격을 거부하는 테스트를 수행한다.
Producer Worker가 존재하지 않으므로 운영 Model Timeout / Circuit Breaker / Duplicate Inference
성공 시나리오를 실행한 것으로 보고하지 않는다. 해당 운영 경로는 BLOCKED다.
실제 Native/LLM Provider 테스트도 미실행이다.

네트워크 금지 테스트 실행기 tests/native_capture_verification_guard.py를 사용해
AF_PACKET/IPv4/IPv6 신규 소켓 생성을 거부한다. Fixture 소유 자식 프로세스의 기존 Crash
검증만 사용하고 실제 권한 Probe는 실행하지 않는다. 현재 사용자 미추적
unit/operational_features/test_producer_parity_boundary.py는 기존 작업이므로 이번 회귀와
독립 Export 모두에서 범위 제외한다. 실패를 숨기기 위한 Skip이 아니다.

## 12. Retraining Decision / 신규 Producer 후보 설계

**재학습 실행: 없음. 재학습 승인 요청을 대신하거나 자동 실행하지 않는다.**
먼저 원저자/데이터 공급 경로에서 원 Producer source commit 또는 binary SHA,
Config/argv, Raw PCAP/FQDN와 기대 Feature 행/매칭키/Checksum 및 실행 로그를 요청하는 것이 우선이다.
DNS는 공급 DNN의 실제 학습/Label Mapping/Export 이력도 필요하다.

원본 확보가 불가능하다고 확정되면 다음은 별도 검토할 후보 설계다. 기존 모델과의 호환성을
주장하거나 추정 Extractor를 구현하지 않는다.

| 후보 | 설계 범위 | 기존 모델과의 관계 |
|---|---|---|
| Network diagnostic-derived producer, 새 Schema/Revision | 기존 Packet/Flow를 재사용하되 방향·packet length 단위·IAT 표본/분산·Timeout·TCP 상태·NaN 규칙을 먼저 문서화하고 Raw 검증 Fixture 고정 | 기존 Top40로 이름 맞추기 금지; 새 입력 의미로 학습/독립 검증 필요 |
| DNS wire-based producer, 새 Schema/Revision | 기존 parser를 재사용; raw label byte와 표시 문자열을 구분하고 case/root/trailing dot/IDNA/숫자·특수문자 집합/Entropy 대상/빈 Label을 명시 | 기존 DNS9 len/subdomain 의미를 추정하지 않음; 공급 모델 자동 재사용 금지 |

새 Producer는 별도 Artifact Binding/Config Digest/Golden Pair를 만들고, Raw 입력 저장이
필요한 검증 Fixture는 승인된 격리 자료로 제한한다. 운영 기본 Payload/질의명 미보존 원칙은
자동 변경하지 않는다. Event Label은 모델 판단이나 운영자 승인 여부로 자동 생성하지 않는다.
Training/Development/Holdout의 Entity·시간 분리 및 독립 Label이 필요하다.

Network CSV 입력 학습 실험은 기존 자료로 계획할 수 있지만, 새 Packet Producer 출력과
동일 의미의 Raw/Label corpus가 없어 이번 최종 목표 기준으로는 재학습 준비도 BLOCKED다.
DNS는 원본 질의와 참조 CSV, DNN 학습/export 코드도 없어 BLOCKED다.
기존 CSV/파생본 총 용량과 Parquet 행 수는 위 관측값일 뿐 새 Corpus의 추가 저장 공간,
RAM, 학습 시간, GPU/Cloud 비용 추정치가 아니다. 해당 비용은 **UNKNOWN / 미측정**이다.
기존 V4-B2의 1,946,494행 × 40컬럼 × float32 4 bytes만 계산하면 논리적 Feature 행렬은
311,439,040 bytes다. 이는 산술 참고값이며 DataFrame/Tree/학습 상태를 포함한 실제 RSS나
새 Producer의 재학습 비용 예측이 아니다. 원본/Label/새 Feature 사양 및 표본 크기가
정해진 뒤 별도 승인된 소규모 Profiling이 필요하다.

## 13. Remaining Blockers / Physical Linux Follow-up

1. 정확한 학습 Producer Revision / Config / 실행 이력.
2. Network 학습 PCAP↔Feature 대응 및 DNS 원본 질의↔학습 Feature 대응.
3. 원본 기준의 Numeric Tolerance와 Missing/단위/방향/Timeout/정규화 규칙.
4. DNS DNN 학습·Label/Export provenance.
5. Producer 검증 이후의 운영 입력 계약, 이벤트 기반 Native Worker 및 Finding/Advisory 연결.
6. lo 일회성 검증과 별개의 NIC 상시 수집 최소 권한·Drop/Gap·부하·보존·복구 검증.
7. 물리 Linux 서버의 NIC/offload/시간 정확도/재시작 검증. WSL 결과를 물리 서버 검증으로 확장하지 않는다.

## 14. 변경 파일 / Git 범위

- docs/linux-soc-v1/producer-recovery-operational-ai.md
- docs/linux-soc-v1/producer-recovery-operational-ai-evidence.json
- tests/integration/network_monitor/test_producer_recovery_gate.py

운영 코드, 모델 Artifact, 기존 Synthetic v2 / Operational Provenance v3,
Human Approval/WRITE 경계를 변경하지 않는다. 위 파일만 기준 HEAD archive에 적용한 독립
Export에서 회귀를 확인하고 Stage SHA를 대조한다. 검증 후 사용자 요청의 Commit 메시지를
사용하되, 커밋 제목을 운영 추론 활성화 증거로 해석하지 않는다. 실제 Commit/Push 결과와
최종 테스트 수치는 아래 검증 결과 및 작업 응답에서 별도로 기록한다.


## 15. 실제 실행 검증 결과

| 실행 | 결과 | 실제 경과 |
|---|---|---|
| 신규 Producer 차단 통합 테스트 | 9 passed / 0 failed | 3.01초 |
| 작업 트리 확대 회귀 | **756 passed / 0 failed** | 250.76초 |
| 기준 HEAD + 이번 3파일 독립 Export | **756 passed / 0 failed** | 243.83초 |
| 기존 실제 lo 저장 세션 재검증 | VERIFIED, Packet 32 / Flow 4 / Source·Receipt 36 | 새 Capture 없음 |
| 원본 Golden Pair / 운영 Native 추론 | BLOCKED / 미실행 | 기준 Producer 없음 |
| 실제 LLM Provider / WSLg 창 검증 | 미실행 | 이번 결과로 PASS 주장 없음 |
| Ruff check src tests | PASS | 전체 검사 |
| Ruff format --check . | PASS, 878 files | 신규 테스트만 formatter 적용 |
| git diff --check | PASS | 기존 사용자 파일 변경 없음 |

9개는 확대 실행 756개 안에 포함되며 실행별 수치를 합산하지 않는다.
기능 테스트 실패나 Skip으로 경계를 완화하지 않았다. 최초 신규 파일의 format-check
불일치는 그 파일만 formatter로 정리했고, 최종 소스로 두 확대 실행을 수행했다.
두 확대 실행에서 기존 권한 거부 테스트의 네트워크 소켓 시도 1회가 Audit Hook에
차단됐다. 이는 권한 거부 오류 주입이며 실제 AF_PACKET 수집이 아니다.

두 확대 실행 범위/명령은 같다. Export에서는 기준 HEAD archive에 이번 3파일만 적용한
뒤 그 Export의 src / tests를 절대 PYTHONPATH로 지정했다. 아래 명령은 저장소 Root 기준이다.

```bash
RUN_LIVE_LLM_TESTS=0 PYTHONPATH="$PWD/src:$PWD" \
  .venv/bin/python tests/native_capture_verification_guard.py \
  --import-mode=importlib -q \
  tests/unit/network_capture tests/integration/network_monitor \
  tests/unit/operational_features \
  --ignore=tests/unit/operational_features/test_producer_parity_boundary.py \
  tests/unit/security_ai/external tests/unit/external_context \
  tests/unit/package_status tests/integration/package_status \
  tests/integration/external_runtime/test_runtime.py \
  tests/integration/external_read_only_backend tests/integration/linux_runtime \
  tests/unit/gui tests/integration/gui \
  tests/unit/approval tests/unit/execution tests/unit/realtime
```

로그는 `/tmp/soc-producer-recovery-{new-tests,regression,export-tests}.log`에 보존한다.
이 로컬 로그·전체 ML 데이터·모델·실제 Capture DB는 커밋하지 않는다.
기존 SOC 1,020파일 및 이번에 기록한 ML source/artifact 172파일의 SHA를 전후 비교했고,
전체 데이터 파일의 SHA를 계산했다고 보고하지 않는다.

**최종 결론:** 수집 Source chain과 패키지 계약/Artifact 및 보안 차단 회귀는 확인했다.
원본 Producer / Golden Pair 미확보로 이번 목표의 운영 AI 연결은 **BLOCKED**다.
공급 자료 확보 전까지 Producer를 추정 구현하거나 실제 Source를 synthetic으로 바꿔
운영 추론을 실행하지 않는다. 기존 모델을 재학습·교체하거나 Gate를 자동 해제하지 않았다.
