# Gate D/G Phase 1 — 계약 및 호환성 조사

2026-10-13. 브랜치 main, 시작 HEAD `a0169285840de6a8107fd1509480dd3cb9af0dcf`.
기존 수정/미추적 상태는 `/tmp/soc-operational-before.txt`에 기록했다.
기존 Gate C/D 명칭과 태그 의미는 변경하지 않는다.

## 결과: 계산 의미 확인은 BLOCKED, 숫자 입력 계약 확인은 PASS

| 대상 | 확인된 계약 | 확인되지 않은 사항 | 이번 결정 |
|---|---|---|---|
| Network Quality / Edge | 공식 Top40Contract 40개 순서, 15-class label mapping, float32 matrix, 동일 FeatureIdentity | 학습 CSV를 생성한 CICFlowMeter source commit/config, 원천 PCAP와 CSV pairing, 세부 계산 규칙 | PCAP→Top40 계산 보류. 이미 계산된 export의 숫자/식별자 검사만 구현 |
| DNS LiteRT | DNSFeatureContract 9개 순서/float32/nonnegative/finite; 기존 scaler/manifest 로더 | FQDN_count/numeric/special/entropy/labels 계열 전부 원천 계산 정의; IDNA·trailing dot·entropy base; DNN training matrix 실제 order의 증거 일부 부재 | FQDN→DNS9 계산 보류. 이름으로 추정하지 않음 |
| 내부 Network | NetworkFeatureExtractor, duration_us/fwd_packets/bwd_packets/fwd_bytes/bwd_bytes | Top40와 동일한 계약 아님 | 5→40 변환 금지 |
| 내부 Authentication | AuthenticationEvent, UTC epoch-aligned 300-second half-open windows, count/rate 공식 | 실제 Windows/Linux source mapping, persistent incremental/window close/late-arrival 정책 | 기존 계산기 재사용 계획. 새 OS 인증 데이터가 검증됐다고 주장하지 않음 |
| External Context | v2 synthetic_contract_only + synthetic=True, advisory adapter/assembly/receipt/guard | 운영 source를 수용할 버전 계약 없음 | v2 변경/위장 금지. v3 확장 계획만 작성 |

외부 ML 저장소 `/home/geonug/kdt-linux/ML`은 읽기 전용이다. 다음은 실제로 확인한 파일이다.

- `packages/network-security-ai/src/network_security_ai/contracts.py::Top40Contract`:
  rank 1..40 및 SHA를 읽고 matrix/payload를 만든다. Packet/flow feature를 계산하지 않는다.
- `packages/network-security-ai/src/network_security_ai/resources/top40_features.csv`:
  Fwd Act Data Pkts부터 Bwd IAT Std까지 40개 순서만 제공한다. 계산 단위/producer version 없음.
- `packages/dns-security-ai/src/dns_security_ai/contracts.py::DNSFeatureContract`:
  순서/finite/nonnegative/scalar/float32 범위를 검증한다. 문자열 FQDN에서 features를 생성하지 않는다.
- `packages/dns-security-ai/src/dns_security_ai/feature_contract.json`:
  9개 모두 unit에 `UNVERIFIED; upstream dataset feature extraction unavailable`을 명시한다.
- `reports/Security_AI_Integration_Report.md`, Feature Contracts 표:
  entropy base/normalization, special/numeric counting, label/length conventions을 UNVERIFIED로 명시.
- DNS EDA/ML notebooks: EDA cells 4/7 및 ML cell 2는 `.pcap.csv`를 읽고,
  EDA cell 10 / ML cell 5는 이미 계산된 9-column을 선택한다. PCAP parser/FQDN extractor가 아니다.
- Network notebooks/preprocessing: CSE-CIC CSV 이름은 확인되지만 생산 CICFlowMeter 코드/config는
  발견하지 못했다. Notebook 코드 cells를 읽었으며 실행/학습/아티팩트 재생성하지 않았다.
- local tree에서 승인된 raw `.pcap`/`.pcapng` 테스트 자료는 발견하지 못했다.

온라인 upstream의 일반적인 CIC 정의와 **이번 학습 producer의 동일성**을 혼동하지 않는다.
이번 조사는 local 코드/메타데이터/notebooks의 증거이며 remote 자료를 확보했다는 주장이 아니다.

## Network 계산 규칙 검증에 필요한 자료

| 항목 | 필요한 증거 |
|---|---|
| 방향/flow 경계 | 첫 패킷 기준 또는 initiator 기준, 5-tuple, bidirectional 매칭, timeout/subflow 분할 |
| Flow Duration/IAT | timestamp resolution와 단위, first/last 제외 규칙, forward/backward total/min/max/std, 표본/모집단 std |
| Packet/segment/header 길이 | L2/IP/transport/payload 중 어떤 길이인지, 옵션·fragment·retransmission·truncation 처리 |
| Flags/window | TCP flags count와 방향별 PSH/URG, 첫 TCP window, 비-TCP/단방향 initial window sentinel |
| Active/idle/subflow | timeout/threshold, segmentation algorithm, empty group와 Subflow Bwd Byts 계산 |
| Rate/zero duration | packet-rate 단위, duration=0 convention, 빈 flow/단방향/missing 처리 |
| 학습 정합성 | 실제 사용 producer commit/config와 PCAP→해당 producer CSV golden pair, dataset/train metadata 연결 |

`Dst Port` 같은 익숙한 이름도 학습의 방향/flow 경계를 확인하지 않고 전체 Top40 parity를
검증했다고 표시하지 않는다. 현재 package의 숫자 입력 검증은 계산 정확성의 증명이 아니다.

## DNS 계산 규칙 검증에 필요한 자료

공식 9개: `FQDN_count, subdomain_length, numeric, entropy, special, labels,
labels_max, labels_average, len`. 원 upstream extractor source/version 또는 검증된 실행
spec와 query→9-column golden pairs가 필요하다. Unicode/IDNA/case/root dot,
문자/byte 길이, label 처리, entropy alphabet/base/normalization을 확인해야 한다.

## 재사용 경계

- `features/extractor.py::FeatureExtractor/create_feature_set`: 원본 참조·Incident binding 및
  FeatureSet factory 재사용 가능. 이 factory는 **계산 정확성을 검증하지 않는다**고 명시한다.
  규칙 미확인 값을 넣어 검증된 FeatureSet처럼 반환하는 경로를 만들지 않았다.
- `external/metadata.py::reviewed_binding`: package/version/code pin 및 공식 FeatureIdentity 재사용.
- 기존 `Top40Contract.matrix`: 이미 신고된 40개 값을 공식 순서/float32로 변환하는 데만 재사용.
  upstream은 numeric string과 NaN/Inf→missing을 허용하므로 이번 운영 intake에서는 더 엄격하게
  finite numeric만 허용한다. 원 package/API 또는 기존 경로는 수정하지 않는다.
- 기존 `external/models.py`, Adapter/validation/assembly/projection/runtime guard/store 및
  Decision/Approval/Fusion/SQLite 계약은 그대로 보존한다.

## Phase별 파일 변경 계획

| Phase | 구체적인 신규/변경 후보 | 실행 조건/검증 |
|---|---|---|
| 1 | 이번 계약 조사/검증 보고서 | 완료. Code/contract/notes 및 기존 tests 읽기 |
| 2 최소 | `security_ai/operational/network_records.py`, `tests/unit/operational_features/` | 완료: 숫자 입력 경계. 항상 NOT_INFERABLE; raw packet extraction 없음 |
| 2 계산 | 신규 `operational/network_flow_extractor.py`, 승인 PCAP/producer golden 테스트 | source/version/config/golden pair 확보 후. 기존 generic FeatureExtractor 재사용 |
| 3 | 신규 `operational/dns_sources.py`, `dns_feature_extractor.py`, query→golden tests | 공식 DNS 원천 계산 규칙 확인 전 보류 |
| 4 | 신규 `operational/authentication_sources.py`, window persistence/late-arrival companion 및 tests | Windows Security XML/provider schema와 Linux auth 원본 계약을 먼저 확인. 기존 AuthenticationEvent/WindowExtractor/내부 AI 재사용 |
| 5 | 신규 versioned observation/provenance types 및 issuer/source-rule validator | 아래 v3 설계 조건 충족 후. v2 유지, 타입/직렬화/receipt compatibility tests 필수 |
| 6 | `external/validation.py`, `service.py`, `assembly.py`, `projection.py`, `runtime_integration.py`의 명시적 version adapter 후보 | reviewed operational source만 수용. Runtime/store 기존 exact type/ID/binding 변경을 추측으로 수행하지 않음 |
| 7 | 신규 raw-source→native model→actual Runtime E2E 및 기존 security 회귀 | 실제 입력 자료 확보 후. Scripted LLM/Native inference/실제 source 검증 범위 분리 |

Phase 3~7은 이번에 선행 구현하지 않았다. 자료가 부족한 경로를 mock inference나 fake
synthetic provenance로 연결해 완료 처리하지 않는다.

## 공식 ordered Feature Identity

설치된 reviewed_binding metadata만 읽어 `feature-contract-evidence.json`에 저장했다.
모델/Scaler 로딩이나 Native inference를 실행한 결과가 아니다. 계산 규칙 상태는 전부
학습 producer와의 parity 증거가 부족한 UNVERIFIED이다.

| Position (0-based) | Network Top40 | DNS9 |
|---:|---|---|
| 0 | Fwd Act Data Pkts | FQDN_count |
| 1 | Fwd Seg Size Min | subdomain_length |
| 2 | Fwd Header Len | numeric |
| 3 | ECE Flag Cnt | entropy |
| 4 | Init Fwd Win Byts | special |
| 5 | URG Flag Cnt | labels |
| 6 | RST Flag Cnt | labels_max |
| 7 | Dst Port | labels_average |
| 8 | Fwd PSH Flags | len |
| 9 | Fwd Pkts/s | — |
| 10 | Fwd Pkt Len Mean | — |
| 11 | Pkt Len Max | — |
| 12 | SYN Flag Cnt | — |
| 13 | Fwd Seg Size Avg | — |
| 14 | Bwd Header Len | — |
| 15 | Init Bwd Win Byts | — |
| 16 | Fwd IAT Std | — |
| 17 | Fwd IAT Max | — |
| 18 | Pkt Size Avg | — |
| 19 | Fwd IAT Tot | — |
| 20 | Bwd Pkt Len Max | — |
| 21 | PSH Flag Cnt | — |
| 22 | Flow IAT Mean | — |
| 23 | Bwd IAT Min | — |
| 24 | Bwd Pkt Len Std | — |
| 25 | Pkt Len Mean | — |
| 26 | Bwd IAT Max | — |
| 27 | Fwd Pkt Len Std | — |
| 28 | ACK Flag Cnt | — |
| 29 | TotLen Bwd Pkts | — |
| 30 | Pkt Len Std | — |
| 31 | FIN Flag Cnt | — |
| 32 | Bwd IAT Mean | — |
| 33 | Flow Duration | — |
| 34 | Flow IAT Max | — |
| 35 | Subflow Bwd Byts | — |
| 36 | Idle Max | — |
| 37 | Fwd URG Flags | — |
| 38 | Bwd Pkts/s | — |
| 39 | Bwd IAT Std | — |
