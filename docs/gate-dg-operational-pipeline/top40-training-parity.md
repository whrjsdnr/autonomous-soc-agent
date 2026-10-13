# P0 Network Top40 학습 정합성 조사·비교 도구 — 2026-10-13

## 판정

**운영 Feature → AI → Agent E2E: BLOCKED 유지.**
학습 Producer의 정확한 revision/configuration과 PCAP↔학습 CSV Golden Pair가 없다.
독립 CSV 비교 도구는 구현·검증했지만 PCAP Feature 계산이나 운영 추론을 활성화하지 않았다.

시작 HEAD: `2589cc9a0d7e5d832592a909a270cc880d4bacb5`, main.
Git 상태는 `/tmp/soc-top40-before.txt`에 보존했다. 기존 사용자 수정 3개 및 미추적 파일은 보존했다.
이번 수정은 신규 모듈/테스트/보고서 각 1개이며 기존 Source Store/Provenance v3/v2/Runtime은 변경하지 않았다.

## Phase A — 로컬 학습 기록

아래 ML 경로는 `/home/geonug/kdt-linux/ML` 기준이다. Notebook JSON code source만 읽었으며 실행하지 않았다.
셀 번호는 JSON cells 배열의 0-based index다.

| 자료 | 확인된 사실 | 확인되지 않은 것 |
|---|---|---|
| notebooks/data.ipynb cell 0 | data/raw/cse_cic_ids2018/*.csv 검색 후 pandas.read_csv 및 헤더/컬럼 검사 | PCAP reader나 Feature Producer 실행 아님 |
| data/raw/cse_cic_ids2018/*TrafficForML_CICFlowMeter.csv | 실제 로컬 CSV 존재 | 파일 이름은 생성 revision/configuration을 증명하지 않음 |
| notebooks/preprocessing.ipynb cells 67/68 | feature_importance_full78.csv 읽기, head(40)의 feature 목록을 Top40 CSV로 저장 | 78개 컬럼의 원천 계산 구현이 아님 |
| notebooks/model_sample_v4.ipynb cells 32/33 | rank 정렬한 40개 이름, 기존 모델 컬럼과 대조 | producer version/timeouts/feature 단위 미기록 |
| 같은 Notebook cell 56 | 기존 V4A Parquet 컬럼 선택 → np.float32 행렬, sample_weight/label 입력 | 원천 PCAP와 행별 대응 증거 없음 |
| notebooks/dnn_top40_v4.ipynb cells 0/1/2/43 | 공식 순서, Parquet 배치 float32 변환, nonfinite→NaN, train batch StandardScaler.partial_fit, 저장 mean으로 impute 후 transform→float32 | 원천 Flow 생성 규칙 미확보 |
| notebooks/model_diversity_v3.ipynb cells 5/7/9 | 이전 실험 float32, median imputation/scaler 코드 | 이 실험의 전처리를 현재 Quality/Edge에 일괄 적용하면 안 됨 |
| packages/network-security-ai/src/network_security_ai/contracts.py::Top40Contract | pinned 40개 순서 및 15-class mapping, numeric→float32 matrix | 컬럼 계산식/단위/producer 구현은 포함하지 않음 |
| 같은 패키지 preprocessing.py::preprocess_dnn_batch | float32 copy → saved training mean imputation → saved scaler.transform → float32 | scaler를 재학습하거나 source feature를 생성하지 않음 |
| predictors.py / reports/Security_AI_Integration_Report.md Network Model Review | Quality LightGBM은 scaler 없이 native missing 처리; Edge DNN은 위 저장 scaler 사용 | 실제 raw source→training CSV 정합성 증거 없음 |
| results/final_report/source_manifest.csv | 모델/Notebook/전달 파일의 경로·bytes·SHA 기록 | 해당 모델 학습 원천 PCAP, producer config 및 실행 로그의 연결 receipt 아님 |

읽은 raw CSV 중 Friday-02-03-2018, Friday-16-02-2018의 헤더는 각각 80개 컬럼이며
확인한 identity 후보는 Dst Port/Protocol/Timestamp다. 이 헤더만으로 완전한 양방향 Flow 키가 확보됐다고 하지 않는다.
두 파일의 데이터를 읽어 재평가하거나 synthetic Golden Pair로 사용하지 않았다.

로컬 tree의 Python/문서/JSON 및 학습 Notebook에서 Producer 실행 구현·설정·원천 PCAP을
확인하지 못했다. CSV reader/선정 코드와 PCAP→CSV Producer를 구분했다.
과거 보고서의 DNS Feature 정의 UNVERIFIED도 유지한다.

## Phase B — 원본 출처 확인과 후보

2026-10-13 확인한 1차 출처:

- [UNB CSE-CIC-IDS2018 공식 Dataset 문서](https://www.unb.ca/cic/datasets/ids-2018.html)는
  raw capture에서 **CICFlowMeter-V3**로 features를 추출했다고 명시한다.
  따라서 producer 계열/버전 이름에 대한 근거는 확보됐다. 정확한 source commit,
  dataset 생성 설정과 로컬 CSV checksum 연결까지 확인된 것은 아니다.
- [UNB Applications](https://www.unb.ca/cic/research/applications.html)는 첫 packet 기준 방향,
  bidirectional flow 및 설정 가능한 timeout을 설명한다.
  이 일반 설명의 timeout 예시를 이번 학습 dataset의 실제 설정으로 사용하지 않았다.
- 공식 Applications에서 연결하는 [UNBCIC/CICFlowMeter](https://github.com/UNBCIC/CICFlowMeter)는
  현재 repository 설명상 V4.0이며 [ahlashkari/CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter)의 fork다.
  현재 V4.0/master를 2018 dataset의 V3 생성 revision으로 대체하지 않는다.

일반 Producer source 후보를 찾는 것과 **학습 당시 Producer 확보**는 다르다.
V4/Python 재구현/임의 commit을 설치하거나 실행하지 않았다.
대용량 공개 dataset을 다운로드해 검증된 Golden Pair인 것처럼 사용하지 않았다.

필요한 확보 자료:

1. 실제 CSV 생성에 사용된 producer source commit 또는 재현 가능한 binary SHA/빌드 정보.
2. 설정 원문·SHA 및 정확한 실행 argv: TCP/UDP/active/idle timeout, flow split/종료,
   packet/header length, timestamp 단위 등 실제 사용 규칙.
3. dataset release/원본 checksum과 로컬 학습 raw CSV의 checksum 대응.
4. 승인된 원천 PCAP + 그 producer가 전체 capture에서 생성한 CSV + 생성 로그/파일 SHA.
5. 동일 flow/segment를 구분하는 방향·시간·5-tuple/추가 구분 키와 PCAP↔CSV 대응 기록.
6. producer column names/units→공식 Top40 이름의 검토된 연결 및 학습 raw→전처리 stage 증거.

FlowID나 5-tuple만 같아도 timeout으로 분리된 서로 다른 flow segment일 수 있다.
Port/Protocol/Timestamp만으로 다른 flow를 임의 병합하지 않는다.

## 차단 시 대체 구현 — 독립 비교 부분

신규 `src/soc_agent/security_ai/operational/compare_exports.py`:

- `parse_export(bytes, key_columns=...)`: 공식 reviewed_binding의 ordered_names를 사용해
  CSV에서 Top40을 명시적으로 projection. 헤더/행 순서는 모델 순서로 정렬하며 원본 digest는 보존한다.
- 비교 대상은 **이미 생성된 두 CSV export**다. PCAP parsing/extraction/PCAP와 행 대응 검증은 구현하지 않았다.
- Flow 키는 caller가 명시한 동일 컬럼 tuple의 **정확한 문자열**이다. 역방향 자동 병합,
  timestamp 반올림/시간 근접 매칭, 누락값/alias 추정은 하지 않는다.
- 중복·빈 key, 누락/중복 Feature column, malformed CSV, nonfinite, float32 overflow,
  빈/비수치 값은 거부한다. 추가 CSV 컬럼은 bounded 상태로 읽되 출력·Inference에 사용하지 않는다.
- 8 MiB/1024 rows/256 columns/128-character numeric token/절댓값 exponent 400의 명시적 한계.
  검토된 작은 Golden subset용 도구이며 전체 dataset 자동 분할·수집 기능은 아니다.
- CSV token을 Decimal로 보존해 binary64 정밀도보다 큰 정수 차이를 숨기지 않는다.
- 40개 각각 절대 오차, reference 대비 상대 오차, numeric equality,
  float32 bit equality와 변환 손실을 반환한다. reference=0인 비일치는 relative_error=None.
- 모델 행렬은 Decimal token→binary64→float32 변환을 사용한다. 이 변환은 실제 Top40Contract.matrix와
  대조 테스트했으며 little-endian float32 matrix SHA를 양쪽에 기록한다.
- signed zero는 numeric equality와 bit equality를 구분하며 비트 차이를 실패로 보고한다.
  float32 underflow/rounding을 출력에 기록하고 source token을 수리하지 않는다.
- 상대 오차는 bounded Decimal precision 600으로 계산하며 이를 acceptance tolerance로 사용하지 않는다.
- Flow 키 원문은 출력하지 않고 key digest만 사용한다. 입력 오류 메시지는 고정 코드다.
- CLI는 두 입력 CSV의 기대 SHA를 요구하고 결과 파일을 exclusive creation으로 작성한다.
  기존 파일/입력/보고서를 덮어쓰지 않는다.

### 사전 수치 정책

정책 버전 **EXACT_DECIMAL_EXPORTS_V1**: 허용 오차 0. 같은 key set에서 40개 token의
숫자 값과 float32 bits가 모두 같아야 numerical_status=PASS다.
이는 producer units/calculation parity 기준이 아니며 학습 정합성 기준을 대신하지 않는다.
계산 단위/학습 규칙이 없는 상태에서 feature별 실용 허용 오차를 발급하지 않았다.
원본 값은 다르지만 같은 float32로 변환되는 사례도 FAIL이다.

동일 export끼리도 다음 상태는 변경되지 않는다:

- training_parity_status: INCONCLUSIVE
- inference_status: NOT_INFERABLE
- write_disposition: WRITE_DENIED

수치 결과는 standalone diagnostic이며 EvidenceEnvelope, 운영 provenance:v3,
External Context, Capability, Approval 또는 Agent 입력으로 변환되지 않는다.
Producer/configuration/원천 매핑 없이 numerical PASS만으로 모델 호출하는 API가 없다.

### 실행 예시 (검토된 파일을 확보한 뒤)

```bash
.venv/bin/python -m soc_agent.security_ai.operational.compare_exports \
  --reference /approved/golden-export.csv \
  --candidate /approved/reproduced-export.csv \
  --reference-sha256 '<independently retained SHA256>' \
  --candidate-sha256 '<independently retained SHA256>' \
  --key '<reviewed flow identity column>' \
  --key '<reviewed segment identity column>' \
  --output /tmp/top40-export-comparison-new.json
```

이 경로/키는 placeholder다. 기존 training CSV에 해당 컬럼이 있다고 가정하지 않는다.
CLI exit 1은 진단 보고서 생성 후 학습 정합성 INCONCLUSIVE를 의미한다.
수치 FAIL도 JSON에서 구분한다. exit 2는 입력/출력 거부다. 현재 도구는 운영 성공 exit 0을 반환하지 않는다.

## 검증 결과

테스트는 인공 CSV Fixture이며 실제 원천 PCAP/학습 Golden Pair를 대체하지 않는다.

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q \
  tests/unit/operational_features \
  tests/unit/security_ai/external tests/unit/external_context \
  tests/integration/external_read_only_backend/test_guard.py
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check .
git diff --check
```

- 신규 비교 테스트 **31개** 포함, 집중·실제 Guard 회귀 **296 passed, 0 failed**.
  `/tmp/soc-top40-regression.log`. 이전 28개 테스트 실행과 합산하지 않는다.
- 동일/다른 export, Flow 순서·컬럼 projection, missing/extra key, duplicate keys,
  nonfinite/overflow, Decimal exact differences, float32 rounding/1 ULP/underflow/signed zero,
  공식 Top40 matrix digest 대조, source digest 불일치, 보고서 덮어쓰기 거부 검증.
- Guard는 기존 실제 로직, READ stub/WRITE spy 테스트를 재사용했다. 모델/LLM 추론 미실행.
- Ruff src/tests PASS, Format 전체 PASS, git diff --check PASS.
- 기존 통합 SHA manifest 33/33, realtime manifest 16/16 일치.
- tests/fusion_support.py SHA
  `e5f9d10f706f71b82e80261f7633a1504e27ba24499be948d04adb6eeb3a21c9` 유지.
- 전체 회귀/Windows Native/실제 모델 추론은 이번 단계에서 실행하지 않았다.

## Phase C/D 및 결과 구분

| 항목 | 상태 |
|---|---|
| Dataset producer 계열 | 공식 문서에서 CICFlowMeter-V3 확인 |
| 정확한 학습 Producer revision/config/실행 명령 | UNVERIFIED |
| 학습 연결 PCAP↔CSV Golden Pair | 미확보 |
| PCAP→Top40 Feature 계산 | 보류, 미구현 |
| 독립 export Top40 수치/identity/float32 비교 | 구현, 자동화 PASS |
| 실제 source에서 40개 계산 정합성 | BLOCKED, 미검증 |
| 운영용 실제 Quality/Edge 추론 | 미실행, NOT_INFERABLE |
| 기존 operational provenance:v3 | 보존, 변경·권한 확장 없음 |
| 운영 Model Result/External Context→Agent E2E | BLOCKED, 미실행 |

추가 파일은 compare_exports.py, test_compare_exports.py, 이 보고서 3개다.
기존 파일/보안 계약/모델 바이너리/ML 저장소를 수정하지 않았다.
Git commit/tag/push, Live LLM, 실제 Security WRITE, 운영 배포 미실행.

## 독립 후속 작업

1. 모델 호환성 P0: 위 producer/golden 증거를 확보해 versioned pairing inventory와
   실제 행별 40개 검산 테스트를 추가한다. 정확한 producer 확보 전 구현 추정 금지.
2. 독립 P0: 승인된 플랫폼별 인증 원본 필드/권한 계약을 확보하고 기존 source intake에 parser 연결 및 원천 검증.
3. 독립 P1: 입력 저장소 capacity/retention 및 Collector cursor와 admission transaction의 연결 테스트.
4. 독립 P1: 기존 운영 intake 재시작/동시 처리/장시간 부하와 Windows Secure Storage 검증.

2~4는 Network Feature Producer와 독립적으로 진행 가능하지만 이번 요청에서 구현하지 않았다.
실제 모델 결과의 운영 Provenance/Context 계약 확장은 Golden 검증과 source assurance 충족 뒤에만 진행한다.
