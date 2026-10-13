# P0 DNS9 Feature Producer 및 학습 정합성 — 2026-10-13

## 결론

**Producer 코드/버전 미확보, 실제 Golden Pair 미확보. 운영 DNS 추론 NOT_INFERABLE 유지.**
공식 자료에서 9개 Feature의 의미와 entropy의 log₂ 정의를 새로 확인했다.
이것은 학습 producer의 문자열 처리·행별 결과 정합성이 입증됐다는 의미가 아니다.
Source→reported Feature row의 연결·공식 numeric contract·수치 비교만 구현했다.

기준 HEAD `d76a259ceb15323e4afb5b32d10e263cdb67adeb`, main.
시작 상태 `/tmp/soc-dns-before.txt`의 사용자 변경과 기존 미추적 파일을 보존했다.
ML 저장소 읽기 전용. 모델/Scaler를 로드·재학습하지 않았다. Git commit/tag/push 미실행.

## 1. 실제 조사 자료

ML 경로는 `/home/geonug/kdt-linux/ML` 기준. Notebook은 JSON code source를 읽었으며 실행하지 않았다.

| 자료 | 확인 결과 |
|---|---|
| reports/CIC-Bell-DNS-EXF-2021_DNS_Security_EDA.ipynb cells 4/7/12/14 | 기존 stateless_features-*.pcap.csv를 pandas.read_csv로 분석; PCAP parsing/Feature 생성 함수 아님 |
| 같은 EDA cell 10 | 기존 9개 컬럼 비교. 개별 DNS 원문에서 Feature를 계산하지 않음 |
| reports/CIC-Bell-DNS-EXF-2021_DNS_Security_ML.ipynb cells 2/3/5/6 | benign/heavy_text CSV 읽기→label 0/1 지정·concat→9개 컬럼 선택→stratified 80/20, random_state=42 split |
| 같은 ML cells 8/11/14/17 | RF/XGB/LGBM/IsolationForest 실험 학습. 공급 INT8 DNN 학습·export 구현 아님 |
| packages/dns_security_package/dns_security_package/dns_security/detector.py | 공급 scaler 적용/INT8 추론. FQDN extractor 아님 |
| packages/dns-security-ai/src/dns_security_ai/contracts.py::DNSFeatureContract | 정확한 이름/순서, schema cic-bell-dns-stateless9-v1, numeric/nonnegative/finite/float32 범위 검증 |
| 같은 패키지 feature_contract.json | 9개 모두 unit 및 upstream extraction UNVERIFIED, raw_domain_extractor 미구현 |
| 같은 패키지 preprocessing.py::quantize_input | named float32 DataFrame→저장 StandardScaler.transform→scale/zero-point→round/clip→INT8 |
| scripts/verify_dns_legacy_parity.py | 공급 detector와 신규 quantization의 synthetic 입력 비교. 원천 DNS Feature Producer 검증 아님 |
| reports/Security_AI_Integration_Report.md DNS Model Review | DNN training/export, 실제 DNN dataset pairing, train-only scaler fit UNVERIFIED 기록 |

Notebook에서 참조한 원천 DNS CSV와 PCAP/원문 Query의 Golden Pair는 로컬 조사에서 발견하지 못했다.
통합 보고서의 기존 모델 추론 성공은 이미 생성된 Feature를 넣은 증거이며 원천 Feature 정합성 증거가 아니다.

### 공식 Dataset 및 생성 논문

- [UNB CIC-Bell-DNS-EXF-2021](https://www.unb.ca/cic/datasets/dns-exf-2021.html), 2026-10-13 열람:
  Table 1의 feature 정의와 packet 기반 dataset 설명을 확인했다.
- 생성 논문: Mahdavifar et al., *Lightweight Hybrid Detection of Data Exfiltration using DNS based on Machine Learning*, ICCNS 2021,
  DOI [10.1145/3507509.3507520](https://doi.org/10.1145/3507509.3507520).
  publisher 본문 접근은 실패했고 [저자 게시 full text](https://www.researchgate.net/publication/359077112_Lightweight_Hybrid_Detection_of_Data_Exfiltration_using_DNS_based_on_Machine_Learning)의
  Dataset/Experimental Results/Table I 내용을 확인했다.
  논문의 자체 DNS extractor와 packet→CSV 설명은 확인했지만 소스 revision/configuration을 확보하지 못했다.
- 논문의 DNSExfiltrator GitHub 참조는 공격 traffic 생성 도구다. DNS9 Feature Producer로 취급하지 않는다.
- 별도 CIC-Bell-DNS2021 또는 제3자 extractor를 EXF-2021 producer로 대체하지 않았다.

## 2. Feature별 정의와 검증 상태

공식 Table 1 의미는 아래와 같다. 모든 입력은 설명상 query/FQDN 계열이지만,
원천 wire field에서 실제 producer가 읽은 문자열 표현·정규화·CSV 행 연결은 미확인이다.

| 순서/Feature | 문서에서 확인한 의미 또는 수식 | 정확한 계산 구현에 남은 문제 | 계산·Golden 상태 |
|---|---|---|---|
| 0 FQDN_count | FQDN의 문자 수 | trailing dot/escape/Unicode/IDNA/bytes 대 characters | UNVERIFIED / 없음 |
| 1 subdomain_length | subdomain의 문자 수 | subdomain 경계·등록 도메인·suffix 처리 | UNVERIFIED / 없음 |
| 2 numeric | 숫자 문자 개수 | ASCII/Unicode 판별 및 대상 문자열 | UNVERIFIED / 없음 |
| 3 entropy | H(X) = −Σ p(x) log₂ p(x), X는 query name | log₂는 확인됨; case/byte/Unicode/normalization/빈 입력 처리 미확인 | UNVERIFIED / 없음 |
| 4 special | 특수 문자 개수 | 전체 character set 및 dot/escape 처리 | UNVERIFIED / 없음 |
| 5 labels | dot로 나뉜 label 수 | empty label/trailing dot/root 처리 | UNVERIFIED / 없음 |
| 6 labels_max | 최대 label 길이 | label parsing과 길이 단위 | UNVERIFIED / 없음 |
| 7 labels_average | 평균 label 길이 | empty label 포함 여부 및 분모 | UNVERIFIED / 없음 |
| 8 len | domain/subdomain 길이 | FQDN_count와의 차이 및 동일 문자열 여부 | UNVERIFIED / 없음 |

위 공식 의미/entropy 식의 출처는 [UNB Feature Table](https://www.unb.ca/cic/datasets/dns-exf-2021.html)이다.
이름으로 추론한 계산식은 추가하지 않았다. 8개 항목의 실행 가능한 정확한 공식은 아직 확보되지 않았다.
Entropy도 식만 확인됐고 실제 학습 입력 표현/producer parity는 검증되지 않았다.
이전 로컬 feature_contract.json의 UNVERIFIED를 조용히 수정하지 않았다.

### 타입·단위·전처리·결측 처리

9개 모두 현재 공식 패키지 입력은 float32, 유한한 비음수 값이며 missing은 reject다.
원천 CSV의 실제 dtype, 계산 단위 및 producer commit은 학습 연결 자료가 없어 미검증이다.
패키지의 numeric contract가 count의 integer constraint나 원천 계산 의미까지 증명하지 않는다.

검증된 배포 전처리: named numeric9→float32→저장 StandardScaler→manifest quantization으로 INT8.
Scaler 검증은 9개 이름/순서, mean/scale/var/with_mean/with_std, n_samples_seen_=162880을 검사한다.
샘플 수가 Notebook split 수와 부합해도 train-only fit 또는 동일 학습 실행을 증명하지 않는다.
Scaler fitting 및 DNN calibration/training/export 순서는 원본 코드가 없어 UNVERIFIED다.

논문/공식 Dataset의 analysis는 NaN→0 처리 등을 설명한다. 이는 현재 공급 DNN의 전처리 증거가 아니며,
현 DNSFeatureContract의 nonfinite/missing reject를 zero imputation으로 바꾸지 않았다.
Notebook cell 5는 missing 개수를 출력하고, 확인한 학습 경로에는 원천 Feature 생성/명시적 imputer가 없다.

## 3. 원본→모델 연결의 확인 수준

```text
DNS wire/query/FQDN (실제 자료·정규화 미확보)
  → original producer (code/revision/config 미확보)
  → stateless9 CSV (Notebook은 이미 생성된 파일을 읽음)
  → selected 9 columns (이름·순서 확인)
  → supplied DNN training/scaler/export (학습 pairing 미확인)
  → float32 / saved scaler / INT8 model input (배포 코드 확인)
```

공식 자료의 packet 단위 설명은 확인됐지만 원본 packet과 모델 학습 row를 식별하는
안정적인 ID/timestamp/packet index 및 source digest 대응표는 확보하지 못했다.
FQDN 문자열이 같아도 서로 다른 query/event를 병합하지 않는다.
Source ID/Incident를 가진 declared row 연결은 학습 Golden Pair의 대체물이 아니다.

## 4. 검증 가능한 부분 구현

신규 `src/soc_agent/security_ai/operational/dns_records.py`:

- `ReportedDNSFeatures`: 별도 soc-reported-dns-features:v1. 명시적인 Incident,
  SourceIdentity/Event ID/source digest, claimed producer name/version, schema/order/digest,
  bounded canonical numeric JSON을 보존한다. producer claim을 attestation으로 취급하지 않는다.
- `validate_reported_dns()`: expected source/row digest와 Incident를 대조하고 실제
  OperationalSourceStore.load()로 저장 원본을 확인한다. 9개 공식 DNSFeatureContract 및
  reviewed_binding("litert")의 Feature Identity를 독립적으로 대조한다.
- dictionary key와 공식 ordered_features 양쪽 확인, 문자열/bool/null/container/negative/nonfinite/overflow 거부.
  원문 Query/시각을 바꾸면 source digest가 달라진다. 숫자를 채우거나 도메인에서 Feature를 생성하지 않는다.
- `DNSInputReceipt`: 공식 matrix의 little-endian float32 SHA, rounding/underflow로 값이 달라진 필드,
  9개 각각 DOCUMENTED_SEMANTICS_INCOMPLETE/UNVERIFIED producer/calculation/golden 상태 반환.
- `compare_dns_rows()`: 동일한 저장 원본에 연결된 reference/candidate의 source/row pins를 각각 검증하고,
  9개 Feature의 절대·상대 오차, numeric equality, float32 bit equality와 변환 손실을 비교한다.
  Network compare_exports.py의 `_number()`/`_difference()`/FeatureDifference를 재사용하며 기존 도구는 수정하지 않았다.
- 비교 허용 오차는 0. 숫자 차이가 float32에서 사라져도 FAIL이며 reference 0의 비일치 상대 오차는 None.

상태는 항상 다음을 유지한다:

- validation_status: NUMERIC_AND_DECLARED_SOURCE_LINK_ONLY
- source_assurance: DECLARED_UNATTESTED
- 모든 계산/producer/golden 상태: UNVERIFIED
- training_parity_status: INCONCLUSIVE
- inference_status: NOT_INFERABLE
- write_disposition: WRITE_DENIED

수치 PASS는 **명시적으로 연결한 두 숫자 행의 일치**만 의미한다.
원본의 진위/추출 정확성을 증명하지 않으며 외부 모델/Context/Agent/Approval로 보내는 API는 없다.
Operational provenance:v3, synthetic context:v2 및 Source Store는 변경하지 않았다.
Receipt/JSON을 기존 v2 Adapter에 넣어 INVALID로 거부되는 실제 계약 테스트를 추가했다.

## 5. 검증

신규 DNS 테스트는 실제 source store SQLite + 공식 DNSFeatureContract를 사용한다.
Query/Feature 값은 인공 Fixture이며 실제 수집/Golden Pair/실제 모델 추론 테스트가 아니다.

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q \
  tests/unit/operational_features \
  tests/unit/security_ai/external tests/unit/external_context \
  tests/integration/external_read_only_backend/test_guard.py
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check .
git diff --check
```

테스트 범위: 정확한 9개 이름/순서·matrix SHA, 잘못된 scalar/negative/nonfinite/overflow,
Source/Event ID/Incident 충돌, source/row digest 변조, 저장 원본 누락·변조,
원문 Query/시각 변경, explicit reference/candidate numeric mismatch/float32 차이,
JSON 임의 필드/권한 위조, serialization 오류, 합성 v2 혼입 차단.
기존 Network 비교, operational provenance:v3, Source Store, v2 Adapter/Context,
실제 READ-only Backend Guard 회귀를 함께 실행한다. Guard 자체를 Mock으로 대체하지 않는다.

최종 실행: 신규 DNS 테스트 **25개** 포함 **321 passed, 0 failed**, 32.01초.
로그 `/tmp/soc-dns-regression.log`. 초기 DNS 22개 실행과 합산하지 않는다.
Ruff src/tests PASS, Format 전체 718 files PASS, git diff --check PASS.
기존 통합 manifest 33/33, realtime manifest 16/16 SHA 일치.
Network compare_exports.py, OperationalSourceStore, provenance.py는 HEAD 내용과 동일하다.
보호 tests/fusion_support.py SHA
`e5f9d10f706f71b82e80261f7633a1504e27ba24499be948d04adb6eeb3a21c9` 유지.
시작 Git 상태의 기존 항목은 제거/변경되지 않았고 신규 파일은 소스·테스트·이 보고서 3개뿐이다.
전체 회귀, Windows Native, 실제 DNS 데이터/모델 추론, Agent E2E는 이번 단계에서 실행하지 않았다.

## 6. 남은 자료와 독립 다음 작업

필수 확보 자료:

1. 실제 DNS extractor source commit/binary hash 및 설정/실행 명령.
2. query_name decoding, case/IDNA/Unicode/escape/trailing dot, numeric/special 집합,
   subdomain 분리·suffix 규칙 및 빈 값 처리의 실제 구현.
3. 승인된 원본 PCAP/Query 기록↔stateless Feature CSV golden pair,
   packet/event 식별 키, UTC 시간·source/CSV digest 대응.
4. 공급 INT8 DNN과 Scaler의 학습 dataset/split/fit/export/calibration 기록.

독립적으로 진행할 다음 단계는 **P1 Authentication 실제 OS 로그 연결**이다.
기존 AuthenticationEvent/5분 집계/OperationalSourceStore를 재사용하고,
승인된 Windows/Linux 원본 로그의 성공/실패 필드·시각·stable source ID·접근 권한 계약을
먼저 확인한 뒤 읽기 전용 parser와 Collector→intake 연결 테스트를 추가한다.
일반 OS 메타데이터로 성공/실패를 추정하지 않고, 권한이 없는 채널은 명시적으로 제한 상태로 둔다.
실제 로그 Evidence provenance 및 Incident association 검증 전에는 모델/Agent 권한을 발급하지 않는다.
이 P1 작업은 DNS/Network Feature Producer 확보와 독립적이며 이번 요청에서는 시작하지 않았다.
