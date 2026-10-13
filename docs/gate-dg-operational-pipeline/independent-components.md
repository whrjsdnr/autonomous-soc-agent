# Gate D/G 독립 운영 구성요소 검증 — 2026-10-13

판정: **독립 입력·집계·Provenance 구성요소 구현 및 집중 검증 완료**.
운영 Feature → 외부 AI → Agent E2E는 **BLOCKED**를 유지한다.
이번 결과는 실제 OS 이벤트의 진위, 운영 배포, 운영 모델 호환성 PASS가 아니다.

## 1. 기준선과 보호

- 브랜치 main, HEAD `a0169285840de6a8107fd1509480dd3cb9af0dcf` 유지.
- 시작 상태 `/tmp/soc-independent-before.txt`: 기존 README.md,
  docs/soc-command-center.md, pyproject.toml 수정 및 기존 미추적 파일 보존.
- ML 원본 저장소 읽기 전용; Notebook은 JSON의 source 셀만 읽었고 실행하지 않았다.
- 기존 합성 전용 `soc-external-model-context:v2`, Fusion v1,
  Decision/Approval/Policy/Capability, 모델/Fixture/Selection Digest를 변경하지 않았다.
- 통합 changed-files.json 33/33, realtime windows-sync.json 16/16 현재 SHA 일치.
- 보호 파일 tests/fusion_support.py SHA:
  `e5f9d10f706f71b82e80261f7633a1504e27ba24499be948d04adb6eeb3a21c9` 유지.
- Git commit/tag/push, 운영 DB Migration, 외부 LLM, 실제 보안 WRITE 미실행.

## 2. 학습 Feature Producer 재조사

아래 경로는 `/home/geonug/kdt-linux/ML` 기준이다. 셀 번호는 Notebook JSON
cells 배열의 0-based index이며 출력 셀·저장된 실행 결과를 재실행 증거로 사용하지 않는다.

| 실제 자료 | 확인된 처리 | 확인되지 않은 사항 |
|---|---|---|
| README.md Dataset 절 | Network CSE-CIC-IDS2018, DNS CIC-Bell-DNS-EXF-2021 명칭 | 학습 원본 dataset release/checksum 및 producer와의 확정적 연결 |
| notebooks/preprocessing.ipynb cells 67/68 | feature_importance_full78.csv를 읽고 head(40)의 feature 컬럼을 Top40 목록 CSV로 저장 | 78개 원천 컬럼 계산 구현. 중요도 선택은 패킷 특징 생산이 아님 |
| notebooks/dnn_top40_v4.ipynb cells 0/1/43 | 기존 Top40 CSV의 순서, 기존 Parquet에서 40개 컬럼 선택; float32 변환, nonfinite→NaN, StandardScaler.partial_fit 및 추론 transform | 원천 PCAP→Flow→40개 계산식/단위/producer 설정 |
| reports/CIC-Bell-DNS-EXF-2021_DNS_Security_EDA.ipynb cells 4/7/10 | stateless_features-*.pcap.csv를 pandas.read_csv로 읽어 기존 컬럼 분석 | `.pcap.csv`는 CSV이며 PCAP parsing 코드가 아님 |
| reports/CIC-Bell-DNS-EXF-2021_DNS_Security_ML.ipynb cells 2/5 | 기존 CSV 읽기 및 FQDN_count/numeric/entropy 등을 포함한 9개 컬럼 선택 | FQDN에서 9개 수치를 생성하는 함수 |
| packages/dns-security-ai/src/dns_security_ai/feature_contract.json | 9개 unit 전부 UNVERIFIED, raw_domain_extractor 미구현 명시 | entropy base, numeric/special 의미, query aggregation 등 |

CSV/Parquet 읽기·전처리·Feature Selection과 **원천 데이터 Feature Producer는 다르다**.
공식 Top40 이름/순서는 이전 검토 결과를 유지한다. 이름에서 수식이나 CIC 버전을 추정하지 않았다.
DNN 전처리에서 nonfinite를 다루는 기존 학습 코드도 운영 입력을 임의로 채우는 근거로 사용하지 않는다.
ML README의 DNS 향후 계획 표현과 실제 DNS 패키지 존재는 서로 시점이 다른 자료로 취급한다.
원천 producer의 commit/version/config, 승인 PCAP/CSV 또는 DNS record/feature golden pair는 확보되지 않았다.

## 3. 단계별 구현과 재사용

### Authentication

`source_records.py::AuthenticationSource`는 기존 AuthenticationEvent를 그대로 포함한다.
Header/Event의 Event ID와 UTC 발생 시각이 다르면 거부하며 success/failure를 임의 추정하지 않는다.
OS 로그 파서는 추가하지 않았다. 테스트는 명시적으로 구성한 구조화 입력이다.

`source_store.py::OperationalSourceStore`는 기존 GovernanceDatabase의 SQLite Transaction과
Secure Storage를 재사용하는 **별도 격리 입력 DB**다. Core 사건 DB를 채택하거나 Migration하지 않는다.
독립 operational_source_config 버전은 1이며 재개 시 capacity/lateness/skew가 저장 설정과 달라지면 거부한다.
사용자 DB 경로를 받아 기존 DB를 자동 생성·변환하지 않으며 create()는 존재하는 파일을 거부한다.

기존 AuthenticationWindowExtractor/create_feature_set 경로가 실제 300초 UTC epoch 정렬
[start,end) 계정별 창의 성공/실패/총횟수, failure_rate, 초당 login_attempt_rate를 계산한다.
새로운 모델/집계 수식을 추가하지 않았다. FeatureSet의 incident_id는 None이다.
Header Incident ID는 **로컬 staging 연결 식별자**이며 실제 SOC Evidence/Incident 검증을 통과했다는 의미가 아니다.
실제 IncidentState나 Evidence를 만들어 기존 extractor의 source 검증을 우회하지 않는다.

- 중복: SourceIdentity(namespace,generation,record_id) 및
  (namespace,generation,event_id) 모두 확인; 정확히 같은 재전송은 기존 결과 반환,
  같은 식별자의 다른 내용/다른 사건은 충돌 거부. 인증 Event ID는 계정 창 집계에서 기존 중복 규칙 유지.
- 지연: incident별 accepted authentication 최대 event time이 watermark다.
  명시적 allowed_lateness_seconds보다 이전이면 LATE_QUARANTINED로 원본 보존하고 집계에서 제외.
  정확한 경계는 허용한다. DNS/Network 이벤트가 인증 watermark를 이동시키지 않는다.
- 허용 지연 안의 새 이벤트는 해당 창을 재계산한다. 고정 창 종료/외부 알림 발행 프로토콜은 없다.
- 수신 시각과 max_future_skew_seconds를 비교한다. 테스트 설정은 60초 지연/5초 skew이며 운영 기본 정책을 주장하지 않는다.
- 소스, watermark, 집계는 단일 SQLite Transaction. 집계 중 실패하면 전체 admission rollback.
- 재개 시 원본 digest/row digest, watermark와 accepted source 최대시각, 창 key/전체 coverage,
  실제 원본에서 재계산한 feature/provenance를 검증한다. 창 누락·변조는 거부한다.
- 변경 없는 창은 기존 created_at과 payload를 보존한다. factory의 계산 시각만 재검산 비교에서 제외하며
  원본 이벤트 시각/발생 순서/Feature/Source Provenance는 제외하지 않는다.
- Bounded capacity는 retained source 전체에 적용한다. 꽉 차면 거부하고 자동 삭제하지 않는다.
  장기 retention/아카이브·Collector cursor와의 연결은 후속 작업이다.

### Network/DNS 원본 경계

`NetworkFlowSource`: TCP/UDP/ICMP, 명시적 두 endpoint, IP family 및 port 관계,
원본 start/end/observation time, 선택적인 reported_packet_count를 검증한다.
endpoint A/B를 Fwd/Bwd라고 재해석하지 않는다. Packet 길이/IAT/Window/Top40은 계산하지 않는다.

`DNSQuerySource`: query name/type/class/transaction ID, source/header를 검증한다.
원문 대소문자/Unicode/trailing dot를 보존하고 IDNA 변환이나 DNS9 계산을 하지 않는다.
DNS wire parser/완전한 도메인 해석기가 아니라 제한된 구조화 query 입력 경계다.
원문 payload/인증 토큰을 수집하지 않으며 잘못된 endpoint 오류에도 입력 문자열을 출력하지 않는다.

동일 저장소에서 Network/DNS 중복·digest·incident·timestamp·재시작 검사를 수행한다.
Source digest는 **구조화 계약 전체의 canonical content digest**다.
원본 PCAP bytes/OS 로그 bytes의 인증 digest로 표현하지 않는다.

### 운영 Provenance

`provenance.py::OperationalProvenanceReceipt` 버전은
**soc-operational-provenance:v3**다. External Context v3 또는 v2 대체 타입이 아니다.
`build_receipt()`/`verify_receipt()`는 실제 저장된 source와 인증 snapshot을 다시 조회하여
incident/source/time/collector identity/digest 및 feature chain을 대조한다.

- source_assurance: DECLARED_UNATTESTED
- validation_status: SOURCE_CHAIN_VALIDATED_UNATTESTED
- rule_status: 인증 feature를 포함하면 VERIFIED_INTERNAL_AUTH_CALCULATION, 그렇지 않으면 UNVERIFIED
- inference_status: NOT_INFERABLE (모든 경우)
- model_result: None (다른 값 거부)
- write_disposition: WRITE_DENIED

인증 FeatureLink는 기존 extractor 이름/버전/계산 코드 reference, schema,
input fingerprint, 계산 시각, window digest를 보존한다.
SourceLink는 original Event ID/SourceIdentity/collector/version/time/content digest를 보존한다.
실제 source 진위를 검증한 서명/attestation이 아니다.
Receipt의 digest를 재계산한 공격도 verify_receipt에서 저장 원본과 다르면 거부한다.
Digest만으로 진위나 학습 Feature 계산 parity를 증명하지 않는다.
외부 모델 결과 또는 Capability/Approval 생성 API는 없고, 기존 v2 Adapter가 이 receipt와 JSON을 INVALID로 거부한다.

## 4. 테스트 증거

WSL 프로젝트 Python 3.12.14, pytest 9.1.1, Ruff 0.16.7.

| 실행 단계 | 결과 | 증거 |
|---|---|---|
| 인증 입력·집계·복구 최소 테스트 | 7 passed | /tmp/soc-independent-auth.log |
| Network/DNS 경계 및 인증 회귀 | 20 passed | /tmp/soc-independent-raw.log, hardening.log |
| Provenance 추가 후 operational 집중 | 63 passed (이전 단계 27개 포함) | /tmp/soc-independent-provenance.log |
| operational + 기존 인증/Adapter/Context/실제 Read-only Backend Guard/Policy/Approval | 377 passed, 0 failed | /tmp/soc-independent-regression.log |
| 최종 원자적 read/write 검사 및 민감 입력 오류 보호 수정 후 operational 집중 | **67 passed, 0 failed** | /tmp/soc-independent-final.log |

67개 중 이번 추가 테스트는 40개, 이전 구현 테스트는 27개다. 서로 겹치는 실행 횟수를 합산하지 않는다.
377개 회귀 이후 변경은 새 source store의 integrity 조회를 admission transaction 안으로 이동,
새 endpoint의 오류 메시지 보호 및 관련 테스트 추가다. 기존 Core/Guard 소스는 변경되지 않았다.

주요 테스트: 정상/잘못된 입력, source identity/digest/incident/time 충돌, bounded capacity,
창 경계/지연 격리, Network/DNS와 인증 시간 분리, DB 재개, 저장 source/window/watermark 변조,
재해시된 잘못된 feature counts, missing window, transaction rollback,
중복 provenance, JSON 상태/권한/model_result 위조 및 기존 합성 v2 호환성.
기존 실제 Guard 회귀는 Guard를 Mock으로 바꾸지 않고 READ stub/WRITE spy로 검증한다.
SQLite 테스트는 실제 격리 파일이다. 프로세스 kill/장시간 운영/Native OS source 테스트는 이번 실행 범위가 아니다.

재현 명령:

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q \
  tests/unit/operational_features \
  tests/unit/security_ai/authentication tests/unit/security_ai/external \
  tests/unit/external_context \
  tests/integration/external_read_only_backend/test_guard.py \
  tests/unit/policy tests/unit/approval
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check .
git diff --check
```

최종 정적 검사: Ruff src/tests PASS, Format 전체 712 files PASS, git diff --check PASS.
전체 회귀 및 실제 모델 E2E는 반복 실행하지 않았다. Windows Native/별도 Linux 호스트 검증은 미실행이다.

## 5. 이번 변경 파일

신규 소스:
- src/soc_agent/security_ai/operational/source_records.py
- src/soc_agent/security_ai/operational/source_store.py
- src/soc_agent/security_ai/operational/provenance.py

신규 테스트:
- tests/unit/operational_features/test_auth_source_store.py
- tests/unit/operational_features/test_raw_sources.py
- tests/unit/operational_features/test_operational_provenance.py

기존 직전 작업 테스트의 최소 확장:
- tests/unit/operational_features/test_adapter_boundary.py (운영 receipt의 v2 혼입 차단 추가)

신규 문서:
- docs/gate-dg-operational-pipeline/independent-components.md

이전 network_records.py와 원래 계약 검토/보고서는 보존한다. 기존 사용자 수정 3개에는 손대지 않았다.

## 6. 결과와 다음 단계

| 영역 | 구현 | 자동화 | 실제 원천 검증 | 운영 AI 추론 |
|---|---|---|---|---|
| 구조화 인증 intake/5분 집계/재개 | 완료 | PASS | 미실행 | NOT_INFERABLE; 내부 계산은 검증됐지만 출처 미인증 |
| Network/DNS 원본 계약·중복·재개 | 완료 | PASS | 미실행 | NOT_INFERABLE |
| 별도 provenance:v3 연결 검증 | 완료 | PASS | 실제 Collector attestation 미확보 | 권한 발급 없음 |
| PCAP→Top40 / FQDN→DNS9 | 보류 | 계산 테스트 불가 | 학습 producer 미확보 | BLOCKED |
| 운영 AI→External Context→Agent | 보류 | 새로운 운영 E2E 미실행 | 미검증 | BLOCKED |

필요 자료/작업:
1. 학습 CICFlowMeter source commit/version/config와 원천 PCAP↔학습 CSV golden pair 및 dataset release/checksum.
2. DNS9 실제 producer 함수/버전/정규화·단위·집계 정의와 FQDN/Query↔feature golden pair.
3. 승인된 실제 인증 기록과 플랫폼별 성공/실패 필드, 시간/중복/접근 권한 계약.
4. 실제 Source attestation/Collector cursor/incident evidence reference 연결 검증.
5. 그 뒤에만 운영 Feature/Artifact/Model Result chain 및 advisory Context/Runtime 연결을 검토한다.
   기존 synthetic v2의 assurance를 조용히 변경하지 않는다.

운영 수집기의 source authority, 모델 연계, Runtime 실행, 신규 위험 점수/자동 심각도/대응 권한은 추가하지 않았다.
이번 단계의 안전한 독립 개발은 완료했고, 모델 호환성/E2E 차단은 유지한다.
