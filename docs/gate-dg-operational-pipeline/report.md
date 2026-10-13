# Gate D/G 운영 데이터 파이프라인 — Phase 1 및 Phase 2 최소 경계

2026-10-13. **전체 운영 Feature→AI→Agent E2E: BLOCKED / 미완료**.
학습 당시 Network/DNS feature 계산 규칙이 확인되지 않아 추측 계산/모델 실행을 하지 않았다.
Phase 1 조사는 완료했고, Phase 2에는 정의가 검증된 숫자 입력 경계만 구현했다.
PCAP Top40 extractor, FQDN DNS9 extractor 또는 운영 Provenance v3를 구현했다고 주장하지 않는다.

## 이번 실제 구현

- `src/soc_agent/security_ai/operational/network_records.py`:
  `ReportedNetworkFlow`는 source/event/time, 신고 collector/extractor, schema identity,
  canonical producer feature JSON을 보존한다. 신고된 이름은 신뢰 attestation이 아니다.
- `validate_reported_flow()`는 reviewed_binding과 공식 Top40Contract를 그대로 사용한다.
  정확한 40개 이름/순서, schema/digest, source content continuity, finite scalar,
  bool/string/None/container/missing/extra/overflow를 검증한다. 값을 채우거나 평균내지 않는다.
- 공식 float32 변환에서 바뀐 필드명과 little-endian matrix SHA를 기록하며, 원본 값은
  수정/반올림하지 않는다. 입력값 digest와 matrix digest를 분리한다.
- 반환 `NetworkInputReceipt`는 VALIDATED_NUMERIC_SHAPE / NOT_INFERABLE /
  REPORTED_EXPORT_UNATTESTED뿐이다. VFA, FeatureSet, ModelInput, Envelope, Context,
  Incident/Approval/Capability/DB write를 생성하지 않는다.
- Duration=0 신고 값은 수치 검사상 보존되지만 NOT_INFERABLE이다. Packet rate나
  IAT를 0으로 만들어 계산했다고 표시하지 않으며 forward/backward/flags/idle 수식을 구현하지 않았다.

## 테스트 및 범위

신규 테스트 27개: 공식 package metadata/matrix API, strict scalar/count/order,
float32 변경/overflow, source/feature 변조, 원본 identity/time 보존, extra VALID flag,
운영 origin을 v2에 넣는 위장 거부, 실제 SOC Adapter의 숫자 receipt→Evidence 거부.
실제 `ExternalEvidenceAdapter`와 외부 package 타입을 사용한다. 기존 synthetic positive
case는 수동 prediction fixture이며 native inference가 아니다. Guard를 mock하지 않는다.

실행:

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q tests/unit/operational_features
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q \
  tests/unit/operational_features tests/unit/security_ai/external tests/unit/external_context
```

- 첫 신규 최소 subset: **21 passed**, 0.48 s (추가 보안/Adapter 테스트 전).
- 최초 신규 26개 + 기존 Adapter/Context 회귀: **124 passed**, 1.40 s,
  `/tmp/soc-operational-regression.log`. 중복 실행 수치를 합산하지 않는다.
- 계산 정의 확인: local code, package resource/feature_contract.json, 보고서 및 notebook code
  cells를 읽기 전용 조사했다. Notebook 실행/훈련/모델 재생성/의존성 설치 없음.
- 실제 원천 PCAP/FQDN 데이터 계산: **NOT RUN / BLOCKED**.
- 신규 운영 source의 실제 모델 추론: **NOT RUN / BLOCKED**.
- 신규 운영 source의 Agent Assessment / E2E: **NOT RUN / BLOCKED**.
- 실제 Windows Native 또는 별도 Linux 운영 호스트: **NOT RUN**.
- 기존 Gate B/C native inference 증거는 참고이며 이번 운영 source 성공으로 재사용하지 않는다.

## 보존 및 영향

기존 소스/테스트/문서/DB schema/Runtime/Fusion/Policy/Approval/Execution Guard는 수정하지 않았다.
기존 Integration SHA pins 33/33과 Gate C manifest entries 16/16이 현재 파일과 일치한다.
기존 사용자 변경·미추적 파일, 보호 helper, 모델/Scaler/Golden/Selection Digest를 보존했다.
ML repo는 읽기 전용이며 운영 DB, privileged capture, 실제 WRITE, live provider를 실행하지 않았다.
commit/tag/push/브랜치 변경/Conda base 변경/전체 회귀 재실행 없음.

## 다음 단계에 필요한 자료

1. Network training producer(CICFlowMeter 계열)의 정확한 source commit/config 및 단위/flow
   split/std/header/flag/window/idle/zero-duration 규칙. 승인 PCAP→해당 producer CSV golden pair.
2. DNS upstream extractor source/version 또는 실행 가능한 specification와 FQDN/DNS query→
   9-column golden pair. entropy/length/numeric/special/IDNA 규칙 포함.
3. 인증 파이프라인용 승인된, 개인정보가 제거된 Windows Security export/Linux auth record
   계약과 샘플. 기존 Collector의 메타데이터만으로 로그인 성공/실패를 추정하지 않는다.

AuthenticationEvent/5분 집계 공식은 기존에 정의돼 있지만 운영 source mapping·재시작/지연
도착 정책은 별도 검증이 필요하다. 이번 첫 실행 범위에서 Phase 4를 선행 구현하지 않았다.
필요한 원본 정의 없이 Phase 3~7을 연결하는 일은 진행하지 않는다.

구체적인 파일 변경 순서는 phase-1-contract-review.md, version 확장 경계는
operational-provenance-plan.md에 기록했다. 정의가 확보되면 해당 계산기에 한정한 최소
extractor/golden test부터 진행하며 Orchestrator나 승인 엔진을 재구현하지 않는다.

## 최종 정적 검사

- `.venv/bin/python -m ruff check src tests`: PASS.
- `.venv/bin/python -m ruff format --check .`: PASS, 705 files.
- `git diff --check` 및 신규 파일 trailing whitespace 검사: PASS.
- 보호 helper SHA: `e5f9d10f706f71b82e80261f7633a1504e27ba24499be948d04adb6eeb3a21c9` 유지.
- HEAD/main과 시작 시점 사용자 status entries 불변. 신규 파일만 추가했다.
- 공식 40/9개 metadata identity와 계산 규칙 미검증 상태는
  `feature-contract-evidence.json`에 기록했다. 이는 Artifact 실제 파일 검증이나 모델 추론 증거가 아니다.

최종 타입 위조 거부 테스트를 추가한 뒤 아래 동일 집중 명령을 다시 실행했다.
신규 **27개**와 기존 Adapter/Context 회귀를 포함해 **125 passed**, 1.59 s,
`/tmp/soc-operational-regression-final.log`. 최초 124개 결과와 합산하지 않는다.
Ruff / Format(705 files) / Diff를 재확인했고 모두 PASS다.
최종 생성 파일은 소스 2개, 테스트 2개, 문서/계약 검토 JSON 4개다.
