# 운영 Provenance 확장 계획 — 미구현

기존 `soc-external-observation:v2` / `soc-external-model-context:v2`의 synthetic 의미는 그대로다.
새 intake `soc-reported-network-flow:v1`과 `soc-network-input-receipt:v1`은 숫자 검증 결과일 뿐,
External Context의 새 버전이나 inference authorization이 아니다.

## v3 후보 계약과 신뢰된 발급 경계

별도 reviewed 운영 observation/provenance version을 도입할 경우 다음을 담아야 한다.

- Source Identity, original Event ID / content digest / event time / collection time.
- Collector ID/version와 실제 source acquisition 경로를 확인한 receipt.
- Extractor ID/version, feature calculation time, 공식 ordered FeatureSchema identity.
- 계산 규칙 review ID/digest + producer version/config + golden-pair verification 근거.
- Original Evidence ID/digest와 정확한 IncidentAssociation/StateAnchor.
- 원본 source assurance와 feature semantic assurance를 분리. 미확인 값은 UNVERIFIED/INVALID.
- Feature input digest와 artifact/model identity. Native inference receipt는 이 경계를 재검증.

Digest equality는 content continuity만 확인한다. Producer 이름, JSON의 VALID flag 또는
자기 선언 review receipt는 실제 source authenticity/계산 정확성을 증명하지 못한다.
검증된 계산기와 trusted collector/승인된 오프라인 import factory만 운영 observation을 발급한다.
파일이 operator-approved라는 사실만으로 feature 계산이 검증되는 것도 아니다.

v2 타입을 synthetic=False로 바꾸거나 기존 digest를 재정의하지 않는다. 양 버전은 명시적
version dispatch와 각자의 typed validation을 사용해야 한다. 기존 v2 fixture/Golden/Selection
검증은 보존한다. 새로운 SOURCE assurance가 준비되지 않았으면 NOT_INFERABLE이고,
VALIDATED_FOR_ADVISORY를 발급하지 않는다.

## 변경 지점

1. `external/models.py`: 현재 DerivationProvenance.origin_assurance / observation.synthetic와
   ExternalModelResult.observation의 strict v2 타입 때문에 단순 flag만 추가할 수 없다.
2. `external/validation.py::validate_source/feature_input_digest/normalized_result`:
   original evidence, reviewed extractor calculation, incident/time/identity 및 version 교차 검증.
3. `external/service.py`/native worker: bounded typed request/receipt 양쪽 동일 version validation.
4. `external/assembly.py`/`projection.py`: verified-only results 사용, UNLINKED 제외,
   Quality/Edge 동일 관측 중복 방지, DNS 독립성, model text를 untrusted advisory로 유지.
5. Companion serialization/ResumeReceipt/RuntimeStore: 새 payload type 읽기/guard를 설계하고,
   legacy reader의 unsafe resume를 차단. 운영 DB 자동 migration은 하지 않는다.
6. `runtime_integration.py`/`runtime_guard.py`: 새 trusted lineage까지 재검증하되
   MODEL_FACT_PROMOTION / WRITE_DENIED / allowlist / context/session binding은 변경하지 않는다.

기존 AssessmentResult와 Decision payload/ID를 변경하는 방안은 제안하지 않는다.
운영 observation version 및 보존 reader 영향은 실제 extractor 규칙 검토 후 확정한다.
위 계획은 구현 완료나 새로운 운영 Context 검증 PASS를 의미하지 않는다.
