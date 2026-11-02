# 실행 승인 UX와 유지되는 권한 경계

## 문제 분류

| 문제 | 분류 | 처리 |
|---|---|---|
| Namespace 진입·TCX 부착·Root 설치·R1 수용 | 실제 보안상 필요한 인간 결정 | 직접 Scope 확인과 OS sudo 인증 유지 |
| Source/Artifact SHA 수동 복사 | 불필요한 수동 절차 | 기존 verify_review/validate_plan이 내부 비교. 입력 요구 없음 |
| 변경 파일 4개 고정 assert | 구현 결함 | 정확한 고정/변경 경로 집합 검사로 수정 |
| 과거 Session 경로를 복사한 Launcher | Artifact·Session 관리 결함 | 기존 Artifact 수정 금지, 새 패키지의 경로와 pins 재결합 필요 |
| 정책 만료 | 필요한 권한 경계 | 새 제안은 승인이 아니다. 만료 정책 자동 연장 금지 |
| 매 모델 입력마다 별도 터미널 | 작업별 결정은 필요, 화면 분리는 불필요 | GUI에서 현재 작업들을 한 번에 보여주되 독립 Action 기록 |
| API가 실제 Incident보다 먼저 승인되는 문제 | Evidence Binding 조건 | Incident·Revision 고정 후 정확한 API 검토 |

## 실제 구현

`agent_review.pending_models()` → GUI 목록 → 명시적 yes → `approve_models()` → 기존 `ApprovalManager` → 기존 Worker가 소비하는 영수증.

화면에는 Session, 작업 ID, ELIGIBLE 수, 예상 호출 수, 모델 Fingerprint, 기존 승인 누계를 보여준다. 대화창 내부 digest는 프로그램이 계산한다. 사용자에게 SHA나 UUID를 입력시키지 않는다. 검토 후 입력이 바뀌면 승인하지 않는다. 실패한 작업을 승인 버튼으로 다시 실행하지 않는다.

`agent_api_review.prepared_api_review()` → GUI Incident/Revision·Provider/모델·비용·호출·Timeout 표시 → 명시적 yes → 기존 `APIRunAuthorization`. 자격 증명 로딩, API 호출, Root 명령은 이 코드에 없다. 이미 승인되거나 시도한 요청은 재발급하지 않는다.

A Native, B RF/LR, C API는 같은 GUI에서 볼 수 있으나 권한은 공유하지 않는다. 초기 A Scope 확인이 미래 B/C 작업의 인간 결정을 대신하지 않는다. R1 결정도 프로그램이 자동 수용하지 않는다.

## 대기와 오류

- 아직 Native RUNNING이 아님: `WAITING_RUNNING_NATIVE_SESSION`.
- 아직 실제 Incident에 결합된 API 요청 없음: `WAITING_EXACT_NATIVE_INCIDENT_API_REVIEW`.
- API 결과 없음: `WAITING_AUTHORIZED_API_RESULT`.
- 변경된 Evidence/Manifest/모델: BLOCKED. 이는 승인 대기가 아니라 무결성 실패다.

## 남은 연결

최종 v2 Launcher는 GUI의 exact authorization 파일을 기다리도록 준비했다. 실제 API 실행 검증은 별도다. 과거 private `run-api-followup.py`의 초기 Scope 기반 자동 발급 코드는 재사용하지 않는다. 기존 실행 패키지는 변경·재실행하지 않는다. 현재 1회용 profile/패키지 연결은 준비됐지만, 새 Session 자동 회전이 완료되기 전에는 반복 운영 UX 완료로 판정하지 않는다.
