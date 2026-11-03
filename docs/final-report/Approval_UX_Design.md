# 승인 UX와 독립 실행 권한

## 문제의 분류와 처리

| 문제 | 분류 | 현재 처리 |
|---|---|---|
| Root 설치·Namespace 진입·TCX·R1 | 필요한 보안 결정 | 전경 Scope/R1·정책 결정과 직접 sudo 유지 |
| SHA·Session UUID 복사 | 불필요한 수동 절차 | 기존 hash 검사와 Session 생성 호출을 내부 조합 |
| 변경 수 4개 고정 assert | 구현 결함 | Root 고정/변경 경로 집합으로 검사 |
| 과거 Session 경로를 복사한 Launcher | Artifact 관리 결함 | 새 초안만 경로·파일 pins·Session을 재결합 |
| 정책 만료 | 필요한 시간 경계 | 새 정책 제안과 활성화 승인 분리 |
| 모델 작업마다 터미널 열기 | 화면 분리의 불편 | GUI에서 정확한 봉인 작업 일괄 검토, 독립 Action 기록 |
| API 입력 이전 포괄 승인 | Evidence 계약 위반 위험 | Incident·Revision 고정 후 별도 GUI 결정 |
| 승인 대기에 Worker 정지 | 정상 대기와 장애 혼동 | 기존 WAITING_EXACT_MODEL_ACTION_APPROVAL과 장애를 구별 |

## 기존 계약 재사용

- A: 기존 terminal.py → 직접 Scope/R1 → 독립 결정 기록 → OS sudo → 고정 Root verify_contract/Installer/Native Launcher.
- B: `agent_review.pending_models()` → GUI 검토 → `approve_models()` → 기존 ApprovalManager → 기존 Worker.
- C: `agent_api_review.prepared_api_review()` → 정확한 Incident/Revision·Provider·가격·비용·횟수 검토 → 기존 APIRunAuthorization → 승인 파일을 기다리는 기존 API runner.

A 화면에 B/C의 예정 범위도 보이지만 A 결정은 B/C 권한이 아니다. 현재 모델 계약은 미래 입력 범위 승인이 아닌 봉인 작업별 승인이다. GUI의 한 번의 확인은 표시된 작업 각각의 결정만 생성한다. 입력 digest는 프로그램이 계산하고 사용자가 입력하지 않는다.

LLM은 승인 API를 Tool로 사용할 수 없으며 Root·Native·DNS 실행 권한을 만들지 못한다. B·C의 승인 메서드도 모델 추론·API 호출·Root 명령을 직접 실행하지 않는다.

## 새 Session과 Release

`agent_release.register/installed`는 기존 review/파일 pins를 참조한다. `agent_release.prepare`는 기존 DNS Session·Continuous Store·Root Scope 바인딩을 호출한다. 새 실행은 기존 receipt와 runtime 디렉터리를 복사하지 않는다. 사람의 결정은 모두 PENDING이다. 제안 만료 시각 생성은 정책 활성화가 아니다.

정상 종료 후에도 Runtime cleanup만으로 다음 실행을 허용하지 않는다. 실제 terminal wait 결과, 최초 오류 없음, Helper final counter, TCX ACK에 대한 기존 Collector cleanup, Root 5개 unit 종료, Namespace 검사 결과를 함께 요구한다. 누락되면 자동 재시도하지 않는다. 과거 글로벌 Kernel UNKNOWN은 현재 소유 자원 판정과 분리한다.

## 대기 상태

`WAITING_RUNNING_NATIVE_SESSION`, `WAITING_EXACT_NATIVE_INCIDENT_API_REVIEW`, `WAITING_AUTHORIZED_API_RESULT`는 입력/권한 대기다. Source·Root·Feature·Fingerprint·Evidence 변경은 무결성 실패이며 BLOCKED다. GUI에는 Release·Session·무결성·권한 경계를 함께 표시한다.

정확한 실제 Live 승인과 비밀번호 인증은 이번 비권한 작업에서 수행하지 않았다. 현재의 GUI·Session 관리 검증을 새 Native/API 성공으로 표현하지 않는다.
