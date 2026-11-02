# 운영 한계와 남은 검증

현재 Research MVP는 제한된 실환경 성공과 실패가 함께 존재한다. 상용 무인 SOC로 판정하지 않는다.

| 항목 | 현재 판정 |
|---|---|
| 제한 Native Packet/DNS 수집, Window·Attestation | 과거 제한 Scope VERIFIED_NATIVE |
| Native RF/LR/Incident/Orchestration | 과거 제한 Scope 성공. 최근 서비스 Worker 실패와 구분 |
| 최근 약6분 수집 | 최종 seal 기준361.395650895초. 전체 GUI/모델은 실패 |
| 최근 설치 실패 | 8경로 중3변경을4로 검사한 코드 결함. 설치 전 차단, 수정본 비권한 회귀 |
| 모델 서비스 실패의 정확한 원인 | UNKNOWN. 호스트 보존 입력 성공은 서비스 해결 증거 아님 |
| Heartbeat 송신 공백의 근본 원인 | UNKNOWN. 과거 증거 보존 |
| 실제 LLM Plan | 과거 VERIFIED_API |
| 실제 LLM Assessment | 과거20초 Timeout, 성공 미검증. Usage 미수신 비용 UNKNOWN |
| Native 20분/1시간 안정성 | 미완료 |
| 글로벌 Kernel Cleanup | UNKNOWN/UNVERIFIED. 소유 범위 결과로 확대 금지 |
| 실제 Host Authentication IF 전체 E2E | 미검증 |
| DNS9 원본 학습 추출 계약 | 미완성, 추론 차단 |
| 새 Native Session 자동 준비/회전 | 미완료. 기존 일회성 review 등록 필요 |
| 설치 Release 완전 분리 | 별도 운영 Worktree 사용. editable 환경이므로 불변 설치 배포는 미완료 |
| 단일 GUI exact 모델/API 검토 | 비권한 구현/회귀. 실제 새 Native 실행은 별도 |

이전 Session의 PENDING·POISON은 삭제·재처리하지 않는다. 기존 Ledger 81행, 과거 FAILED/false/UNKNOWN/UNVERIFIED, 설치본·Rollback·원본 Audit는 유지한다. 신규 테스트는 격리된 저장소에 쓴다.

실패를 가리기 위한 Timeout 증가, 승인 범위 확대, 자동 모델 교체, API 반복 요청, Root Helper 우회 실행을 하지 않았다.

이번 비권한 실제 CLI Replay에서 Runtime 오류 없이120초 정상 Stop/PENDING13 보존, 후속 격리 복구75.809초/DONE36/새 Prediction22/소유 Runtime Cleanup VERIFIED와 실제 GUI 재연결을 확인했다. 복구 대상의 중간 디렉터리0755 결함은 최소 수정했다. 이를 Native 20분 성공으로 표시하지 않는다.

추가 발견한 제한 Planner Schema identity 결함은2064af1로 수정했다. 실제 보존 모델 결과·Native DNS 메타데이터와 FAKE_HTTP 조사 E2E가 통과했으나, 실제 Provider의 Plan/Assessment 성공은 여전히 별도다. 현재 범위는 Native20분·1시간이나 반복 Session 자동 준비의 완료가 아니다.
