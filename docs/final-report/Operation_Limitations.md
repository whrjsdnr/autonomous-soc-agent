# 운영 한계와 남은 실제 검증

## 이번 변경의 범위

고정된 기존 Native Release의 자동 검증, 새 Session 초안 준비, 명시적 Update와 이전 profile 보관, GUI Session 선택, 정확한 모델/API 검토 UI를 비권한으로 통합한다. 관리 CLI는 별도 재현 Wheel에 고정한다. 사용자 SHA/UUID 입력은 필요하지 않다.

이는 새 Native 전체 E2E, 실제 외부 API, 장시간 운영 성공을 의미하지 않는다. 실제 실행에는 새 Scope/R1·정책·Root/Native/DNS 승인과 직접 sudo가 필요하다. 모델은 봉인된 ELIGIBLE 작업별 승인, API는 정확한 Incident/Revision 승인이 별도로 필요하다.

| 항목 | 판정/제한 |
|---|---|
| 제한 Native Packet/DNS·Window·Attestation | 과거 제한 Scope VERIFIED_NATIVE 유지 |
| Native RF/LR·Incident·Orchestration | 과거 제한 성공 보존. 최근 서비스 Worker 원인은 UNKNOWN |
| 최근 약6분 수집 | 최종 seal 기준361.395650895초; 전체 GUI/모델 성공과 다름 |
| Heartbeat 송신 공백 | 근본 원인 UNKNOWN. 과거 실패 증거 유지 |
| 실제 LLM Plan | 과거 VERIFIED_API |
| 실제 LLM Assessment | 과거20초 Timeout. Usage 미수신 비용 UNKNOWN; 새 API 성공 미검증 |
| Native20분·1시간 | 미완료 |
| Global Kernel Cleanup | UNKNOWN/UNVERIFIED. 소유 자원 결과로 확대 금지 |
| 실제 Host Authentication IF 전체 E2E | 미검증 |
| DNS9 원본 학습 계약 | 미완성, 실제 추론 차단 |
| 새 Session 준비·일회성 보호 | 비권한 검증. 실패/증거 누락 후 자동 재시도 금지 |
| GUI 재연결·이전 Session 조회 | Backend 조회; 실행·모델/API 권한을 부여하지 않음 |

현재 Installed mode는 검증된 **기존 고정 계약**을 재사용한다. 새 Namespace/Interface/Root 경로·트래픽·Deadline·추론/API 상한을 임의로 바꿀 수 있는 일반 배포 도구가 아니다. 기존 Ledger anchor가 바뀌면 새 검토가 필요하다. 상용 무인 운영이나 무제한 반복 실행을 지원한다고 주장하지 않는다.

기존 PENDING2·POISON1 및 다른 과거 Session의 미처리 작업은 삭제·재처리하지 않는다. 정상 Stop 후에도 현재 Queue의 미처리 수와 실패 수를 표시한다. Queue가 남으면 전체 작업 처리 완료가 아니다.

지난 비권한 PCAP Replay 결과는 Packet70·격리 복구DONE36/새Prediction22·소유 Runtime Cleanup VERIFIED다. 보존 Native DNS 메타데이터·모델 결과와 FAKE_HTTP 조사 E2E를 실제 신규 Native/API 성공으로 바꾸지 않는다.

현재 새 초안은 전체600초·순수 수집 목표360초·TCP<=4·DNS UDP2/TCP1·Queue32를 유지한다. B는 최대2개 봉인 작업/16회, C는 Plan/Assessment 최대2회/$0.05/20초/재시도0회다. API Key는 기존 안전한 설정에서 실제 승인 이후 읽는다. 모델 자동 교체와 임의 Timeout 증가는 없다.

기존 Ledger81행, Audit, 설치8경로, Rollback, 사용자 변경164개와 보존 증거2554개를 유지한다. 파일/권한 검사 실패는 BLOCKED이며 사용 편의를 이유로 무시하지 않는다.
