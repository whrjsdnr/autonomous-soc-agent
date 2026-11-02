# Native 20분 전체 통합시험 준비 및 DNS 상태 조회 격리

운영 코드 260e760. 직전 실제 시험은 약199.394초에 중단됐으며 Runtime 최초 오류는 CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT, 외부 관측 최초 오류는 RUNTIME_HEARTBEAT_STALE이다. Native Packet34·DNS Transaction3을 보존한다. TCX STOP ACK와 Runtime Cleanup은 UNVERIFIED, Helper와 Root 소유 범위 Cleanup은 VERIFIED이다. 전역 Cleanup과 원래 Heartbeat 지연 원인은 UNKNOWN이다.

확인한 결함은 Control 상태 생성 중 동기 DNS snapshot이 Reader lock·프로세스 상태 조회를 기다릴 수 있다는 것이다. 기존 저장 작업 경계에서 DNS 상태를 읽고 Control에는 관측 시각을 가진 표시 전용 cache를 전달한다. 2초 이상 지난 상태는 UNKNOWN_STALE_OBSERVATION이며 Cleanup VERIFIED로 사용하지 않는다. 실제 admission·Helper2초·Control5초 계약은 유지한다.

기존 코드에서 새 lock 경합 테스트는 DNS_STATUS_BLOCKED_EVENT_LOOP로 실패했고 수정본에서는 통과했다. 이는 코드 결함의 재현 증거이며 실제 실패의 단일 원인 확정은 아니다.

집중 회귀66 PASS. Workspace1445 PASS/1 SKIP, 독립 Export1445 PASS/1 SKIP. Native6·Supervisor2·Wheel을 Workspace 두 번과 Export에서 빌드하여 SHA 일치를 확인했다. Wheel SHA79d8ca3e20d5b47eef5cab5f93569404f31067186e3fdf1b873a62a6fa83550c. 증거는 .git/native20-failure-dns-status-rca-20261102T063540Z/에 보존한다.

이전 Installer 시간 상수 변환으로 파일0644가 잘못 변경된 결함은 실제 복구 시험에서 수정·설치 검증됐다. 현재8경로 모두0644이며 다음 시험은8경로 검증·백업, 새 Binding에 따른3개 내용 교체만 필요하다. 이전 실패 Session·영수증을 재사용하지 않는다.

사용자 요청에 따라 다음 시험은 Packet·DNS·GUI와 실제 RF/LR·Incident·SCRIPTED 조사·평가·Audit을 포함하는20분 전체 통합시험이다. 순수 수집 목표1200초, 전체 상한1800초, Window180초, 기존 자원·TCP8연결·DNS UDP2/TCP1 제한을 유지한다. 모델은 봉인하지 않으며 실제 Capture Window가 봉인되고 ELIGIBLE이 된 기존 작업에 정확한 별도 Action 승인이 있어야 추론한다. 신규 미래 작업에 대한 포괄 모델 승인은 발급하지 않는다.

GUI 필수 표시 항목은 이번 Session의 Packet·DNS·Control/Data Progress·Queue/Drop·Window/Quality/Eligibility·RF/LR Prediction/Latency·Incident·Investigation/Assessment·Audit·STOP/Cleanup이다. 필수 항목 누락은 전체 통합시험 실패로 판정한다. Authentication·DNS9·외부 LLM은 미실행임을 표시한다. Fixture와 과거 결과로 실제 값을 대신하지 않는다. GUI 화면 검증과 Backend/프로세스 검증은 구분한다.

실제 새 시험은 아직 미실행이며 정확한 Binding 검증·사용자 Scope 직접 확인·sudo 인증이 필요하다. 실패 시 자동 재실행하지 않는다. 기존 Ledger81행과 성공 Session PENDING2/POISON1은 보존한다.
