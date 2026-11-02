# Native 20분 전체 통합시험 준비 및 DNS 상태 조회 격리

운영 코드 260e760. 직전 실제 시험은 약199.394초에 중단됐으며 Runtime 최초 오류는 CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT, 외부 관측 최초 오류는 RUNTIME_HEARTBEAT_STALE이다. Native Packet34·DNS Transaction3을 보존한다. TCX STOP ACK와 Runtime Cleanup은 UNVERIFIED, Helper와 Root 소유 범위 Cleanup은 VERIFIED이다. 전역 Cleanup과 원래 Heartbeat 지연 원인은 UNKNOWN이다.

확인한 결함은 Control 상태 생성 중 동기 DNS snapshot이 Reader lock·프로세스 상태 조회를 기다릴 수 있다는 것이다. 기존 저장 작업 경계에서 DNS 상태를 읽고 Control에는 관측 시각을 가진 표시 전용 cache를 전달한다. 2초 이상 지난 상태는 UNKNOWN_STALE_OBSERVATION이며 Cleanup VERIFIED로 사용하지 않는다. 실제 admission·Helper2초·Control5초 계약은 유지한다.

기존 코드에서 새 lock 경합 테스트는 DNS_STATUS_BLOCKED_EVENT_LOOP로 실패했고 수정본에서는 통과했다. 이는 코드 결함의 재현 증거이며 실제 실패의 단일 원인 확정은 아니다.

집중 회귀66 PASS. Workspace1445 PASS/1 SKIP, 독립 Export1445 PASS/1 SKIP. Native6·Supervisor2·Wheel을 Workspace 두 번과 Export에서 빌드하여 SHA 일치를 확인했다. Wheel SHA79d8ca3e20d5b47eef5cab5f93569404f31067186e3fdf1b873a62a6fa83550c. 증거는 .git/native20-failure-dns-status-rca-20261102T063540Z/에 보존한다.

이전 Installer 시간 상수 변환으로 파일0644가 잘못 변경된 결함은 실제 복구 시험에서 수정·설치 검증됐다. 현재8경로 모두0644이며 다음 시험은8경로 검증·백업, 새 Binding에 따른3개 내용 교체만 필요하다. 이전 실패 Session·영수증을 재사용하지 않는다.

사용자 요청에 따라 다음 시험은 Packet·DNS·GUI와 실제 RF/LR·Incident·SCRIPTED 조사·평가·Audit을 포함하는20분 전체 통합시험이다. 순수 수집 목표1200초, 전체 상한1800초, Window180초, 기존 자원·TCP8연결·DNS UDP2/TCP1 제한을 유지한다. 모델은 봉인하지 않으며 실제 Capture Window가 봉인되고 ELIGIBLE이 된 기존 작업에 정확한 별도 Action 승인이 있어야 추론한다. 신규 미래 작업에 대한 포괄 모델 승인은 발급하지 않는다.

GUI 필수 표시 항목은 이번 Session의 Packet·DNS·Control/Data Progress·Queue/Drop·Window/Quality/Eligibility·RF/LR Prediction/Latency·Incident·Investigation/Assessment·Audit·STOP/Cleanup이다. 필수 항목 누락은 전체 통합시험 실패로 판정한다. Authentication·DNS9·외부 LLM은 미실행임을 표시한다. Fixture와 과거 결과로 실제 값을 대신하지 않는다. GUI 화면 검증과 Backend/프로세스 검증은 구분한다.

실제 새 시험은 아직 미실행이며 정확한 Binding 검증·사용자 Scope 직접 확인·sudo 인증이 필요하다. 실패 시 자동 재실행하지 않는다. 기존 Ledger81행과 성공 Session PENDING2/POISON1은 보존한다.

## 실제 전체 통합시험과 저장 경합 후속 수정

49ef77b Binding의 실제 시험은 전체427.693초·봉인된 수집420.274초에 중단됐다. 최초 외부 오류는 DNS_RECEIVER_NOT_RUNNING_OR_PROVED_COMPLETE이며 Runtime 자체 last_error는 null이다. Packet54, DNS Transaction3, Window3 VERIFIED, ELIGIBLE5/INCOMPLETE2, Drop/SourceGap0이다. 별도 모델 작업 승인이 기록되지 않아 RF/LR0·모델 Incident0이며 전체 통합시험은 FAILED다. DNS SCRIPTED 조사 Task3은 실제 DNS 증거와 연결됐지만 Network 모델 검증을 대신하지 않는다.

TCX STOP ACK·Helper CLOSED/Counter/STOP ACK·Root 소유 Cleanup·Runtime Cleanup·Audit Flush는 독립 증거로 VERIFIED다. 기존 Ledger81행과 이번 Queue PENDING2/POISON1을 보존한다. 과거 동일 개수 Queue와 이번 Queue는 별도 Session이다. 전체 Root Audit Heartbeat 최대 간격1.281311초다. 정확한 오류 판정 시점의 DNS 상태 Snapshot은 저장되지 않아 그 값과 최초 느린 저장의 원인은 UNKNOWN이다. 저장 update 최대6.806728초와 DNS 상태 갱신이 같은 저장 순서를 기다리는 코드 결함은 확인했다.

운영 코드 db5e8dc는 DNS 상태 조회를 독립 비권한 관측 작업으로 분리한다. DNS 조회 자체는 별도 lock으로 직렬화·중복 제거하며 SQLite 순서를 기다리지 않는다. Control은 cache만 읽는다. 관측 신선도는 읽기 시작 시각으로 판단하므로 느린 조회가 오래된 상태를 새 상태로 갱신할 수 없다. 기존 Helper2초/Control5초와 실제 Reader admission은 유지한다. 관측 작업 실패와 종료 join을 보존한다.

기존 코드에서 실제 저장 경합 회귀는 UNKNOWN_STALE_OBSERVATION으로 실패했다. 수정본은6초 이상 저장 지연 중 DNS RUNNING/Control Heartbeat와 독립 STOP 전달, 느린 상태 조회의 신선도 만료를 검증했다. 최초 집중 테스트의 초기 관측 순서와 동일 조회 중복 문제를 수정했으며 기존 Assertion을 완화하지 않았다. 단독 CLI 시작 테스트의 일시적8초 입장 실패는 기존 제한 그대로 재검증했고 전체 회귀도 통과했다.

GUI의 DNS Query/Response 카운터가 그래프 입력 network 투영에 누락된 결함을 수정했다. 실제 카운터 차이로만 rate를 계산하고 누락값은 None으로 유지한다. DNS 요청이 끝난 뒤 실제 rate0은 정상이며 가짜 트래픽을 생성하지 않는다. 이 GUI 누락과 미승인 모델/Latency 누락으로 이전 시험을 성공 처리하지 않는다.

검증: 집중42 PASS, Workspace1449 PASS/1 SKIP, 독립 Export1449 PASS/1 SKIP. 추가 실제 Tk Continuous/Flow Eligibility 검증은 Workspace·Export 각각5 PASS이며 Fixture/REAL_MODEL/SCRIPTED 입력을 실제 Native로 보고하지 않는다. Ruff Check/Format/Diff 통과. Native6·Supervisor2·Wheel을 Workspace2회/Export에서 재현 빌드했다. 새 Wheel SHA3ec43692165d27a9de29c351d8d412f3d456b1a0302e3b77cf9d0483da2be8cf. 증거는 .git/native20-dns-storage-isolation-20261102T071948Z/에 보존한다.

다음 전체 Native 재시험은 새 Session·Binding으로 준비한다. Scope는 순수1200초/전체1800초, Root8경로 검증·백업/3개 내용 교체, TCP8연결·DNS UDP2/TCP1과 기존 자원 상한을 유지한다. 기존 봉인 작업별 Action 승인 도구를 실행 터미널에서 표시해 사용자 직접 yes를 받는다. 미래 작업 자동 승인·자동 재시도·종료 후 Retained 추론 대체는 허용하지 않는다. Launcher는 DNS 입장 검증 실패 시 해당 관측 값을 추가로 보존한다. 실제 재시험은 새 Scope 확인·sudo 인증 전까지 미실행이다.
