# Packet·DNS·RF/LR·GUI 전체 통합 재시험 결과

최종 판정: **FAILED_FULL_INTEGRATION / PARTIALLY_VERIFIED**. 요청된20분 수집·모델·GUI 전체 검증은 통과하지 못했다. 성공으로 보고하지 않는다.

## 실제 실행과 보존

| 시험 | 실제 HEAD | 전체 시간 | 봉인 수집 | Packet | DNS Transaction | Window | ELIGIBLE | RF/LR |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 최초 전체 통합 |49ef77b|427.693초|420.274초|54|3|3 VERIFIED|5|0|
| 수정 후 전체 통합 |aead2e9 / 운영db5e8dc|91.809초|85.896초|24|3|1 VERIFIED|2|0|

수정 후 Runtime Session은3e72e89c-fd41-409a-91f1-8453e8f28571, DNS Session은dfd8fd0e-e243-4872-b692-aa4889938cac이다. Namespace net:[4026532232]·lo/Ingress, 전체1800초/순수1200초 목표·기존 자원 상한·TCP8연결/DNS UDP2·TCP1 승인 Scope를 유지했다. 각각 새 Binding의 사용자 Scope yes·sudo 인증 후1회 실행했다. 동일 실패 Session·영수증의 자동 재실행은 수행하지 않았다.

두 시험 모두 Drop·Source Gap0, 실제 RF/LR 호출0, 외부API0, DNS9/HostAuthentication 미실행이다. 최초 시험은 봉인 작업의 별도 모델 승인이 기록되지 않았다. 수정 후 시험은 첫180초 정상 봉인 전 장애가 발생하여 모델 승인·실행까지 도달하지 못했다. 종료 때 생성된 적격 Window를 사후 추론해 실시간 성공으로 대체하지 않았다. 모델 Incident0, 이번 DNS SCRIPTED Task3이며 Plan·Read-only Tool·Assessment·Audit은 실제 DNS 증거에 연결됐다. 실제 LLM 검증으로 보고하지 않는다.

## 수정한 확인된 결함

1. DNS Reader lock·/proc 조회가 Control 이벤트 루프를 막을 수 있는 동기 snapshot을 worker 경계로 이동했다(260e760).
2. 이후 DNS 상태 갱신이 SQLite 저장 순서에 종속된 결합을 별도 비권한 관측 작업으로 분리했다(db5e8dc). 동일 상태 조회는 직렬화·중복 제거하고 읽기 시작 시각으로 freshness를 평가한다. Helper2초/Control5초 제한과 실패 차단을 유지한다.
3. Dashboard DNS 그래프에 Query/Response 카운터가 누락된 투영을 연결했다(db5e8dc). 실제 카운터 차이만 사용하고 누락값은 UNKNOWN으로 유지한다. 실제 두번째 시험의 Dashboard 스크린샷에서도 DNS 시계열과Transaction3을 확인했다.
4. 반복 STOP이 이미 종료된 Helper의 FAILED/STOPPED 상태를 STOPPING으로 덮어쓰는 결함을 수정했다(ac33af8). 원래 오류와 Cleanup receipt는 보존한다. 이 수정은 비권한 검증이며 이전 실제 Snapshot을 소급 변경하지 않는다.

## 마지막 실제 Helper 장애 RCA

최초 Runtime 오류는 CaptureUnavailable:HELPER_HEARTBEAT_OR_PROCESS_STALE, 외부 최초 오류는 RUNTIME_FIRST_ERROR:CaptureUnavailable:HELPER_HEARTBEAT_OR_PROCESS_STALE이다. Helper PID1038019/start94675367은 진단 당시R(실행 또는 실행 대기)였고, 그 후 승인된 실패 STOP에 응답해 CLOSED를 반환했다. 최초 판정 시 프로세스 종료로 단정하지 않는다.

- 실제 수신 Heartbeat age2.236042초, 기존2초 기준을 초과했다.
- 마지막 Helper Trace의 생성→수신은1.302270ms였다.
- 마지막 성공 송신 완료→CLOSED 생성은4.181037초다. 이 구간의 정확한 Helper 연산 단계는 기록되지 않았다.
- 실패 시 AF_UNIX FIONREAD0bytes, 송수신 buffer각212992bytes, packet queue0/32, source counter issue없음이다. 이미 밀린 메시지를 못 읽었다고 볼 증거는 없다.
- Reader 최대 poll공백0.818836초, 전체 Root Audit Heartbeat 최대 간격1.536483초다. 이번 오류는 이전 GUI cache 만료와 구분한다.
- Helper cpu.max는10000/100000(10%) 그대로다. READY→실패 nr_throttled는20 증가했지만 throttled_usec는증가0이다. 스케줄링·CPU quota가 원인이라고 확정하거나 제한을 완화하지 않았다.
- Runtime 저장 update 최대6.952602초, Control 상태 게시 작업 최대0.039924초였다. 저장 지연 자체의 최초 원인은 UNKNOWN이다.

확정 범위는 Helper의 실제2초 Heartbeat 계약 위반과 송신 공백이며, 어떤 연산·스케줄링 요인이 Helper 생성 공백을 만들었는지는 **UNKNOWN/미해결**이다. Timeout을 늘리거나 실패를 무시하는 변경은 하지 않았다. 확인되지 않은 원인을 해결 완료로 보고하지 않는다.

## 종료·Cleanup

두 시험 모두 TCX STOP ACK·순서·Receiver join/socket close, DNS Helper CLOSED·최종 Counter·STOP ACK 순서·Durable Cleanup, Root 소유 Link/Map/Socket·Runtime Cleanup·Audit Flush를 각각 검증했다. 마지막 시험은 stream admission DENIED_AFTER_FAILURE를 유지한 채 Cleanup만 VERIFIED다. 종료0으로 판정하지 않았다.

마지막 Runtime unit은실제exit2, 중단된 TCP Helper는SIGTERM15이며 이를 보존한다.5개 소유 서비스 MainPID0, TCX·DNS·dnsmasq inactive, Runtime·TCP는실패 상태가 남아 있다. Root 자원 Cleanup VERIFIED를 실행 성공이나 오류 삭제로 확대하지 않는다. 전역 Kernel Cleanup과 과거 UNKNOWN/UNVERIFIED/FAILED는 그대로다.

Ledger81행 SHA07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae를 보존했다. 기존 성공 Session PENDING2/POISON1을 변경하지 않았다. 최초 전체 통합 Session PENDING2/POISON1과 마지막 Session PENDING1도 별도로 보존한다. Queue 전체 분석 완료·완전 처리로 보고하지 않는다.

## GUI 판정

실제 Tk 화면·Backend projection·Widget 상태·스크린샷을 보존했다. Native Packet·DNS3·Capture Quality VERIFIED·Eligibility·SCRIPTED 조사/Assessment·Audit·오류·Cleanup은 표시됐다. RF/LR Prediction·Inference Latency·모델 Incident 및20분 중 GUI 종료/재연결은 검증되지 않아 전체 GUI 수락 기준도 FAIL이다. 기존 과거 Prediction이나 Mock을 이번 값으로 채우지 않았다. 마지막 실제 화면의 DNS STOPPING 표시는위4번 결함이며 과거 Snapshot은 보존한다.

## 비권한 검증과 빌드

- db5e8dc: Workspace1449 PASS/1 SKIP, 독립 Export1449 PASS/1 SKIP, 집중42 PASS. 실제 Tk Continuous/Flow Eligibility 추가 검증은각5 PASS.
- ac33af8의추가 terminal-state 수정: Workspace·새독립 Export에서 DNS Source/Heartbeat/Transport 각42 PASS. 전체1449 재실행 결과를 이 후속 수정에 대한 전체 회귀라고 주장하지 않는다.
- Ruff Check/Format, git diff --check 통과. Native6·Supervisor2·Wheel을각Workspace2회/Export에서 재현 빌드했다.
- db5e8dc 실제 시험 Wheel은3ec43692165d27a9de29c351d8d412f3d456b1a0302e3b77cf9d0483da2be8cf이다.
- ac33af8 비권한 최종 빌드 Wheel은e7b66af6d866159bad788fcea0fcc94a5b87a661adb78d9191813bbd63c0c560이며 실제 설치·실행하지 않았다.

## 증거와 다음 조건

최초 실제 시험은 .git/native20-full-integration-review-20261102T065604Z/full-integration-failed-result.json, 수정 후 실제 시험은 .git/native20-full-integration-review-20261102T073720Z/full-integration-failed-result.json과failed-trial-evidence-sha256.json(119개SHA)에 보존한다. 비권한 검증·빌드는 .git/native20-dns-storage-isolation-20261102T071948Z/에 있다.

다음 실제 시험 전에는 Helper 연산 구간과 CPU/스케줄링 공백을 더 좁혀야 한다. 근거 없는20분 반복 실행이나 새 Artifact에 대한 기존 승인 승계는 하지 않는다. 수정본은 새 Git/Source/Artifact/Root Manifest/Session/Namespace/Ledger Binding과 R1·Root·Native·트래픽 승인, 사용자 Scope·sudo 인증이 필요하다. 모델은 실제 봉인된 적격 작업별 별도 Action 승인으로 유지한다. 현재 **20분 전체 통합 재검증 미완료**, 운영 승격 불가다.
