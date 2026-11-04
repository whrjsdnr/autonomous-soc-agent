# Authentication Host 읽기 전용 진단 결과 — 2026-11-04

## 판정

**승인된 Host Source 진단 1회 성공. Authentication READY 복구와 Full Live E2E는 미검증/BLOCKED.**
새 Root·Native·DNS·RF/LR·IF·외부 API 실행은 없었다. 실제 진단은 승인된 기존 필터를
일반 사용자 UID1000으로 조회한 독립 작업이며 과거 소비 Session을 재사용하지 않았다.

## 실행 승인·Binding

승인 대상은 `evidence/authentication-source-rca-20261104/host-read-review.json`이다.
직전 인간 메시지의 조건부 승인 원문 범위를 새 진단 문맥에 기록했다.
입장 만료는2026-11-04 18:00 KST, 전체15초,16건,1회,재시도0회다.
Source682개/검증Wheel/검토서SHA가 일치했고 Ledger81행,Root8SHA·inode·mtime,실패증거를 확인했다.
Native Session/설치Release 권한을 사용하는 작업이 아니며 별도 진단ID로 묶었다.

원래 명령의15초 Timeout을 전체15초로 잘못 해석하지 않았다. 기존 Collector/Parser와
bounded_command를 사용하되 단독 진단용 subprocess 경계에서 명령 대기를10초로 제한하고,
전체13초 알람 및 소유자식 종료/회수 시간을 확보했다. 운영 Timeout은 변경하지 않았다.
고정 argv를 Mock으로 먼저 대조했다. 실제 명령은 승인된 journalctl 인자 그대로1회 실행했다.
진단 harness는 별도 `.git` 증거에 있으며 제품 Source/Launcher/정책을 수정하지 않는다.

## 실제 결과

| 항목 | 증거 |
|---|---|
| 실행 시각 | 2026-11-04 16:07:36.724771 ~ 16:07:42.507267 KST |
| 전체 진단 | 5.782495초, 결과 fsync까지5.787384초 |
| 명령 spawn/wait 관측 | 5.778828초 |
| Child | PID3339249, start_ticks111763264, UID1000 |
| Identity | 동일 boot ID, 생성 직후 상태D 표본1개 |
| Exit/errno | 0 / null |
| stderr | 0바이트, 원본 내용 저장/출력 없음 |
| Journal 레코드/Parser 통과 | 16 / 16 |
| 의미 해석 | MAPPED_AUTHENTICATION1, NOT_INFERABLE15 |
| 최초 오류 | 없음 |
| 자식 종료 | 정상 Exit0, reap완료, PID부재 |
| Cleanup | VERIFIED_OWNED_DIAGNOSTIC_CHILD_ONLY |
| 신규 Native·모델·API | 모두0회 |

단조 시각은 시작1117632.643310731, 명령시작1117632.643862299,
명령완료1117638.422690195, 종료1117638.425806103이다.
명령 관측에는 Popen·PID검사·wait 복귀 시간이 포함되며 순수 Journal I/O 시간으로 단정하지 않는다.
D상태 한 표본으로 특정 디스크/파일/CPU/GIL 원인을 확정할 수 없다.
원본 MESSAGE·사용자명·주소·cursor·stderr는 보고서/Audit에 저장하지 않았다.
임시 출력 파일은 기존 context manager로 닫았고 진단 Python도 정상 종료했다.

READY 생성·송신·Runtime 수신은 **NOT_APPLICABLE**이다. 이번 승인에는 Authentication Runtime 시작이 없다.
단독 journalctl은 STOP ACK 프로토콜이 없으므로 ACK를 만들어내지 않았다.
자식 회수·PID부재의 증거와 과거 Runtime Cleanup을 별개로 기록한다.
1개 해석 가능 이벤트가 나왔다고 IF Window가 봉인/적격/승인됐다고 판단하지 않는다.

## 원인 판정

| 후보 | 판정 |
|---|---|
| 현재 Source 전체 부재 | 이번 필터에서16건 조회됐으므로 현재 진단에서는 재현되지 않음 |
| 현재 접근 권한 부족 | UID1000의 실제 조회 성공. 숨겨진 모든 Journal 파일에 대한 접근권한 증명은 아님 |
| Journal 명령 실패 | 이번 Exit0, stderr0. 과거의 ExitCode는 없어서 과거 판정은 UNKNOWN |
| Source 필터 불일치 | 승인 인자와 실제 인자 일치. Source 임의 추가 없음 |
| Parser 계약 거절 |16건 모두 통과.15건 NOT_INFERABLE은 예외/장애와 다른 정상 보수적 분류 |
| READY 예산 초과 가능성 | 이번 명령 구간5.778828초가 기존READY5초보다 길다는 사실 확인 |
| READY 게시/전달 경합 | 독립 진단은 Runtime/SQLite READY 경로를 실행하지 않아 실환경 원인 확정 불가 |
| STOP 후속 Source 오류 | 비권한 Event 제어 Fixture에서 재현. 과거 실제 원인이었다는 증명은 아님 |
| 과거 SOURCE_UNAVAILABLE 근본 원인 | UNKNOWN 유지 |

기존 READY는 child spawn 이후5초 안에 동일PID의 RUNNING과 healthy collector 상태를 요구한다.
정상적인 Source 읽기가 이번처럼5초를 넘으면 같은 지연이 Managed 경로에 나타났을 때
healthy READY를 제시간에 게시할 수 없다. 이는 관측된 지연과 계약의 관계이며
과거 실패의 정확한 syscall/권한/스케줄링 원인을 확정하는 결론이 아니다.
Source가 현재 읽힌다는 사실을 Authentication 장애 해결이나 다음Live 성공 보장으로 바꾸지 않는다.

## 비권한 인과관계 재현

기존 실제 child CLI·Monitor·Parser·Queue·SQLite·Audit·Lifecycle은 유지했다.
Host 명령 경계만 Event로 보류하여, 기존5초READY Timeout 뒤 부모STOP이 들어오면
모의 명령이 -15 종료 오류를 반환하도록 했다. Sleep으로 테스트 통과를 유도하지 않았다.

검증 순서:

1. 모의 Journal 명령 시작, collector NOT_STARTED.
2. 실제5초 입장 계약에 따라 AUTHENTICATION_READY_TIMEOUT.
3. 부모의 STOP, child STOP_RECEIVED.
4. 모의 명령 종료 뒤 SOURCE_UNAVAILABLE 및 returncode -15 기록.
5. 최초 Timeout 유지, 소유child STOP ACK·durable Cleanup VERIFIED, Queue0.

이 결과는 SOURCE_UNAVAILABLE이 후속 오류일 수 있음을 증명하며 과거 종료 신호를 확정하지 않는다.
새 테스트의 첫 실행은 status projection에 내부 collector 키를 사용한 KeyError로 실패했다.
해당 Assertion을 실제 내부 read API로 정정했으며 최초 실패·trace는 보존했다.
제품 코드와 READY/Heartbeat/승인/권한 계약을 바꾸지 않았다.

| 회귀 | PASS | Driver 경과 |
|---|---:|---:|
| Workspace/일반 디스크 |19|20.980초|
| Workspace/tmpfs |19|16.091초|
| 독립 Export/일반 디스크 |19|20.492초|
| 독립 Export/tmpfs |19|16.375초|

동일19개를4환경에서 검사했다. Guard 위반0, Ruff/Format/Diff PASS.
테스트 Commit: e1d7a57a05db19a7b1a9ae2e6632af3a679907ab. 운영 Source·Wheel은a5441a9의 검증 바이트와 동일하다.
따라서 기존1066PASS 전체회귀와 Native/Supervisor/Wheel 재현빌드 증거를 재사용하며
새 빌드를 수행했다고 주장하지 않는다. 현재 변경은 재현 테스트와 보고서뿐이다.

## Cleanup·보존·후속 권한

현재 진단 자식 Cleanup만 VERIFIED다. **과거 Runtime Cleanup UNVERIFIED는 그대로다.**
과거 Authentication Child Cleanup VERIFIED 및 Global Kernel UNKNOWN도 소급 변경하지 않는다.
원본 실패파일SHA,Ledger81행,Root8SHA·inode·mtime,설치·Rollback은 보존됐다.
승인된Host진단1회는 완료했으며 자동재시도하지 않는다.

전체Live를 재개하려면 다음이 남는다.

- Source 지연이5초READY 계약을 충족할 수 있는지, 확인된 원인에 대한 최소 수정/검증.
- 기존Namespace의RootTCX/BPF/소유FD·Socket 잔류 읽기 전용 검사와 소유권 확인.
- 새Release·RootManifest·Session·Lease·정책/횟수의 정확한Binding.
- Root·Native·DNS·R1/R2,Host Runtime 읽기,RF/LR·IF 봉인 작업별GUI,LLM입력/비용의 독립 승인.
- 직접Scope 확인·sudo인증. 이번Host진단 승인을 전체Live에 전용하지 않음.

18:00이후 신규Live를 시작하지 않는 조건을 유지한다. 내일시연의 현재 예비경로는
`Authentication_Source_Recovery_And_Demo_Readiness.md`에 있는 검증된 저장결과 GUI 조회다.
과거PCAP/RF-LR·실제LLM 성공결과를2회 열고 종료/재연결한 증거가 있다.
이는 신규Replay→RF/LR→LLM 통합시연이나 실제Host IF 시연 성공을 뜻하지 않는다.
18:00/21:00 목표 자체로 미검증 범위를 완료로 표시하거나 예약/백그라운드 실행을 만들지 않는다.

## 증거

새 `.git/authentication-host-approved-diagnostic-20261104T070452Z/`에
인간승인문맥,검토서/Source/Wheel Binding,단독harness,1회실행marker,result,durable-timing,
회귀/Guard로그,최초Fixture실패,보존검사를 저장했다.
민감정보 없는 요약은 인접 `evidence/authentication-host-diagnostic-20261104/`에 있다.
