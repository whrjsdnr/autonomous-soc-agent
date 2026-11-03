# Full Live E2E — Root Exit2 최초 오류 복원 및 비권한 복구

## 판정

**BLOCKED — 다음 전체 Live E2E를 지금 안전하다고 판정할 수 없다.** 최초 오류는 복원했고 확인된 오류 보존 결함 및 늦은 DNS 트래픽 시작 Gate를 수정·비권한 검증했지만, 실제 Root Control 송신 정지의 기저 원인은 UNKNOWN이다. 원 실행 TCX STOP ACK·Runtime Cleanup UNVERIFIED를 유지한다. 이 작업에서 실제 Root·Native·DNS·모델·외부API 재실행, sudo 인증, 예약·새승인·기존Ledger변경은0회다. 새승인패키지도 생성하지 않았다.

실행 원본: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/full-e2e-operations-readiness-20261103T035500Z/candidate-final/native/execution`. 원 실행 Source74cbcb2, 운영 Worktree의 기존보고HEAD6ef3ea0/대상HEADdfb6abd를 확인했다. 새 코드수정은30df74e다. 실행된 원본·frozenSource·설치·Rollback은 덮어쓰지 않았다.

## 1. 실제 존재한 증거와 없는 증거

전체 실제 파일목록/크기/SHA는 evidence의 execution-inventory.json에 기록했다. Root stdout `root-stdout.log`는 **0byte**다. Root stderr는 Source상 사용자 foreground terminal로 상속됐고 별도 저장파일이 없다. Controller/Collector/Runtime/DNS의 전용 stdout·stderr 파일도 해당 디렉터리에는 없으며, 실제 존재하는 bounded `*-service-journal.json`과 `*-service-process/final.json`을 사용했다. GUI launch log는 별도profile에 존재하지만0byte며, 이번 실행의 GUI Screenshot은 제공되지 않았다. 이전 Fixture Screenshot을 이번Live처럼 사용하지 않는다.

실제로 존재한 핵심 증거는 first-error.json, runtime-final.json, terminal-status-history.jsonl, Root admission/설치8개 기록, authenticated-producer-ready.json, Root Audit before/after, Root exit/wait결과, Kernel/Namespace before/after, DNS session의 verified-ready/closed·transport-failure·cleanup.json이다. API후속 디렉터리는 not-executed.json과실행Script만있고 authorization/api-attempt/실API결과는없다. 없는로그를추정해서채우지않는다.

## 2. 최초 오류와 Exit2

- 최초 내부 오류: **CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT**, Runtime PID**2079255**.
- 원 frozen `src/soc_agent/continuous/tcx_producer.py:357`에서5초 sock_recv 대기, **395행**에서 domain ValueError 발생. 보존 trace는 events445 → messages288 → receive220 → receive_message395다.
- 오류 시각 **2026-11-03 13:49:59.413934 KST**, monotonic1022975.332452720. 계약5초는그대로이며 실제 wait 측정은**6.311554초**다. Callback/수신스케줄링 지연을포함한관측값이지 Timeout이6초로설정된것이아니다.
- Root coordinator의 `root-trial.py:519`가 `observe_service_health`를호출하고 **375행**에서 `RUNTIME_FIRST_ERROR:...`로전달했다. Root coordinator PID는기록없어UNKNOWN이다. **Root Collector PID2079245와 coordinator를혼동하지않는다.**
- `root-deadline-result.json`의 실제 wait 결과2, planned_returncode2, deadline_exit=false다. 전체 공유Launcher경과 **41.595616초**, root-finished공유시계41.399769초, Collector시작이후32.265150초다. 다른46.87초실패와합치지않는다.
- Root Exit2는복원된Runtime실패를Launcher가실패종료한결과다. Runtime systemd `2/INVALIDARGUMENT` 표시는exit2의일반명칭이며, CLI인자오류나설치실패가확인됐다는뜻이아니다. Root Collector서비스자체는0으로종료했다.
- 바깥Terminal/관리CLI의정확한최종종료시각·PID·wait기록은없다. Root자식의실제exit2와사용자가보고한BoundedExit2를구분하고없는CLI종료증거는UNKNOWN으로둔다.

## 3. 시간순 복원 — 2026-11-03

| KST | 단계 | PID / 근거 |
|---|---|---|
| 13:49:24.566426 | USER_SCOPE_CONFIRMED | 미기록 |
| 13:49:28.451931 | SUDO_AUTH_COMPLETED | 미기록 |
| 13:49:28.516440 | LAUNCHER_EXECUTION_CLOCK_START | 미기록 |
| 13:49:36.870395 | ROOT_ADMISSION | 미기록 |
| 13:49:36.874613 | ROOT_BINDING_VERIFIED_INSTALL_PHASE_STARTED | 미기록 |
| 13:49:37.616327 | COLLECTOR_START_REQUEST | 미기록 |
| 13:49:38.414441 | ROOT_AUDIT_ATTACH_OWNED | 2079245 |
| 13:49:38.497810 | ROOT_SOCKET_READY | 미기록 |
| 13:49:41.921290 | ROOT_FIRST_CONTROL_GENERATED | 2079245 |
| 13:49:41.921858 | ROOT_FIRST_CONTROL_SEND_COMPLETE | 2079245 |
| 13:49:41.921910 | RUNTIME_FIRST_CONTROL_RECEIVE | 2079255 |
| 13:49:43.013744 | AUTHENTICATED_PRODUCER_READY | 미기록 |
| 13:49:51.126506 | DNS_HELPER_READY | 미기록 |
| 13:49:52.008563 | ROOT_LAST_CONTROL_SEND_SEQ9 | 2079245 |
| 13:49:53.102300 | RUNTIME_LAST_CONTROL_RECEIVE_SEQ9 | 2079255 |
| 13:49:59.413934 | FIRST_TCX_RECEIVE_TIMEOUT | 2079255 |
| 13:49:59.415887 | TCX_STOP_REQUEST | 2079255 |
| 13:50:02.416862 | DNS_READER_STALE | 2079255 |
| 13:50:02.789758 | DNS_STOP_REQUEST | 미기록 |
| 13:50:02.807535 | DNS_CLOSED_RECEIVED | 2079360 |
| 13:50:03.061937 | DNSMASQ_SOCKET_READY | 미기록 |
| 13:50:03.086615 | DNS_PROBE_START_REQUEST | 미기록 |
| 13:50:03.132732 | ROOT_OBSERVER_ERROR | 미기록 |
| 13:50:04.419026 | TCX_STOP_ACK_TIMEOUT | 미기록 |
| 13:50:05.607908 | ROOT_RECEIVES_VALIDATED_STOP | 2079245 |
| 13:50:05.808065 | ROOT_AUDIT_CAPTURE_WINDOW_SEALED | 2079245 |
| 13:50:05.819121 | ROOT_AUDIT_CAPTURE_FINAL_SEAL_NOT_DELIVERED | 2079245 |
| 13:50:05.826584 | ROOT_AUDIT_SERVICE_STOPPED | 2079245 |
| 13:50:09.916132 | ROOT_FINISHED | 미기록 |
| 13:50:09.923991 | ROOT_CHILD_PLANNED_EXIT2 | 미기록 |
| 13:50:10.119309 | CLI_ROOT_WAIT_RETURNED2 | 미기록 |


Root Binding은13:49:36.870395에 admission으로확인된다. 설치는baseline조사후Collector시작13:49:37.616327전완료됐지만8개설치항목각각의wall timestamp는없으므로정확시각을꾸미지않는다. root-trial-started.json의at은36.874613이고monotonic값은더이른공유Launcher시작값이다. 두필드를같은순간으로간주하면잘못된ClockOffset을만든다. Root Control의bracketedClock과공통Boot/timeNamespace를사용해mono시각을매핑했다.

서비스PID: Collector2079245/StartTicks102295355, Runtime2079255/102295443, DNS2079360/102295896, dnsmasq2079558. 원 Session은81660de4-5cb8-418a-ae46-520ba4b168c0, DNS3743fc22-a959-4006-9907-4f22ffd55353다. 최초Kernel Packet Event/Runtime Packet수신은없다. 최초Control수신과실제Packet수신을혼동하지않는다.

## 4. TCX 송수신·CPU RCA

- Root final 진단은 **17개 정상전송 시도(9Control+8Data)**, SENT17/PARTIAL0/BACKPRESSURE0/ERROR0, truncated0이다. Data record의frames는비어있고Packet0이다.
- 마지막Control9 send완료부터Root가VALIDATED_STOP을처리할때까지 **13.599345초** 동안정상Control송신시도가없다. 메시지공백분류는 **PRODUCER_NOT_SENDING**으로좁혀졌다. 단, 이후별도finally경로의Seal/ACK시도와혼동하지않는다.
- 전체trace의최대send **0.627016ms**, 최대Lock대기 **0.016099ms**다. 기록된송신이Socket에서5초Blocking하거나Lock에서5초막혔다는증거는없다.
- Control9는Runtime에 **1093.736908ms** 늦게수신됐다. 수신지연도관측됐지만새Control10이송신되지않은13초공백을전부설명하지못한다.
- Timeout시Runtime Socket은nonblocking, SO_RCVBUF/SO_SNDBUF각212992, FIONREAD0/send_queue0, applicationqueue0/drop0이다. 마지막Rootsend의kernel send_queue4608은포화증거가아니다. Socket연결FD가유효한것만으로상대진행을확정하지않는다.
- Root CPU표본14.493957초구간: usage+1.746551초, periods+145, throttled+137, throttled_usec+**25.394701초**. 실제throttling은확인됐지만이구간은정확한13초공백과일치하지않으며누적counter를벽시계지연으로환산하지않는다. **CPUQuota·HostScheduling·GIL·syscall중근본원인은UNKNOWN**이다. quota25%를올리거나설치무결성검사를생략하지않았다.
- Root worker의마지막공개단계는INSTALLED_INTEGRITY였다. 단계명이그함수의결함이나Hash검사실패를증명하지않는다. Process가살아있어도Control진행이정지할수있다. Root와Runtime은같은Boot/timeNamespace로확인됐다.

DNS의2.225194초stale는최초TCX오류보다약3.003초늦다. 당시Helper는PID/StartTicks일치,stateR로관측됐고CPU10%/누적throttled4.716207초, schedstat누적대기6.031156초였다. IPCavailable_bytes0이다. 이는Helper Crash증거가아니며이DNS누적값을Root의원인으로대체하지않는다.

## 5. 오류 분류

|분류|이번증거판정|
|---|---|
|ROOT_INSTALLATION_FAILURE|최초원인아님. Binding/설치/KernelAttach다음단계도달|
|COLLECTOR_START_FAILURE|최초원인아님. ATTACH_OWNED·Socket·Control수신확인|
|PRODUCER_AUTH_FAILURE|최초원인아님. Peer UID/PID·Session/Policy인증통과|
|TCX_SEND_FAILURE|기록된send호출실패0. 대신다음Control송신시도정지확인|
|IPC_RECEIVE_FAILURE|최초Runtime증상확정:5초수신계약Timeout|
|HEARTBEAT_STALE|DNS후속실패확인. 최초TCX오류와분리|
|RUNTIME_WORKER_FAILURE|실제모델Worker시작/오류증거없음;모델0|
|DNS_HELPER_FAILURE|후속ReaderStale,프로세스Crash로단정불가|
|DEADLINE_FAILURE|전체600초Deadline아님. receive/ACK의개별Timeout은있음|
|CLEANUP_FAILURE|TCX ACK미수신·RuntimeUNVERIFIED. 최초오류와분리|
|UNKNOWN|송신loop정지의정확한스케줄링/Host/GIL원인,RootcoordinatorPID등|

## 6. Cleanup — 전체 UNVERIFIED 유지

TCX STOP은13:49:59.415887에송신됐으나Root의VALIDATED_STOP은13:50:05.607908이다. **송신완료후약6.192초**로기존5초ACK대기보다늦다. Runtime은13:50:04.419026에ACKTimeout으로닫았고Root는이후Seal전송실패를기록했다. 이순서는ACK부재를설명하지만정확한send syscall error번호는기록없어추정하지않는다. 시간을늘려성공으로바꾸지않았다.

- DNS: 원본CLOSED/최종counter/cleanup의소유범위VERIFIED보고,서비스exit0.다른영역으로확대하지않음.
- Collector/Root: hash-chain검증된SERVICE_STOPPED cleanupVERIFIED와저장된Namespace후TCX없음/link·map목록없음이있다. 이는원본의제한된소유범위보고다. 독립된전역Kernel/모든FD정리증명으로확대하지않음.
- TCX STOP ACK: **UNVERIFIED**, finalSeal은Root로컬기록만있고전달실패. RuntimeWindow0/Attestation미검증.
- Runtime: 원본 **UNVERIFIED** 유지. 오래된최종last_error는DNS였으며원본을소급고치지않음.
- GlobalKernel: programID가before/after달라**UNKNOWN**. 이차이만으로새leak또는정상정리를단정하지않음.

현재일반권한Snapshot은세PID없음/RootUnixSocket없음이다. 과거Cleanup을소급검증하지않는다. 권한이필요한검사는 [읽기전용계획](evidence/root-exit2-20261103/readonly-cleanup-inspection-plan.md)에만정리했고실행하지않았다.

## 7. 확인된 결함의 최소 복구

1. **최초공개오류유실**: snapshot은source.failure의TCX오류를표시했지만self.last_error에고정하지않았다. TCX실패Cleanup대기중DNS후속오류가self.last_error를차지해최종상태가바뀌었다. 새코드는최초공개Source오류를메모리에고정한다. 기존더이른명시적오류는유지한다.
2. **Collector traceback누락**: 기존self.last_error가있으면collector_failure도저장하지않았다. 새코드는최초Collector traceback을독립보존한다. DNS상태/후속예외는별도증거에남겨숨기지않는다.
3. **늦은DNS트래픽Gate**: dnsmasq준비대기후Runtime현재건강을재검증하지않고probe.start()를호출했다. 실제DNSprobe시작요청은최초Runtime오류보다**3.672681초늦다**. child완료false/exit-9/events[]이므로실제DNS송신성공여부는UNKNOWN이며Transaction0이다. 수정복사본은기존observe_service_health와ready를 **probe.start직전** 호출한다. 실제원본은보존했고이복사본은미승인·미배치·미실행이다. 실제인접AST구문을추출한실패/미인증/정상3개Gate검증으로트래픽Spy호출여부를확인했다.

코드Entry Point·Namespace·Root·Ledger·Model Admission·API비용·2초/5초계약은유지한다. Native송신공백자체를고쳤다고주장하지않는다. Root Audit8029개chain검증,기존prefix보존및이번17개append를확인했다.

## 8. 비권한 검증

Workspace **883PASS/207.25초**, Export **883PASS/243.95초**, Source불변/no-live guard위반0. 집중20PASS(신규3개포함),Ruff/check/format/diff PASS. Native6개·legacy·Supervisor·Wheel을Workspace2회+Export1회빌드해SHA일치. WheelSHA `2c4dc1675c8f93a7baaa19ad1769ac6ab51ce42a5965506c56b0e0b4e06b9896`. 실제KernelLoad/설치/모델/API시험이아니다.

최초Workspace는882PASS/1FAIL(DNS실제2초무응답Fixture가6초대기상한내종료하지못함)이었다. 동일코드/기대값으로단독PASS(7.70초)와전체883PASS를재확인했고최초로그를보존했다. 간헐실패원인은UNKNOWN이며Native원인으로합치지않는다. Assertion/Timeout완화나테스트삭제는없다.

원 실행Packet0/DNSTransaction0/Window0/ELIGIBLE0/Prediction0/Incident0/실API0. 과거RF/LR8개나LLMPlan성공을이번실행성과로합산하지않는다. 새Source30df74e는비권한수정본이며Root설치/실행Release로자동전환하지않았다.

원본파일797개SHA,설치8경로SHA/inode/mtime,Ledger81행chain을보존재확인했다. Root-only백업byte는추가권한조회하지않았으며쓰기없음. 기존원본safe_for_next_attempt/FAILED/UNKNOWN/UNVERIFIED는수정하지않는다.

## 9. 다음 Live E2E 조건

현재는즉시재시험불가다. 기존Session/RootNative1회승인은이미소비됐고새Source/Launcher복구본에승계할수없다. 먼저현재소유자원에대한정확한읽기전용Root검사와직접인증이필요하며,남은Cleanup미검증과송신원인UNKNOWN을그대로보고해야한다. 이후새Source/Artifact/RootManifest/Session·Release·Namespace·LedgerBinding을검토하고필요한R1/Root/Native/DNS승인을새로확인한다. 실제시도는사용자Scope확인·직접sudo후최대1회,실패시자동재실행0이다.

RF/LR은새봉인ELIGIBLE/Attestation VERIFIED작업별독립승인,LLM은같은Session의exactIncident/Revision과호출·비용·Provider승인을유지한다. 이번작업은새승인패키지를생성하지않았다. 전체실환경성공은미검증이며다음시험의안전을현재증거만으로보증하지않는다.
