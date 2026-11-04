# Native 최초 수신·STOP ACK 복구 — 2026-11-03

## 판정과 증거

실제 재시험은 **실패**했다. 최초 오류는 `AUTHENTICATED_PRODUCER_READY` 단계의
`CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT`이다. DNS Helper와 승인된 트래픽 공급은 시작되지 않았다.
RF/LR·LLM·Incident 성공으로 확대할 수 없다.

보존 원본은 공통 Git 디렉터리의
`operator-session-40491555c2af44beb3518aa9b0c15946/native/execution/`이다.
복구 검증 디렉터리는 `native-receive-startup-recovery-20261103/`이다.

| 항목 | 실제 관측 |
|---|---|
| Root driver 실행 | 41.211초, 실제 자식 종료 코드 2 |
| 첫 수신 대기 | 5.000545초; 첫 메시지·Sequence·Control 기록 없음 |
| Peer | PID 1851667, UID 0, Start Identity SAME_PROCESS |
| 이벤트·DNS | 0; DNS Helper 시작 전 중단 |
| Root Audit | ATTACH_OWNED 이후 HEARTBEAT 존재, 중간 약 15.3초 공백 |
| TCX 종료 | 동일 채널의 STOP ACK·진단 Seal 검증, TCX Cleanup VERIFIED |
| Root 종료 관측 | 소유 소켓 제거, Collector MainPID 0, 저장된 Namespace-after TCX 비어 있음 |
| Runtime | MainPID 0, 서비스 종료 2, Cleanup UNVERIFIED |
| Runtime 후속 오류 | `request_control_stop → request_stop`의 `TimeoutError` |
| Global Kernel | UNKNOWN; 다른 시스템 프로그램의 ID 변화는 이 시험 소유 자원 증거가 아님 |

종료 코드 0을 근거로 정리를 주장하지 않았다. 현재 자원이 없다는 Snapshot으로
과거 Cleanup UNVERIFIED를 소급 변경하지 않았다.

## RCA: 확인된 결함과 남은 UNKNOWN

`continuous/native/service.py`의 최초 `server.accept()`는 정책·설치 무결성 검증,
Kernel poll·Counter·Audit 작업 이후 Data Worker 루프에서만 실행됐다.
따라서 최초 연결은 이미 분리된 Control Heartbeat 스레드의 보호를 받지 못했다.
실제 최초 수신 Timeout과 이 구조적 결합은 확인했지만, 이번 약 15.3초 공백이
특정 파일 I/O·CPU Throttling·스케줄링 중 무엇에서 발생했는지는 **UNKNOWN**이다.
기존 증거에는 수락 Timestamp와 해당 구간의 cgroup delta가 없다.

별도 종료 결함은 구체적으로 확인했다. 정상 수신 Reader는 `transport_stop_ack`를
설정하지만, 실패 정리 Reader는 같은 `records()` 검증기로 STOP ACK를 검증하면서도
그 이벤트를 설정하지 않았다. 이미 대기 중인 Control STOP 호출은 별도 이벤트에서
Timeout될 수 있었다. 원본 Runtime 증거는 TCX STOP ACK VERIFIED와 이 대기 Timeout을
동시에 보존하고 있다. 실제 STOP 송신 요청부터 ACK 검증까지는 약 0.084초였고,
검증된 ACK가 있었음에도 `transport_ack`는 None이었다. 단순한 ACK 지연으로만 설명할 수 없다.

## 최소 수정

- 기존 ControlTransport 스레드가 비차단 Listener 수락과 `SO_PEERCRED` UID 검증을 담당한다.
  Kernel 부착 뒤에만 Listener를 전달하며 추가 스레드·권한·연결 재시도는 만들지 않는다.
- 최초 Control 기록에 실제 수락 PID/UID/GID·monotonic 시각을 포함한다.
  이 기록은 데이터 READY·Attestation·모델 권한을 부여하지 않는다.
- 기존 Data Worker는 수락된 Peer를 전달받는다. 수락 직후 STOP이 와도 최종 정리가
  같은 Peer를 확보한다.
- 실패 정리의 `records()`가 Epoch·Namespace·Policy를 검증한 ACK를 수신하면
  같은 ACK를 Control STOP 대기자에게 게시한다. 미검증 ACK·Timeout은 계속 차단한다.
- 기존 5초 수신·Worker Stale 계약, 자원 상한, 무결성 검증, 승인 계약을 유지한다.

운영 수정 Commit은 `183070f5899796e36af2b19b214aefb68c78a236`이다.

## 검증

- 실제 일반 사용자 UNIX Listening Socket으로, Data Worker가 진행하지 않아도 최초 수락·
  Control Heartbeat·STOP이 동작하는지 검증했다. 잘못된 UID는 수락 후 즉시 차단한다.
- 실패 정리 ACK와 동시에 대기하는 Control STOP 경합을 재현해 같은 검증된 ACK로
  대기가 완료되는지 확인했다.
- 집중 Workspace **27 PASS**, 독립 Export **27 PASS**.
- Native 6개 Artifact, 기존 Native 컴파일, Supervisor, Wheel을 Workspace 2회·Export 1회
  빌드하여 각각 SHA가 일치했다. 실제 Kernel 실행을 수행한 결과가 아니다.
- Wheel SHA: `ec239dd4f1bf191b41216db132efa82ecb012de17ebc10f7277d78ec23e02f85`.
- Ruff Check·Format·Diff 통과.
- 확대 Runtime·DNS·Orchestration·Recovery·GUI 회귀: **380 PASS**, 실제 443.40초.
  초기 병렬 작업 중 DNS 내구성 기록의 종료 대기 테스트가 Timeout했다. 원본 로그를
  보존했으며 Assertion·시간 상한을 바꾸지 않고 직렬 최종 회귀를 완료했다.
  당시 CPU/I/O 압박은 관측했지만 특정 실패와의 인과관계는 UNKNOWN이다.

## 새 실행 후보와 실행 경계

새 후보는 `native-receive-startup-recovery-20261103/retest-candidate/native/`에 준비했다.
Runtime Session: `b67eb5b8-a603-4afc-aba9-d1bcda2d78c9`.
Git/Source/Manifest/Session을 새로 결합했으며 기존 소비된 승인을 승계하지 않았다.
기존 Root `verify_contract()`를 비권한으로 검증하고 문서 SHA·만료·Session·Git 불일치
거부를 확인했다. 승인·Scope 입력과 Root 서비스 조회만 메모리 Fixture이며, 실제 Source·
설치본·Artifact 파일은 그대로 검증했다. 승인 영수증은 발급하지 않았다.

Root 고정 8경로 중 4개 변경 후보는 정책 JSON, Runtime Unit, DNS Unit, Collector
service.py다. 나머지 4개는 SHA·inode·mtime 검증만 한다. 전체 상한 600초,
순수 수집 목표 360초, TCP 최대4연결, DNS UDP2/TCP1, 기존 자원 상한을 유지한다.
모델은 봉인된 ELIGIBLE 작업별 별도 확인, API는 정확한 Incident/Revision별 별도
확인(2회/$0.05/20초/재시도0)으로 유지한다.

이전 Runtime Cleanup UNVERIFIED 때문에 새 권한 실행을 시작하지 않았다.
사용자가 지정한 Cleanup 실패 후 후속 실행 중단 조건을 유지하며, 정확한 새 Binding의
복구 위험 수용과 Scope 직접 확인·sudo 인증 전에 재시험을 실행하거나 예약하지 않는다.
기본 설치 Profile은 실패한 원본 Session을 계속 가리켜 실패 흔적을 숨기지 않는다.
새 후보 CLI Profile은 복구 검증 디렉터리의 `retest-profile`에 분리했다.

이전 사용자 파일 164개, 실패 실행 파일 SHA, Ledger 81행과 SHA를 재검증했다.
실제 DNS·모델·API 재호출이나 Root 변경은 이번 복구 작업에서 수행하지 않았다.

## 직접 인증 후 실제 재시험 — 2026-11-03 10:33 KST

첫 재확인 창은 yes 입력 대기에서 KeyboardInterrupt로 종료됐다. 그 창에서는 Scope 승인,
sudo 인증, Root 실행이 없었고 오류 원본을 보존했다. 사용자의 재시작 요청에 따라 별도
새 Session과 창을 마련했으며, 사용자가 직접 yes·sudo 인증을 완료한 뒤 최대1회 실행했다.

실제 실행 증거는 복구 디렉터리의
`retest-after-interrupted-confirmation/native/execution/`에 있다.
요약은 `actual-retest-result.json`, SHA 목록은 `actual-retest-evidence-pins.json`이다.

| 항목 | 실제 재시험 결과 |
|---|---|
| 실행 코드 | 183070f, Source Identity 3f2593526ede65efc209cd5c6c9f92de359353550849667919609d9bcb19a0a2 |
| 전체 Root driver | 46.873초, 실제 자식 종료 2 |
| 최초 연결 | 인증된 Producer READY 통과; 실제 이벤트 수신 확인 |
| Packet | 12 |
| DNS Transaction | MATCHED_RESPONSE 2: UDP 1·TCP 1 |
| 나머지 DNS | TCP 종료 후35초 대기 중 시험 중단; 두 번째 UDP 요청 전이므로 Scope 전체 완료 아님 |
| TCP 공급 Helper | 시작0회; 추가 트래픽 임의 생성 없음 |
| Runtime Window·ELIGIBLE | 0; 실패 정리의 TCX 진단 Seal을 Runtime 완전 Window로 계산하지 않음 |
| RF/LR·LLM·Incident | Prediction0·API0·Incident0; 미검증 |
| Drop·Source Gap | 0·0; 이 숫자만으로 Window 완전성을 주장하지 않음 |
| Runtime 최초 오류 | CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT; 마지막 메시지 이후5.001초 |
| Root Observer 표시 | COLLECTOR_EARLY_EXIT: Runtime 실패 STOP의 후속 종료를 먼저 검사함 |
| 종료 | TCX STOP ACK·Helper CLOSED·최종 Counter·Root 소유 정리·Runtime Cleanup VERIFIED |
| Global Kernel | UNKNOWN 유지 |
| GUI | 실행 종료2에서 기존 CLI가 GUI도 닫음. 이후 동일 실제 결과를 읽는 GUI를 별도로 재개함 |
| 최종 판정 | PARTIALLY_VERIFIED; 전체 Native AI E2E 실패, 장시간 운영 미검증 |

새 Control accept 경로 덕분에 최초 연결은 통과했고, 동시 STOP 대기 문제 수정 후 이번
Runtime Cleanup은 VERIFIED다. 이를 이전 UNVERIFIED에 소급하지 않는다. 그러나 수집 중
Root Control 메시지에도 공백이 재발했으므로 전달 경로 전체가 안정화됐다고 주장하지 않는다.
마지막 Control Sequence24의 Worker Stage는 INSTALLED_INTEGRITY였고, Peer는 SAME_PROCESS,
수신 Queue Depth·Dropped Batch는0이었다. 특정 파일 I/O·GIL·Scheduling·Root CPU Throttling이
원인이라는 확정 증거는 없다. 이번 CPU 샘플은 DNS Helper용이며 Root Collector의
동일 구간 CPU delta를 대신하지 않는다. 원인은 **UNKNOWN**으로 유지한다.

후속 비권한 수정 `e2876d9`: `observe_service_health()`가 Snapshot에 기록된 Runtime 오류를
확인한 뒤 서비스 종료를 검사하도록 순서를 고쳤다. 성공한 실패 정리를 최초 Collector
장애로 잘못 보고하지 않게 했다. 오류가 없는 Collector/Runtime 조기 종료는 여전히 차단한다.
이 함수는 검토된 Coordinator에 삽입되므로 다음 시험에서는 새 Source·Launcher Binding이
필요하다. 이번 실제 실행의 Coordinator나 증거는 수정하지 않았다.

후속 수정 집중 Workspace20 PASS·독립 Export20 PASS, Ruff·Format·Diff 통과.
Native·Supervisor·Wheel의 Workspace2회/Export1회 재현 빌드 일치. 후속 Wheel SHA는
`9fc0c15955b569ddfb4ad23534d260e8fd4414db063b5f19a0c2710e0c94fd39`다.
앞의 확대380 PASS는 실행 코드183070f에 대한 결과이며 후속 전체 회귀로 바꿔 서술하지 않는다.

새 자동 권한 재실행은 수행하지 않았다. 추가 실환경 시험은 원인 진단을 보강한 새로운
정확한 검토 Binding과 새 인간 Scope/R1·직접 sudo 인증을 필요로 한다.

## 2026-11-03 후속 읽기 전용 심층 RCA

[TCX 5초 메시지 공백 RCA](Native_TCX_Message_Gap_RCA.md)에 프로세스·Sequence·Clock·CPU·
IPC 판정을 분리해 기록했다. 기존5초 공백은 **TCX 수신 완료 부재**이며 송신 중단으로
확정되지 않았다. 공백 중 DNS Record96과 Runtime Control31은 계속 갱신됐다. Root 송신
시도/커널 큐/Lock·해당 구간 CPU delta가 없어 근본 원인은 UNKNOWN이다. 이 후속 작업은
Native·DNS·모델·외부 API를 재실행하지 않았고 새 승인 영수증도 발급하지 않았다.


---

# Full Live E2E — 2026-11-04 실제 실행 및 Authentication 시작 실패

판정: **BLOCKED**. 이전 성공 회차와 합산하지 않는다. 재실행·모델·API 성공이 아니다.

## 실제 실행

- 운영 소스 067d36a, Release ec9c913, expiry-cap-recovery 최종 Binding을 사용했다.
- 사용자의 새 실행 승인, 직접 Scope 확인 및 sudo 인증 뒤 최대 1회 실행했다.
- 기록된 승인 만료는 `2026-11-05T00:09:00+00:00`(KST09:09:00)다. 기존35.912778초 초과값을 사용하지 않았다.
- Runtime Session: `c1f2c795-642b-4c38-b60a-6217922f9db6`.
- Root Trial driver29.887157684초, Root 내부29.478746839초. Collector 시작 이후25.957979697초는 검증된 순수 수집 시간이 아니다.
- Root 고정8경로 중3개 교체·5개 검증을 수행했다. 기존8개 백업·Rollback은 보존했다.
- BPF attach 및 Root socket 준비 증거는 있으나 Runtime의 authenticated producer READY에 도달하지 못했다.
- Runtime Packet0, DNS0, Host Event0, Window0, RF/LR0, IF0, Incident0, LLM 요청0.
- Root Audit의 종료 봉인 기록은 빈 수집 종료 증거다. Runtime VERIFIED Window/ELIGIBLE 성공으로 세지 않는다.

## 최초 오류와 바깥 종료 코드

직접 예외는 `ValueError:AUTHENTICATION_READY_TIMEOUT`이다.
`continuous/authentication_lifecycle.py:257`, `AuthenticationLifecycle._start_owned()`의
기존5초 READY 루프에서 발생했다(실행 소스067d36a 기준).
필요한 조건은 동일 PID/Start Identity, RUNNING, `INITIAL_READ/RESUMED_EXACT/RESUMED_WITH_REPLAY`다.
`continuous/service.py:1361`의 Authentication 시작이 완료되지 않아 TCX Producer 연결 단계에 진입하지 못했다.
Root는 `root-trial.py:477`에서 Runtime의 `last_error=ValueError`를 보고
`RUNTIME_FIRST_ERROR:ValueError`로 중단했다. Root Exit2 자체가 근본 원인은 아니다.

## 시각 및 인과관계

| 관측 | UTC / monotonic |
|---|---|
| 인간 승인 기록 |05:34:43.265811Z|
| Runtime systemd active |monotonic1112066.834396|
| Authentication 단계 시작 |monotonic1112067.771317040|
| 가장 느린 Runtime 저장 작업(control) |1112067.771359212→1112070.096967884, 2.325608672초|
| Authentication 자식 identity |PID3261118, start_ticks111207070, UID1000|
| Authentication RUNTIME_STARTED |05:34:55.404128Z|
| COLLECTION_START |05:34:55.463048Z|
| Root가 최초 Runtime 오류 관측 |05:35:00.208689Z|
| Authentication STOP 요청 |monotonic1112076.070955167|
| COLLECTION_RESULT SOURCE_UNAVAILABLE |05:35:00.353349Z|
| COLLECTION_RETRY #1 |05:35:00.467756Z|
| Authentication RUNTIME_STOPPING |05:35:00.818420Z|
| Authentication RUNTIME_STOPPED |05:35:02.265584Z|
| Authentication 자식 ACK·reap 관측 |monotonic1112078.709390848|
| Runtime 프로세스 exit2 |UTC05:35:05(서비스 Journal 표시KST14:35:05)|
| Root 완료 |05:35:15.995756Z|

COLLECTION_START→RESULT는4.890301초이나 명령 실행·SQLite·파싱 각각의 지연은 기록되지 않았다.
SOURCE_UNAVAILABLE 결과 기록은 Root의 최초 오류 관측보다 늦다. 따라서 SOURCE_UNAVAILABLE가
5초 전체를 차지했다거나 CPU/권한/파싱이 직접 원인이라고 확정하지 않는다.
Root Audit Heartbeat 최대 간격은3.786731720초(벽시계 기록 차이)다. Runtime/TCX 수신 Heartbeat와 동일 지표가 아니다.
수집 직전 cgroup/프로세스 snapshot은 있으나 실패 경계의 CPU Throttling delta는 없다: **UNKNOWN**.
이번 실패를 과거 TCX 메시지 공백 재현으로 분류하지 않는다.

## Cleanup

- Root Audit는 기존8388행 prefix를 보존하고19행 append했다. 이번 SERVICE_STOPPED는 cleanup VERIFIED.
- Collector MainPID0/inactive, Root socket 없음, 대상 namespace의 tc/xdp 없음, BPF link/map 전후없음.
  이 증거에 한정하여 Root 소유 범위 Cleanup VERIFIED. 전역 Kernel 프로그램 ID 변화의 소유권은 UNKNOWN.
- Authentication: STOP ACK, 비강제 exit0, identity 일치, child reap, state reader join,
  ordered RUNTIME_STOPPING→RUNTIME_STOPPED, Queue drain, durable 기록에 의해 VERIFIED.
- DNS Helper는 시작되지 않았다. 실제 CLOSED/Counter 검증 성공으로 보고하지 않는다.
- TCX STOP ACK는 미확보. Runtime Cleanup은 **UNVERIFIED** 유지.
- Runtime 후속 오류: `CONTINUOUS_STOP_REQUIRES_CONNECTED_OWNER`, `CONTINUOUS_REMOTE_CLEANUP_UNVERIFIED`.
  최초 Authentication READY 오류와 구분한다. Runtime PID3261026, Auth3261118, Collector3261002는 후속 일반사용자 /proc 조회에서 부재.
  프로세스 부재로 과거 ACK/Runtime Cleanup 판정을 소급 변경하지 않는다.
- 기존 Ledger81행 SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` 동일.

## 수정 요청 이후의 비권한 작업

사용자의 "오류 다 해결하고 다시 시도해" 요청 후 설치 Release/실행 증거와 분리된
`fix/authentication-startup-evidence-20261104` Worktree에서 확인된 진단 유실만 수정한다.
현재 증거로 하위 원인을 확정할 수 없으므로 권한 확대·입력 무시·Timeout 증가를 적용하지 않는다.

1. bounded_command의 OS 오류/명령 Timeout/비정상 종료/권한 거절/출력 상한을 고정 코드로 분리한다.
2. Authentication 파서에서 CollectorUnavailable이 JSON 오류로 다시 포장되는 문제를 수정한다.
3. Health→Runtime 상태→Audit→GUI projection에 안전한 오류 코드와 monotonic 관측 구간을 전달한다.
4. Authentication start snapshot에 spawn/deadline/observation/identity/collector 상태를 보존한다.
5. 원본 stderr·MESSAGE·명령 인자·인증 정보는 진단 필드에 기록하지 않는다.
6. 기존5초 READY,2/5초 Heartbeat,8초 Control Identity,15초 bounded command 및 승인 계약은 유지한다.

하위 실제 Source 실패의 원인은 여전히 UNKNOWN이다. **모든 운영 오류가 해결됐다고 선언하지 않는다.**
수정된 소스를 기존 Launcher/Pin/영수증에 넣어 실행하지 않았다.

## 재시험 입장 조건

사용자의 재시도 의사는 확인했다. 그러나 소비된 Session/1회 영수증의 재사용은 불가하다.
다음 Live 전에 Source 실패의 구체적 코드 확인, 새 코드의 검증 Release/Source/Wheel Binding,
새 Session 및 기존 설치3개 변경 결과를 반영한 Root 설치 계획, Cleanup 미검증 항목의 읽기 전용 확인,
유효기간 검증과 직접 Scope·sudo 인증이 필요하다.
RF/LR/IF 봉인 작업 및 LLM 입력·비용 GUI 확인은 별도 유지한다.
불확실한 Source에 READY를 부여하거나 Authentication을 빼고 전체 성공을 주장하지 않는다.

## 증거 위치

- `.git/full-live-final-approval-readiness-20261104/live-attempt-result.json`
- 같은 디렉터리 `execution-evidence-sha256.json`, `fresh-human-authorization-context.json`
- `.git/full-reliability-stabilization-20261104T021605Z/final-verified/candidate/native/execution/`
- 같은 native 경로 `future-runtime/authentication-child.log`, `authentication-cleanup.json`,
  `authentication/monitor.sqlite`, `authentication/collection-audit.sqlite`, `service.sqlite`
- 후속 검증: `.git/full-live-final-approval-readiness-20261104/recovery/`

검증 결과 및 Commit은 완료 후 별도 추가한다. 기존 실패 로그는 보존한다.

## 최종 비권한 검증 및 한계

- 코드 Commit: `c4f5d4d98b808ebfc691fb0739a9a0c26ad1f24b`. 설치 Release 및 기존 Launcher/Pin은 교체하지 않았다.
- 집중 회귀79 PASS. pytest 공유 임시디렉터리 정리 경고49건은 로그에 보존했다.
- Workspace 관련 전체1058 PASS(294.84초), 독립 Export 1058 passed in 293.09s (0:04:53). 실제 Driver 경과는 validation-summary.json을 참조한다.
- 테스트 Guard 위반0. 실제 Root·Native·Host Journal·모델·외부 API 재실행 없음.
- 초기 검증 harness의 AF_UNIX 긴 임시경로로2 FAIL/234 PASS에서 중단된 결과를 보존했다.
  짧은 임시경로로 고친 것은 운영 소켓/Timeout/Assertion 변경이 아니다.
- Ruff check PASS, format1626 files PASS, git diff --check PASS.
- Workspace2회·독립 Export의 Native/legacy/Supervisor/Wheel 해시 일치. 빌드만 수행했다.
- 전체 E2E 재실행은 아직 차단된다. SOURCE_UNAVAILABLE의 실제 하위 원인은 새 계측이 없던 회차에서는 UNKNOWN이며,
  Runtime Cleanup UNVERIFIED와 소비된 Session/승인 기록을 임의로 초기화할 수 없다.
- 이 수정은 진단 유실 보완의 검증이지 Host 원인 해결 또는 FULL_LIVE_E2E_VERIFIED가 아니다.


---

# Authentication SOURCE_UNAVAILABLE RCA — 2026-11-04

## 판정

**실제 SOURCE_UNAVAILABLE의 직접 원인: UNKNOWN. Full Live E2E 재개: BLOCKED.**
`c4f5d4d`/`a9c3a7c`를 기준으로 기존 증거만 읽고 비권한 검증을 수행했다.
현재 설치 Release ec9c913 및 기존 Source/Launcher/Pin/Session/Root 설치는 변경하지 않았다.
개발 변경은 `fix/authentication-startup-evidence-20261104` Worktree에 분리했다.
이 보고서는 과거 Runtime Cleanup UNVERIFIED를 변경하지 않는다.

## 1. 최초 오류와 발생 순서

실제 실행은 067d36a 소스와 Runtime Session `c1f2c795-642b-4c38-b60a-6217922f9db6`를 사용했다.
Root Trial driver29.887157684초 뒤 exit2. 내부 최초 예외는
`AuthenticationLifecycle._start_owned()`의 `AUTHENTICATION_READY_TIMEOUT`이다.
실행 당시 `continuous/authentication_lifecycle.py:257`, 바깥 관측은 `root-trial.py:477`의
`RUNTIME_FIRST_ERROR:ValueError`다. Runtime는 auth READY 이전에 TCX 수신을 시작하지 않았다.

| 기록 | 시각 |
|---|---|
| Authentication child |PID3261118/start_ticks111207070/UID1000|
| child RUNTIME_STARTED |UTC05:34:55.404128|
| COLLECTION_START |UTC05:34:55.463048|
| parent의 auth STOP 요청 |monotonic1112076.070955167|
| Root가 Runtime 오류 관측 |UTC05:35:00.208689|
| Runtime PROCESS_SIGNAL 수신 |mono1112076.147092812 / UTC05:35:00.228552|
| COLLECTION_RESULT SOURCE_UNAVAILABLE |UTC05:35:00.353349|
| COLLECTION_RETRY counter1 |UTC05:35:00.467756|
| auth RUNTIME_STOPPING → STOPPED |UTC05:35:00.818420 → 05:35:02.265584|
| auth ACK/reap/reader join 관측 |mono1112078.709390848|

Runtime의 저장된 wall/monotonic 한 쌍으로 환산한 auth STOP 요청은 약UTC05:35:00.152415이다.
이는 단일 시계 상관 표본이며 전체 구간의 clock 동기성을 증명하지 않는다.
boot ID는 저장된 child Identity와 이번 metadata 조회에서 일치한다.
**SOURCE_UNAVAILABLE 결과의 기록이 Timeout/STOP보다 늦다는 사실과,
그 예외가 내부에서 실제 발생한 시각은 구분해야 한다.** SQL/audit 지연 때문에 앞선 실패가
늦게 기록됐을 수도 있고 STOP 중 명령 종료가 후속 실패로 분류됐을 수도 있다.
COLLECTION_START→RESULT4.890301초를 journalctl 실행시간으로 해석하지 않는다.

### 이전 보고서 시간 필드 해석 정정

이전 result.md의 "Authentication 단계 시작 = mono1112067.771317040" 표기는 정확하지 않다.
실행 소스의 `ContinuousRuntime.run`은 `startup.started_monotonic`을 CONTROL_FLAGS 단계에서
한 번 기록하고 이후 stage 문자열만 갱신한다. 최종 stage=AUTHENTICATION_READY와 그 시각을
결합해 해당 단계 시작 시각이라고 해석하면 안 된다.
2.325608672초의 저장 관측(1112067.771359212→1112070.096967884)은 초기 control I/O이며
자식 생성/READY 대기 이전 구간이다. 이것만으로 자식 생성 후 설정되는5초 deadline 초과를
설명할 수 없다. 실제 단계별 시작시각과 명령/상태 read 지연이 없던 회차의 원인은 UNKNOWN으로 유지한다.
원본 로그/과거 파일은 보존하고 이 문서에서 해석을 정정한다.

## 2. 실제 호출 경로 및 READY

`ContinuousRuntime.run → AuthenticationLifecycle.start/_start_owned → linux_runtime CLI
→ LinuxMonitor.run/tick → collect_with_health → AuthenticationPipeline.collect
→ LinuxAuthenticationCollector.poll → bounded_command(journalctl) → project_journal
→ Queue → Source Store/Correlation → collector=INITIAL_READ 게시` 순서다.

부모는 `AuthenticationLifecycle._observe → asyncio.to_thread(RuntimeStore.observation)`으로
**SQLite 상태와 Audit 무결성**을 읽는다. Authentication READY 전용 Unix Socket 메시지 경로는 없다.
Root TCX socket READY는 Authentication READY가 아니며 Producer 인증 완료도 아니다.

| 분류 | 증거 기반 판정 |
|---|---|
| Collector/child 시작 실패 |child RUNTIME_STARTED 및 COLLECTION_START가 있어 전면 시작 실패로 설명할 수 없음|
| Journal 연결/명령 실패 |실제 command PID·returncode·errno·stderr 부재, UNKNOWN|
| Parser/Queue 입력 오류 |SOURCE_UNAVAILABLE은 CollectorUnavailable 또는 ValueError에서 가능; 실제 하위 예외 부재|
| READY 게시 |첫 healthy COLLECTION_RESULT 없음. 정상 READY 조건 충족 증거 없음|
| READY Socket 전달 |해당 READY 경로는 SQLite observation; TCX IPC 장애로 분류하면 안 됨|
| Runtime READY 관측 실패 |기존5초 안에 일치 identity/RUNNING/정상 collector 상태를 관측하지 못함|
| Startup scheduling/storage |command/SQLite/fsync/throttle 단계별 측정 부재, UNKNOWN|
| WSL2 미지원 |현재 WSL2에서 journald active/socket/journalctl 존재. WSL2 자체를 직접 원인으로 단정 불가|
| 빈 Source |비권한 빈 stdout fixture에서 INITIAL_READ/READY/STOP ACK 검증; 단순0건은 장애가 아님|

저장된 queue cursor0, events0이며 초기 collection은 cursor=None 경로다.
기존 Cursor 재개를 시도한 회차로 해석하지 않는다. Pipeline binding의 collector는
`linux:journal:authentication:pam-failure:v1`이며 현재/실행 소스의 생성 계약과 일치한다.

## 3. Host Scope 및 현재 확인 범위

승인 Source는 `SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 + _COMM=sshd` 필터다.
별도의 `-u` Unit 필터는 없다. 임의의 sshd.service/auth.log 등으로 변경하지 않았다.
호출은 `--no-pager --quiet --output=json --output-fields=<고정 FIELDS> --lines=+16`이다.
Parser는 Cursor/기기 ID/시간 metadata, scalar 및 길이 제한, OpenSSH/PAM 신뢰 필드를 검증한다.
미확인 형식은 추론하지 않는다. 원본 메시지는 downstream 영구 증거에 보존하지 않는다.

현재 일반 사용자 metadata 검사: UID1000, adm supplementary group, journald active MainPID53,
journal socket 존재, journal 디렉터리 두 곳 존재, journalctl executable/systemd255 확인.
실행 당시 Runtime의 UID1000/Groups에 adm4가 있었다. **디렉터리 접근 가능은 개별 Journal
파일의 ACL·해당 Source 읽기·이벤트 존재·파싱 성공 증명이 아니다.**
실제 Journal 이벤트 조회는 수행하지 않았다. Source 이벤트 유무·현재 Cursor·실제 읽기 성공은 UNKNOWN.

## 4. 종료 중 명령 실패 가설과 최소 보강

저장된 Runtime unit은 KillMode=control-group이다. READY Timeout 후 부모의 child STOP과
Root의 Runtime service STOP이 이어졌다. 따라서 Journal subprocess가 종료 신호를 받고
비정상 종료한 것을 SOURCE_UNAVAILABLE로 기록했을 가능성이 있다.
**당시 명령 종료 코드가 없으므로 이 가설을 직접 원인으로 확정하지 않는다.**

확인된 진단 결함: c4f5d4d는 COMMAND_EXIT_NONZERO까지 분리하지만 returncode -15와1,
OS errno 및 command 전후시각을 보존하지 않아 위 가설을 구분할 수 없다.
다음 최소 보강을 수행했다.

- `CommandObservation`: 고정 숫자 필드(returncode, os_errno, monotonic start/end), 추가 필드 금지,
  NaN/시간 역전 거부. command/argv/stdout/stderr/Host payload는 저장하지 않는다.
- `bounded_command` 오류에 해당 관측값을 첨부하고 Health→Runtime 상태/Audit→GUI projection에 전달한다.
- 신호 종료를 자동으로 정상 종료/READY/권한 성공으로 변환하지 않는다. 상태는 기존 SOURCE_UNAVAILABLE 유지.
- 실제 Host 대신 자기 자신에게 SIGTERM을 보내는 무해한 Python 자식으로 -15 보존을 검증했다.
  이것은 실제 Journal이나 과거 systemd 종료 신호 전달의 증명이 아니다.
- 기존15초 명령 Timeout,5초 auth READY 및2/5/8초 제어 계약·승인·Model Admission은 그대로다.

## 5. 추가로 확인된 테스트 결함

전체 회귀 첫 회차는1065 PASS/1 FAIL이었다. GUI 연결 테스트가 `last_collection`만 기다린 뒤
처리 중인3건 중2건을 읽었다. 수집 완료 timestamp는 Queue ingest 이후, Source Store/상관분석
완료보다 먼저 게시되므로 READY 신호가 아니다. `TEST_FIXTURE_RACE`로 분류한다.
기존 Event 차단 회귀에 last_collection 존재와 collector NOT_STARTED의 동시 성립 Assertion을
추가해 잘못된 전제를 확인했다. GUI 테스트는 기존40×0.05초 상한 안에서 INITIAL_READ를 기다린다.
3건·Queue DONE3·조사2건·GUI 재연결·Cleanup의 기존 Assertion은 모두 유지한다.
빈 Journal fixture도 실제 빈 출력처럼 개행을 추가하지 않도록 보완했다. 기존 비어 있지 않은 fixture는 동일하다.

## 6. Cleanup 및 보존

Authentication child: ordered STOPPING/STOPPED, 동일 Identity, exit0, 강제 종료 없음,
reader join/child reap/queue drain/durable 기록으로 **VERIFIED(소유 child 범위)**.
Root: 기존 이번 회차 SERVICE_STOPPED/Audit·socket 없음·target tc/xdp 없음·link/map 없음으로
소유 범위 VERIFIED. 현재 일반 사용자 systemctl metadata도 Collector/DNS inactive, Runtime failed,
모두 MainPID0이며 저장된 세 PID는 부재다. 새 privileged 검사는 하지 않았다.

Runtime Cleanup은 **UNVERIFIED** 유지. TCX 연결 전 실패하여
`CONTINUOUS_STOP_REQUIRES_CONNECTED_OWNER`, `CONTINUOUS_REMOTE_CLEANUP_UNVERIFIED`가 후속 기록됐다.
TCX STOP ACK는 없으며 exit0나 PID 부재로 이를 만들어내지 않는다. Global Kernel Cleanup UNKNOWN.
기존 Ledger81행·Root8경로·Rollback·과거 실패 DB/로그는 변경하지 않았다.

## 7. 남은 검사와 재개 조건

`host-read-review.json`은 실행 영수증이 아닌 승인 요청 초안이다.
기존 Auth 필터·UID1000·첫16건·명령1회·15초·재시도0, 원본 영구 저장/출력 없이
명령 결과와 Parser 계약만 진단하도록 제안한다. Root/Native/DNS/모델/API 권한은 포함하지 않는다.
일반 사용자 단독 진단은 systemd cgroup/namespace 환경의 재현으로 주장하지 않는다.
필요한 TCX/BPF/owned FD 권한 검사는 별도 Scope로만 수행한다.

소스와 Wheel이 바뀌므로 새 Release/Source Binding이 필요하다. 기존 소비 Session·승인 영수증을
승계하지 않는다. Source 원인 확인/필요한 최소 수정, 검증된 새 Binding, 잔류 자원 확인,
정확한 독립 권한과 직접 Scope·sudo, 봉인 모델/LLM 입력 GUI 확인 뒤에만 Full Live E2E를 재개한다.

## 증거

- `.git/authentication-source-rca-20261104/evidence-analysis.json`
- `environment-metadata.json`, `preservation.json`, `host-read-review.json`
- `before-fixture-fix-workspace.log` 및 수정 후 Workspace/Export/빌드 결과
- 원본 `.git/full-reliability-stabilization-20261104T021605Z/final-verified/candidate/native/execution/`
  및 `future-runtime/authentication/`/`authentication-cleanup.json`/`service.sqlite`



## 8. 최종 비권한 검증

- 코드 Commit: `a5441a9c480f62bba0c4f83c128be7cfb7fa20f2`. 기존 설치 Release/Root/Launcher/Pin/Session 변경 없음.
- 집중 회귀34 PASS. 관련 전체 Workspace1066 PASS(300.11초), 독립 Export1066 PASS(293.83초).
- 최초 전체 회귀1065 PASS/1 FAIL은 보존했다. 확인된 TEST_FIXTURE_RACE 수정 후 위 결과를 얻었다.
- Guard 위반0. 실제 Root·Native·DNS·Host Journal 기록·모델·API 실행 없음.
- Ruff check PASS, format1626 files PASS, diff check PASS.
- Native/legacy/Supervisor/Wheel: Workspace 두 빌드와 독립 Export 해시 일치(compile only).
  Supervisor 검증은 기존 보존 package의 prepare_supervisor_image 경로다. 새 Root 설치 검증을 의미하지 않는다.
- Wheel SHA-256: `59479b3738d71060823f57bb550bf75e488cc4a3a1d3a9afee180a9e7c2cc45e`.
- Source682개 Workspace/Export 일치. Ledger81행 SHA와 원본 실패 DB/로그 해시 보존 확인.
- Root8개 SHA·inode·mtime은 직전 읽기 전용 기준과 모두 일치. 백업/설치/증거 수정 없음.
- 현재 코드 위치: `realtime/collectors.py:30,80`, `security_ai/operational/journal_health.py:41,82`,
  `linux_runtime/service.py:389`. READY Timeout의 현 코드 위치는
  `continuous/authentication_lifecycle.py:268`이며 실패 당시 소스의257행과 구분한다.

**결론:** 진단 유실 보강과 비권한 회귀 완료. 실제 Host Source 장애 원인 UNKNOWN,
Runtime Cleanup UNVERIFIED, 전체 Live 재개 BLOCKED. 새로운 Source/Wheel Binding과
독립 Host 읽기 진단 승인, 필요한 잔류 검사 및 새 Live 승인이 필요하다.
`host-read-review.json`은 승인되지 않은 검토 초안이며 실행 영수증이 아니다.

원본 상세 로그는 `.git/authentication-source-rca-20261104/`에 보존한다.
원격으로 보존할 안전한 요약은 이 문서 인접
`evidence/authentication-source-rca-20261104/`에 저장했다.
