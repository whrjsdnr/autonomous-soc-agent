# Full E2E Reliability 최종 안정화

## 기준선과 증거 복원

운영 기준 b7505ca / 보고 cc96f92를 보존하고, 같은 release/research-demo-mvp Worktree에서
비권한 조사·수정을 수행했다. 주 Worktree의 사용자 변경은 stage하거나 덮어쓰지 않는다.
Root·Native·DNS Live·Host Journal·실제 모델·외부 API는 실행하지 않는다.

기준선의 일반 디스크/tmpfs × Workspace/Export 로그에서 실패 8건을 추출했다.
그보다 오래된 최초 8초 실패와 중간 수정본 실패 2건도 별도 역사 범주로 보존한다.
테스트별 경과 시간·PID·Thread·monotonic이 원본에 없으면 UNKNOWN이다.
suite 전체 시간이나 다른 시험 PID를 해당 테스트의 측정값으로 대체하지 않는다.

| 환경 | 실패 테스트 | 최초 관측/기대 | 원인 판정 |
|---|---|---|---|
| Workspace/디스크 전체 | ten_second_write_does_not_block_heartbeat_or_stop | 18 sampled sequences <20; DEGRADED/게시 오류 없음 | UNKNOWN. CPU/디스크 지연을 분리할 자료 없음 |
| Workspace/tmpfs 전체 | closed_without_process_exit_remains_unverified_at_shared_deadline | 5.5초 대기 Timeout; CLOSED+살아 있는 Helper는 UNVERIFIED여야 함 | UNKNOWN. 실제 종료·durable commit·스케줄링 지연 단정 불가 |
| Workspace/tmpfs 전체 | dns_status_reader_lock_does_not_block_control_or_stop | 읽기2회/기대1회 | TEST_FIXTURE_RACE. 동시 요청이라는 전제 미확보 |
| Workspace/디스크 집중 | owned_child_ready_ingestion_gui_cache_stop_ack_and_durable_cleanup | AUTHENTICATION_CLEANUP_UNVERIFIED | 과거 직접 원인은 UNKNOWN; 보존 영수증은 forced/-9/ACK=false |
| Export/디스크 집중 | invalid_model_grants…[changed_input] | fixture Authentication READY/정리 실패 | UNKNOWN. IF 승인 Assertion 전 실패 |
| Export/디스크 집중 | composed_packet_dns_authentication_mock_e2e_one_parent_session | fixture Authentication READY/정리 실패 | UNKNOWN. 실제 Native/API 결과 아님 |
| Export/디스크 집중 | existing_sshd_success_and_failure_share_training_feature_contract | AUTHENTICATION_READY_TIMEOUT 후 Cleanup 미검증 | UNKNOWN. 모델 Feature 계약 실패로 해석하지 않음 |
| Export/tmpfs 집중 | invalid_model_grants…[rejected] | AUTHENTICATION_CLEANUP_UNVERIFIED | UNKNOWN. 실제 미승인 모델이 실행된 증거 아님 |

첫 Workspace Heartbeat 실패의 보존된 Control identity PID는3029128, 마지막 monotonic은
1098363.499396942, sequence28, 최대 게시 지연1.123329855초였다. Observer 표본은18개였다.
모든 표본을 전달해야 한다는 모델 권한 계약과 5초 liveness lease를 혼동하지 않는다.
기존 >=20 Assertion은 이번에도 그대로 유지했다.

보존된 Authentication Cleanup 한 회차는 요청1099235.587324234→관측1099240.678889787,
5.091566초, forced=true/returncode=-9/STOP ACK=false였다. 수집 Queue DONE3/drained=true지만
조사 RUNNING1/PENDING1이었다. 이것을 전체 처리 완료나 Cleanup 성공으로 바꾸지 않는다.

## 재현과 최소 수정

### Control Loop에서 동기 Authentication I/O 실행

기존 LinuxMonitor.tick/조사에서 Journal 명령·SQLite·Queue·Source 검증이 async 함수 안에서
동기 실행됐다. 소유 fixture에 thread identity 검증을 주입하면 수집과 read-only 증거 읽기
모두 Control Loop thread에서 실행되어 실패했다. **PRODUCTION_STATE_RACE**로 분류한다.
과거 모든 Timeout이 이것 때문이었다고 확대하지 않는다.

기존 I/O를 직렬 storage 경계의 to_thread로 옮겼다. 실제 Tool/Policy/Parser/DB/Audit 구현과
payload는 유지한다. read-only Tool의 Source 검증도 같은 의미로 실행하되 Event Loop 밖에서
수행한다. 취소 중에도 소유 I/O를 shield/join하며 두 번째 취소가 Join을 끊지 않도록 한다.
완료되지 않은 Thread를 둔 채 STOPPED·VERIFIED를 기록하지 않는다.

### READY 게시 순서

collector=INITIAL_READ가 Queue→Source 최초 배치 처리보다 먼저 게시됐다.
pipeline.step을 Event로 막으면 아직 PENDING3인데 READY 조건이 보이는 것을 재현했다.
**STARTUP_ORDER_RACE**다. 정상 Collector 상태는 최초 bounded 배치와 관련 Evidence 처리 후,
Investigation **전**에 게시한다. 초기화가 LLM/조사 완료를 기다리는 구조로 바꾸지 않는다.
빈 Journal도 정상적인 빈 수집이며, 이벤트나 적격 IF 입력을 만들어내지 않는다.
권한 거부·gap 등 실패 상태는 계속 즉시 보존한다.

### STOP ACK의 중첩된 5초 대기

외부 AuthenticationLifecycle은 소유 child 종료를5초 기다리는데, child는 STOP 후에도
조사에 다시 전체5초 grace를 사용했다. 비동기 조사를 Event로 막아 STOP을 요청하면
durable ACK에 사용할 시간이 남지 않는 구조를 재현했다. **STOP_ACK_RACE**다.
명시적 operator/SIGTERM STOP은 read-only 작업을 즉시 취소하고 기존 Checkpoint/Join을
거쳐 종료한다. 자연 duration 종료의 기존 grace와 외부5초 한도는 유지한다.
API가 불확실하게 제출된 경우의 기존 UNKNOWN/재시도 차단도 유지한다.

### Timeout 후 살아 있는 상태 Reader

첫 수정 후보의 Export/디스크에서 READY 실패를 실제 계측으로 포착했다.
Parent PID3086338/child3087011. Spawn1100934.303754854 이후 상태 읽기 하나가
1100936.113687751→1100939.601743188, 3.488055초 걸렸다. start는 그보다 먼저
1100939.309422596에 Timeout으로 반환했다. 해당 회차의 close는 이후 exit0/ACK/Cleanup
VERIFIED였으므로 그 과거 Cleanup을 임의로 실패로 바꾸지도 않는다.

wait_for(to_thread(...))는 Timeout 때 Thread를 종료하지 않는다. Reader가 소유자 실패 후
계속될 수 있는 **CLEANUP_RACE**를 확인했다. 현재는 Reader task를 추적/shield하고
Cleanup 판정 전에 남은 기존 STOP 예산 안에서 Join한다. Join 실패는 UNVERIFIED다.
상태·설정·전체 Audit 검증을 하나의 읽기 Snapshot에 모아 DB open을4회→2회로 줄였다.
검증이나 권한을 생략하지 않으며 config/audit/state 변조 거부 테스트를 추가했다.
open 수 감소를 해당 3.49초 지연의 원인이 밝혀졌다는 주장으로 사용하지 않는다.

### 불필요한 ML cold import와 Fixture 시작 비용

Host READ_ONLY CLI가 ResponseSimulation의 AssessmentResult/데모 도구의 annotation을 통해
ingestion→governance→assessment/fusion→학습 라이브러리를 미리 로드했다.
importtime과 별도 프로세스 검사에서 NumPy/sklearn 로드를 확인했다.
실제 사용하는 지점으로 기존 import만 이동하고 annotation은 TYPE_CHECKING으로 분리했다.
기존 모델·Fusion·평가 알고리즘을 변경하지 않는다. 실행 전후 import 검사 로그를 보존한다.

테스트 child는 row()를 얻으려고 pytest와 테스트 모듈까지 import하고 있었다.
기존 row 함수로 Parent에서 동일 레코드를 준비하고, child는 Journal 명령 경계만 Mock하며
실제 CLI·Signal Handler·Parser·Queue·Store·Runtime을 재사용한다. child에 테스트 프레임워크가
로드되지 않음을 검증한다. 이 변경을 실제 Host 수집 성공이라고 보고하지 않는다.

### DNS Fixture의 요청 순서

기존 두 task를 동시에 생성해도 data snapshot은 DB를 먼저 읽는다. DB가 지연되면 Control의
DNS 읽기가 먼저 완료되고, data snapshot의 뒤늦은 요청은 새로운 읽기가 필요하다.
Event로 이 순서를 제어해 읽기2회를 재현했다. 이것은 동시 읽기 coalescing 실패가 아니다.
기존 테스트가 의도한 동시 요청은 data reader가 실제로 진입한 후 Control을 시작하도록
설정한다. >=2 sequence/age<2/STOP<0.5s/읽기1회 Assertion은 변경하지 않았다.
필요한 최종 Cleanup 상태 읽기를 생략하거나 stale 상태를 재사용하지 않는다.

## 검증 과정의 실패도 보존

원래 실패11개(과거 코드3개 포함)·첫 controlled 재현·중간 후보의 실패 로그를 삭제하지 않는다.
최초 기존 테스트 11개는 네 환경에서 각각 통과했지만, 그것만으로 안정화됐다고 선언하지
않았다. 확인된 생산 코드/Fixture 결함을 별도 Event 제어 테스트에서 재현하고 수정했다.

중간 후보 after-3/tmpfs Export에서도 READY 실패1건이 발생했다. Parent3110267/child3110931,
Spawn1102068.386389728→start 실패1102073.403107331이다. 마지막 관측은 RUNNING이지만
collector NOT_STARTED였다. close는0.348879초 안에 exit0/ACK/Reader Join/Cleanup VERIFIED였다.
이 경우의 구체적인 CPU/I/O 원인은 UNKNOWN이다. 후속 fixture에 Script/도메인 import/
서비스 import/초기화/Run/STOP의 monotonic·CPU time·PID·thread 계측을 추가했다.

Fixture 정리 중 기본 메시지가 성공 로그인으로 바뀐 중간 실수도 있었다. 해당 after-4
결과는 PASS여도 acceptance에서 제외했다. 원래의 Failed password 레코드로 복구하고,
실제 parser를 통한 실패3건 및 명시적 성공/실패 혼합 입력의 golden 검증을 추가했다.
인증 판단 결과를 바꿔 시간 테스트를 통과시키지 않는다.

2초·5초·8초 계약, 기존 Assertion, Source/Root/Namespace·Model Admission·API 승인은
완화하지 않았다. 테스트를 통과시키기 위한 sleep이나 테스트 삭제도 없다.

## 전체 회귀에서 추가로 확인한 DNS Fixture

첫 전체 Workspace 회귀는909 PASS / 1 FAIL이었다. 실패는
`test_delayed_heartbeat_stops_admission_but_drains_owned_cleanup[quarantine]`이다.
Parent3129980/Thread127263448053568, call 경과11.942481초, 실패 관측 monotonic
1102961.103609199였다. 기대한 최초 HELPER_HEARTBEAT_OR_PROCESS_STALE 대신 바깥7초
대기의 Timeout이 드러났다. Cleanup에는 원래 stale 오류가 보존됐으며 UNVERIFIED였다.

영수증의 STOP 요청1102949.504397072/한도1102954.504397072는 정확히5초다.
Helper3130414는 관측 당시 ALIVE, quarantined0/CLOSED 없음, 실패 STOP 경과6.192440초였다.
실제 Kernel Helper가 아니라 테스트가 생성한 일반 UID AF_UNIX peer의 기록이다.

이 Fixture는 STOP을 받고 나서 `tests.total_monitoring_support.dns_packet`을 import했다.
그 import는 다른 테스트 모듈과 학습/ML 의존성까지 로드한다. 별도 계측에서는
STOP1103274.272050928→Packet 준비1103275.554964026, CLOSED1103275.555315851로,
유휴 환경에서도 약1.283초를 사용했다. 처음 진단 script의 누락 import 오류도 보존하고
그 잘못된 계측 회차를 제품 실패나 통과 근거로 사용하지 않았다.

**TEST_FIXTURE_RACE**인 불필요한 cold import를 STOP 경로에서 제거했다. 같은 기존 함수로
Parent에서 Packet을 미리 구성하고, child는 검증된 PacketObservation JSON을 복원한다.
기존 stale2초/STOP5초/테스트7초, quarantined1/실제 전달0, ACK·소켓·Thread·Cleanup
Assertion은 그대로다. 실제 Packet 트래픽을 생성한 것이 아니다.
이 조치는 전체 실패 순간의 구체적인 CPU 대기/디스크 syscall 원인까지 입증한 것은 아니다.
후속 집중 회귀에 이 테스트를 포함한 뒤 전체 회귀를 다시 진행한다.

## 최종 고정 소스 결과

집중 검증이 안정적으로 통과한 후에만 전체 회귀 Gate를 연다.
최종 환경별 횟수·경과 시간·실패·Cleanup, 전체 회귀와 재현 빌드 결과는 검증 완료 후
이 절과 portable verification JSON에 고정한다. 현재 단계의 상태를 Live 성공으로 해석하지 않는다.

## I/O 분리 후보의 Commit·취소 경합 보완

다음 후보에서는 전체 관련 회귀가 네 환경 모두910 PASS였으나, 일반 디스크 Authentication
집중 회귀에서1건/3건의 종료 실패가 확인됐다. Workspace의
`test_cleanup_evidence_write_failure_does_not_publish_verified`는 의도한 Disk Full 예외 이후
child exit0/ACK를 기대했지만 실제 exit1이었다. Parent는 Cleanup 성공을 표시하지 않았다.
child3167284의 STOP1104617.586820795→Run 종료1104617.743254548를 보존했다.

Audit에는 `INVESTIGATION_DONE_READ_ONLY` 다음 `RUNTIME_FAILED(ValueError)`가 있었고,
같은 finding은 이미 DONE이었다. I/O 분리 후 commit은 끝났지만 await 반환 전에 취소되면,
기존 CancelledError handler가 같은 작업을 PENDING으로 다시 finish하려는 경합이었다.
**PRODUCTION_STATE_RACE / STOP_ACK_RACE**로 분류한다. 기존 strict finish 검증은 올바르게
`STALE_INVESTIGATION_COMPLETION`을 거부했다. 이 검증을 idempotent 성공으로 바꾸지 않았다.

commit 직후 Worker를 Event로 막은 테스트에서 동일 예외를 재현했다. Claim commit 직후
취소되는 경우도 제어하면 미시작 작업이 RUNNING으로 남았다. 두 테스트는 수정 전 모두
실패했다. 현재는 Join된 Worker의 실제 claim/completion 결과를 호출자가 보존한다.
완료된 결과는 유지하고, 아직 조사하지 않은 claim만 PENDING으로 반환한다.
LLM 호출이 시작된 취소의 기존 BLOCKED/UNKNOWN·중복 호출 차단은 유지한다.
실패 Audit에는 Payload/예외 메시지 대신 type·monotonic·PID/thread·함수/행을 보존해
바깥 종료 코드와 최초 오류 위치를 구분할 수 있도록 했다.

이 후보의 실패 로그·DB에서 읽은 상태·재현 Trace는 최종 통과 회차와 구분한다.
과거 Native 실패나 이전 Source에 이 새 경합이 있었다고 소급 주장하지 않는다.

## 최신 후보의 고부하 구간 실패 — 통과 회차와 분리

`commit-fixed-1-workspace-disk`는22 PASS/8 FAIL이다. 같은 소스의 Export 일반 디스크와
Workspace·Export tmpfs는 각각30 PASS였다. 8개 실패의 Assertion·실제 경과·PID/thread·
monotonic·Cleanup은 `failure-classification.json` 및 raw events에 보존한다.
Heartbeat에서2.418194초의 관측 Age, CLI 자식 종료10초 초과, Authentication 초기화5초
경계, DNS RUNNING3초 경계, 새 Event 기반 READY 테스트의1초 경계가 실패했다.
Authentication 자식3178777은 STOP을1105113.392353160에 받았지만5초 내 종료하지
못해 -9/forced로 정리됐고 Cleanup은 UNVERIFIED다. 자식3180641·3179845는
초기화 중 SIGTERM 종료(-15)로 ACK가 없었다. 실패를 VERIFIED로 변경하지 않았다.

실패 직후 시스템 PSI I/O full avg10=10.94%·some avg10=15.51%, CPU some
avg10=4.86%였다. 현재 검사 프로세스의 init.scope CPU throttled counter는0이다.
이 Snapshot은 실패별 스케줄링/fsync를 직접 측정한 자료가 아니므로,
각 실패의 근본 원인은 UNKNOWN으로 유지한다. 후속 통과나 낮아진 PSI를
이 실패 원인이 해결됐다는 증거로 사용하지 않는다. 기존2/5/8초와 Assertion은 유지한다.

## 커밋·파일 경계와 재현 자료

- `d099d95`: Authentication 동기 I/O 분리·READY 순서·STOP 예산·Reader Join·가벼운 CLI import,
  DNS 동시 읽기 Fixture 전제 및 회귀. 기존 Native TCX 수집 구현을 교체하지 않는다.
- `a51ebb2`: DNS STOP 이후 테스트 모듈 cold import를 제거하는 Fixture 준비 순서 수정.
- `067d36a`: 완료/Claim commit과 STOP 취소의 경합 보완. 새로운 Claim 경합 테스트에서는
  수집·상관분석을 먼저 완료한 뒤 실제 `investigate_one()`의 Claim을 제어한다.
  기존2초 Event 대기·3초 Worker 대기·상태 Assertion은 유지하며 PENDING2 준비 Assertion을 추가했다.

핵심 운영 경로는 `linux_runtime/service.py:161(storage)`, `:176(investigate_one)`,
`:377(tick)`, `:440(run)`, `linux_runtime/store.py:109(observation)`,
`continuous/authentication_lifecycle.py:171(_observe)/:177(_join_reader)/:288(close)`,
`security_ai/operational/authentication_investigation.py:300(_joined_read_view)`다.
행번호는 운영 코드067d36a를 기준으로 한다. UI는 기존 backend projection을 재사용한다.

최초 수집·저장 지연이 생산자 TCX 송신 공백의 직접 원인이라는 새로운 주장은 하지 않는다.
이번 검증은 일반 사용자 환경의 Fixture·Mock·read-only 처리에 한정되며,
승인된 Native cgroup CPU25%/50% 환경을 실제 실행한 것이 아니다.
과거 Native CPU Throttling 비율과 메시지 공백의 인과 UNKNOWN도 그대로다.

테스트의 Exit0는 해당 Assertion 통과다. 실패 주입에서 요구되는 Cleanup UNVERIFIED,
미승인 모델/API BLOCKED, Queue PENDING 보존은 정상 기대 결과이며,
모든 자원이 언제나 VERIFIED라는 뜻이 아니다. 실제 Host·RF/LR·IF·LLM을 호출하지 않았다.

## 최종 고정 소스의 검증 결과

운영 코드 `067d36a65962518adc89191d8980f2096389d45a`를 고정했다.
기존 베타/실패 회차를 지우지 않고, 마지막 준비 Fixture 수정 후 네 환경 집중 회귀가
각각30 PASS인 것을 확인한 뒤 아래 전체 관련 회귀를 순차 수행했다.

| 결과 파일/환경 | 결과 | 실제 driver 경과초 |
|---|---|---:|
| export-test-result.json | 910 passed in 195.64s (0:03:15) | 197.285 |
| export-tmpfs-test-result.json | 910 passed in 176.10s (0:02:56) | 177.752 |
| extra-export-disk-result.json | 34 passed in 9.65s | 11.213 |
| extra-export-tmpfs-result.json | 34 passed in 5.13s | 6.744 |
| extra-workspace-disk-result.json | 34 passed in 9.97s | 11.448 |
| extra-workspace-tmpfs-result.json | 34 passed in 4.95s | 6.372 |
| supplement-export-result.json | 123 passed in 90.00s (0:01:29) | 90.761 |
| supplement-export-tmpfs-result.json | 123 passed in 50.47s | 51.144 |
| supplement-workspace-result.json | 123 passed in 94.69s (0:01:34) | 95.356 |
| supplement-workspace-tmpfs-result.json | 123 passed in 49.81s | 50.525 |
| workspace-test-result.json | 910 passed in 203.43s (0:03:23) | 204.958 |
| workspace-tmpfs-test-result.json | 910 passed in 173.65s (0:02:53) | 175.170 |

관련 회귀는 Continuous/DNS/TCX protocol·Heartbeat·Queue·STOP/Cleanup·GUI·
RF/LR/IF Admission·LLM Mock·SOCRuntime·Orchestration을 포함한다.
Authentication 보충은 기존 Journal 명령 경계만 Fixture로 대체한다.
모델을 실제 로드/추론하는 `test_runtime.py`, `test_capture_admission.py`,
`test_stream_integration.py`는 제외하되 후자의 Root Resource Contract 테스트는 실행했다.
전체 저장소의 모든 테스트나 실제 모델 Action을 실행했다고 주장하지 않는다.
12개 테스트 프로세스의 Guard 위반0, Source·테스트1487개 고정 일치다.

Native BPF/User Space·기존 Supervisor·Wheel은 Workspace2회/독립 Export1회 빌드에서
각 artifact SHA가 모두 일치했다. compile-only이며 Load/Attach/실행은 없다.
Wheel SHA `6e42d89adbb1909f42aae2861b26472b221bdabb9746ea1cb79c7c46c8acf1f1`.
Ruff Check PASS, Format1627개 PASS, Diff Check PASS.
기존 세 테스트 파일의 Assertion276개 AST는 cc96f92와 동일하다.

## 실행 준비의 메타데이터 정합성

새 Source 고정 뒤 준비 스크립트가 Model/API 제안서의 과거 Source SHA/Commit을
유지한 결함도 찾았다. 아직 PENDING인 두 제안서만 새 Source에 맞췄고, 실행 핀을
재계산한 뒤 기존 verify_review를 통과했다. Source/운영 코드 변경이나 승인 발급은 아니다.
과거 값·새 값·검증 결과는 candidate-proposal-reference-alignment.json에 보존했다.
Source682개, 새 Session, Root Manifest·기존 Ledger81행의 새 후보 Binding을 확정했다.
Root 변경 후보3개/검증 전용5개이며 실제 설치·백업 생성·교체는 수행하지 않았다.

## 최종 판정과 남은 조건

**PARTIALLY_READY**. 확인된 I/O/READY/Reader Join/STOP/취소 커밋 결함은 수정됐고
최종 고정 소스의 네 환경 회귀·재현 빌드는 통과했다. 하지만 이전 같은 운영 코드의
고부하 구간 시간 경계 실패를 후속 통과로 소급해서 해결 처리하지 않는다.
개별 실패의 CPU Scheduling·Disk I/O·Lock 인과는 UNKNOWN이다.
따라서 전체 시간 경계 안정성이 확정됐다는 무조건적 FULL_E2E_READY를 선언하지 않는다.

전체 Live 검증은 **NOT_EXECUTED / BLOCKED_PENDING_APPROVALS**다.
새 정책·검증 Release 선택/Update·잔류 소유권 검사·Root/Native/DNS/R1/R2·
Host 읽기·봉인 작업별 RF/LR/IF·실제 Incident/API 입력 승인이 독립적으로 필요하다.
현재 정책은 만료됐으며 새 제안은 활성화하지 않았다. 직접 Scope/sudo 인증도 수행하지 않았다.
과거 Native 장시간 실패·Global Kernel Cleanup·실제 Host IF·LLM Assessment의 미검증을
이번 Mock/Fixture 결과로 성공 처리하지 않는다.

[실행 검토안과 정확한 명령](Full_E2E_Reliability_Live_Review.md),
[최종 검증 요약](evidence/full-reliability-20261104/final-verified/Acceptance_Summary.json),
[증거 SHA 인덱스](evidence/full-reliability-20261104/Index.json)를 따른다.

## 증거 보존 범위와 자료 공백

주 Worktree 사용자 파일164개, 기존 Native/실패 증거797개는 원래 SHA 그대로다.
Root8은 SHA·inode·mtime이 동일하며 기존 Ledger81행 SHA는
07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae다.
설치 manager는4e4fb2c90c3a9467-57f8c396184bc1f8로 그대로다.

이번 작업의 첫 전체 회귀 quarantine 실패 후 임시 pytest basetemp가 다음 회귀에서
재사용되어, 그 임시 Cleanup JSON의 원래 바이트는 남아 있지 않다. 원본 실패 로그와
phase 기록은 남아 있고, 당시 도구로 읽은 값만 `quarantine-cleanup-derived.json`에
재구성했다. 이를 원본 영수증 SHA 검증이나 durable 원본으로 제시하지 않는다.
이후 회차는 고유 basetemp를 사용하고 실패 Fixture·Trace를 따로 보존했다.
기존 사용자 증거797개에는 영향을 주지 않았다.
