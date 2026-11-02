# Native DNS Helper Heartbeat 반복 장애 RCA 및 비권한 수정

기준 보고 Commit `7cd2d61`. 실제 Native20분 시험과 Replay20분 성공 증거를 보존했다.
이번 작업의 실제 Root 설치·Native Capture·DNS 트래픽·외부 API·Native 모델 Action은 모두0회다.

## 판정과 한계

**관측된 최초 장애는 수신 Heartbeat Age 초과이며, 과거 Native 장애의 근본 원인은 UNKNOWN이다.**
Helper가 최초 오류 시 종료됐다는 증거는 없다. 이후 동일한 인증 채널에서 CLOSED와
최종 Counter를 받고 실제 EXITED를 관측했다. 최초 Stale을 Helper Crash로 단정하지 않는다.

별개로 기존 코드의 Reader poll/deadline 경합과 stale consumer/queued heartbeat 경합을
비권한으로 재현·수정했다.
해당 결함이 과거 Native 실패의 직접 원인이었다는 인과 증거는 아직 없다.
수정본의 실제 Native 성공이나 Runtime Cleanup VERIFIED를 주장하지 않는다.

## 기존 실행 증거

- Helper PID867318 / StartTicks93644092; 인증된 UID/GID1000, effective/permitted/ambient
  capabilities0. 기존 Namespace net:[4026532232].
- 2026-11-02 13:48:29.859795 KST DNS Reader 실패:
  HELPER_HEARTBEAT_OR_PROCESS_STALE, Age2.015534초 / 기존2초 bound,
  reader poll gap 최대3.643053초, reader queue0 / high-water12/32, counter issue 없음.
- Root observer는13:48:30.892529 KST 해당 Runtime 오류를 CAPTURE 최초 오류로 보존.
- Helper는 STOP 후 authenticated CLOSED, 최종 Counter와 process EXITED 증거를 남겼다.
  CPU1.263376초 / Helper elapsed41.196540초. 평균값은 순간 throttling 부재의 증거가 아니다.
- 후속 TCX Producer timeout:5.000173초, 동일 Root PID/start와 연결 IPC,
  queue0/drop0. 마지막 Control stage INSTALLED_INTEGRITY. 원인은 별도 UNKNOWN.
- Runtime Cleanup에는 TimeoutError와 DNS CaptureUnavailable이 secondary error로 보존됨.
  과거 기록에는 Timeout await origin이 없어 어느 join/await인지 확정할 수 없다.
- TCX STOP ACK·DNS Helper 소유 Cleanup·기록된 Root Scope Cleanup은 기존 판정을 유지하고,
  Runtime·Global Kernel Cleanup UNVERIFIED를 소급 변경하지 않는다.

## 구간별 판정

| 구간 | 기존 Native 증거 판정 |
|---|---|
| Heartbeat 생성 중단 | UNKNOWN: 생성 시각/sequence 미기록 |
| 생성 후 송신 blocking | UNKNOWN: send 시작·완료 미기록 |
| 송신 후 수신 scheduling/IPC 지연 | UNKNOWN: Reader gap만 있고 send/queue 원시 기록 없음 |
| Runtime 수신 후 상태 게시 지연 | 게시 최대3.642816초 계측, 직접 원인·발생 구간 중첩 UNKNOWN |
| 오래된 Observer 상태 | 최초 오류는 Helper Reader 자체에서 발생. 단순 GUI stale 화면만의 문제는 아님 |
| Helper 실제 종료 | 최초 오류 시 증거 없음. 이후 CLOSED 수신 및 종료 확인 |
| cgroup CPU throttling·GIL·호스트 scheduling | UNKNOWN: 해당 시점 CPUstat/stack/scheduler 증거 없음 |

기존 서로 다른 프로세스의 DNS emit clock/time Namespace 증거가 없으므로, Helper PID start
혹은 wall time으로 정확한 송신-수신 지연을 만들어내지 않았다. 수신 프로세스의 STOP
monotonic과 ACK 관측 순서는 기존 증거 범위에서 비교한다.

## 확인·수정한 코드 결함

기존 DNS Reader의 select(timeout)가 빈 결과를 반환한 뒤 Thread가 deschedule되면,
그 사이 도착한 정상 Heartbeat를 다시 확인하지 않고 check_reader_liveness에서 실패했다.
수신 대기 여부와 Deadline 판정 사이의 경합이다. 7cd2d61의 원본 함수를 그대로
실행한 ordinary AF_UNIX 재현에서 Stale이 발생했고, 새 Reader는 동일 대기 메시지를
검증해 처리했다. confirmed-reader-race.json으로 남겼다.

기존 HelperCapture.statistics도 소비자가 호출할 때 캐시된 last_heartbeat가2초보다
오래됐으면 IPC에 정상 Heartbeat가 대기해도 즉시 실패했다. Reader thread가 deschedule된
상황에서는 수신자가 처리할 수 있었던 메시지와 실제 peer silence를 구분하지 못한다.

보존된7cd2d61 원본 statistics 함수를 실제 ordinary AF_UNIX fixture에 적용하자,
소켓에 정상 Heartbeat839bytes가 대기한 상태에서 동일 Stale이 발생했다. 수정 함수는
같은 메시지를 기존 Session·Sequence·Counter·identity 검증으로 처리해 성공했다.
패킷 전달0·Cleanup 승격False를 확인했다. 증거 confirmed-consumer-race.json.

수정은 bounded64 records, 기존 reader_lock으로 수신을 직렬화한다. Packet은 기존 bounded
Queue·seal accounting을 거쳐야 하며, counter/identity 위반·Queue full은 계속 실패한다.
빈 IPC는 기존2초에 실패한다. Deadline 증가·새 권한·재연결·재시도는 없다.
소비자가 CLOSED를 먼저 수신한 경우 Reader가 이를 다시 Stale로 분류하지 않도록 종료
조건도 보강했다. 완료 판정·STOP ACK·Capture Admission은 기존 검증을 유지한다.

## 진단 보강

DNS Helper에서만 새 structured transport trace를 명시적으로 활성화한다. 기존 일반
stream/total helper 기본 wire 동작은 유지한다. trace는 권한이나 Counter 대체 증거가 아니다.

- 모든 DNS message의 trace sequence, PID/start, Boot ID, Time Namespace.
- 생성 monotonic_ns·wall_ns, 직전 send 시작·성공 완료 monotonic_ns.
- 현재 receive monotonic_ns·wall 관측 시각과 직전 decoded receive.
- 동일 Boot/Time Namespace·process identity·순서 검증 후에만 cross-process latency 계산.
- 마지막 send completion은 다음 메시지가 와야 관측되므로 마지막 미수신 요청은 UNKNOWN.
- READY/최초 failure의 PID identity·nice·schedstat·cgroup cpu.stat(cpu throttling)/cpu.max.
  권한 부족·process exit·counter 부재는 UNKNOWN/UNAVAILABLE, Cleanup 성공 근거가 아님.
- 최초 failure 시 FIONREAD bytes·SO_RCVBUF/SO_SNDBUF, reader queue·poll gap.
  FIONREAD bytes를 메시지 개수 또는 payload로 해석하지 않는다.
- 상태 snapshot의 monotonic 관측 시각과 transport trace를 기존 GUI Backend에 전달.
- Runtime secondary Cleanup 오류에 traceback file/function/line 최대4개를 추가해 다음
  Timeout의 정확한 await 지점을 남김. frame locals·비밀번호·API Key·packet payload는 기록 안 함.

부가 진단을 읽기 위해 Root 명령을 실행하지 않는다. self/peer의 허용된 proc/cgroup 파일만
읽는다. 기존 fixed Helper·Source hash binding이 변경되므로 기존 승인 영수증은 재사용 불가다.

## 비권한 검증

최종 집중 프로토콜/Lifecycle 검증518건 PASS / 별도 retained-session opt-in1건 SKIP: 정상 Helper trace 생성, 기존 send timeout/STOP/counter/drop 경계,
queued heartbeat 경합·실제 silence, bounded backlog, trace replay/clock domain/identity 위반,
ordinary AF_UNIX socket backpressure, simulated cpu.stat throttling delta, CLOSED 경합,
최초 실패 diagnostic 및 Cleanup 비승격.

실제 cgroup quota를 설정하거나 Native Helper를 실행한 검증이 아니다. CPU quota pressure는
counter fixture로 구분하며, 실제 Kernel throttling에서의 안정성은 미검증이다.
기존 DNS Lifecycle/Runtime 회귀에서 Helper Exit7, heartbeat/ACK 지연·누락, Cleanup 실패,
SQLite10초 지연·lock/backpressure, GUI 지연·재연결 경로도 확인한다.

최종 Workspace·독립 Export는 각각 **1,443 PASS / 1 SKIP**다.
실제 경과 시간은 pytest 기준637.09초 /638.05초이며, 가상 이벤트 시간과 구분한다.
두 실행의 Source SHA는 동일한
`e9fb676994dab1e1c8fb99ba08b5ac935521e4331794234372078d23f946d60d`이며 검증 중 불변이다.
Continuous·DNS·Storage/SQLite·Control·SOCRuntime/LLM mock·Model Admission·GUI·
Source Guard·CLI·Network Capture·Streaming·Direction 회귀를 포함한다.
SKIP1은 별도 retained-session 읽기 opt-in이 없어 실행하지 않은 기존 검사다.

Ruff check PASS, Format1,547파일 PASS, git diff --check PASS.
Native6종·legacy native compilation·guarded Supervisor2종·Wheel은 Workspace2회와
독립 Export1회 SHA가 모두 일치했다. Kernel Load나 privileged Supervisor 활성화는 하지 않았다.
Wheel SHA:
`7ece3838bec175198dc5ee9260c6c86e42bdee3cefdc35ef345781b8d8474cf9`.
패키지 내부 Source672개 byte 비교·ZIP CRC·Manifest3종 검증이 통과했고,
패키지의 일반 사용자 Capture 권한 검사도 정상 거부했다.

기존 실패/성공·Replay 증거 및 Ledger를 포함한82개 SHA가 불변이며,
현재 Root 설치8경로는 기존 승인 시험의 설치 후 SHA와 일치한다.
기존81행 Ledger를 변경하지 않았다. 소유 FD/socket·Helper/Runtime cleanup의
실제 Native 과거 판정은 그대로다. 이번 테스트의 소유 자원 정상/실패 정리는
비권한 테스트 결과이며 과거 Runtime Cleanup 승격 근거가 아니다.

검증 증거:
`.git/dns-heartbeat-rca-20261102T045501Z/`의
`rca-timeline.json`, `confirmed-reader-race.json`, `confirmed-consumer-race.json`,
`preservation-final.json`, `final/workspace-recovery-final-result.json`,
`final/export-recovery-final-result.json`, `final/reproducible-builds.json`,
`final/packaged-wheel-check.json`.

새 Helper 코드와 고정 total/calibrated/direction Manifest가 달라 첫 확장 회귀는 양쪽
929건 PASS 뒤 TOTAL_HELPER_BUNDLE_MISMATCH로 차단됐다. 이 보호를 제거하지 않고
새 소스 후보 Manifest3개를 정확한 code_hashes로 동기화했다. 설치본·기존 승인에는 적용하지 않았다.

추가 회귀에서 역사적 보고서가 현재 Investigation 서비스 코드에 SHA를 대조하는 문제와
새 Helper bundle을 과거 결과의 bundle과 동일시하는 문제도 발견했다. 해당 시점의 정확한
Git/기존 archive 소스를 비실행 .txt7종으로 보존하고 기존 SHA/digest Assertion은 그대로
확인한다. 원본 보고서·과거 증거는 변경하지 않는다. 현재 bundle은 별도로 verify_bundle과
code_hashes의 일치를 확인하고 과거 승인과 구분한다. 또한 인증 대기 clock-jump 테스트의
불완전한 fake time 객체에 기존 wall-clock 관측 메서드를 제공했다. 기존 Assertion 삭제·완화 없음.


## 보존과 다음 실환경 조건

실제 설치·Rollback·Root service 설정·Ledger는 변경하지 않았다. 기존81행 Ledger,
Native 실패 증거와 Replay20분 성공 증거의 SHA를 전후 대조한다. 이번 작업에서
Source만 바뀌며, 이전에 승인된 실행 Artifact를 덮어쓰거나 영수증을 소비하지 않는다.

다음 실환경 시험은 새 Source·Wheel·DNS Helper Session·Root Manifest의 정확한 Binding,
새 인간 승인/R1, 동일 Namespace·Interface·자원·트래픽 상한, 직접 Scope yes·sudo 인증이
필요하다. Helper generate/send/receive trace와 CPUstat delta를 관측해야 원인을 더 좁힐 수 있다.
Runtime Cleanup 미검증을 해소하지 않고 추가 권한 실행을 이어가지 않는다.
모델 Action·외부 API는 계속 별도 승인이다. 이번 작업에서는 실제 재시험하지 않았다.

## Git

운영 코드·테스트·새 소스 후보 Manifest Commit: `5e70da8`.
검증된 이번 변경만 선별 Commit한다. 기존 설치·Rollback·Ledger·Native 증거는 Stage하지 않는다.
보고서 Commit과 함께 `feat/one-command-runtime`에 Push한다.
