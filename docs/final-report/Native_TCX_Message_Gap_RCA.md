# Native TCX 5초 메시지 공백 RCA — 2026-11-03

## 결론

실제 46.873초 시험의 최초 오류는 **Runtime의 TCX 수신 Timeout**이다. DNS Helper의
2초 Heartbeat 장애가 아니다. 5.001초 동안 TCX 수신 코루틴이 메시지를 완료하지 못했다는
증거는 있으나, 그 동안 커널 소켓이 실제로 비어 있었는지, Root가 송신을 시도했는지에
대한 증거는 없다. **송신·IPC·수신 중 근본 원인은 UNKNOWN**이다. 추측에 근거한 경로 변경,
Timeout 확대, Native 재실행은 하지 않았다.

확인 범위를 줄일 수 있는 사실은 다음과 같다.

- TCX 마지막 Control Sequence24의 생성→검증은33.413ms였다. 이후5.001초 수신 공백이 있다.
- 그 공백 안에서 DNS Metadata Sequence96은 생성→Runtime Reader 수신1.194ms로 도착했다.
- Runtime 독립 Control Sequence31도 공백 안에서 갱신됐다. 프로세스 전체가5초 내내
  정지했다는 설명은 이 관측과 맞지 않는다. 특정 스레드·Task 지연은 배제하지 못한다.
- `ipc_connected=true`는 유효한 로컬 FD라는 뜻이며 정상 전달을 증명하지 않는다.
  애플리케이션 Queue0도 커널 소켓 버퍼가 비어 있었다는 뜻이 아니다.
- DNS Helper CPU Throttling은 관측됐지만, 이를 다른 cgroup의 Root Collector 원인으로
  옮겨 해석할 수 없다.

## 조사 기준·보존

분석 실행의 고정 Source는 `183070f`이며, 당시 실제 Source는 공통 Git 디렉터리의
`native-receive-startup-recovery-20261103/retest-after-interrupted-confirmation/native/export/`다.
새 코드의 행 번호와 실제 실패 당시 행 번호를 섞지 않는다. 원본 파일·SQLite는 읽기 전용으로
조회했으며 SQLite는 `mode=ro&immutable=1`로 열었다. 기존 Ledger81행, Root 설치8개,
이전 성공·실패 증거와 Rollback을 변경하지 않는다. 권한 검사·서비스 제어·Capture·DNS 송수신·
모델 추론·외부 API 실행·승인 영수증 발급은 하지 않았다.

재구성 결과: `.git/native-tcx-gap-rca-20261103/`의 `rca-summary.json`,
`event-timeline.json`, `sequence-evidence.json/.csv`, `preservation-before.json`.
분석 스크립트는 같은 디렉터리의 `analyze.py`이며 새로운 실행 증거나 승인 기록을 만들지 않는다.

## 최초 오류와 후속 표시 오류

| 구분 | 실제 함수·행·프로세스 |
|---|---|
| 실패한 대기 | 실제 고정 Source `continuous/tcx_producer.py:331`, `TCXProducer.receive_message()`, `asyncio.wait_for(loop.sock_recv(...), 5)` |
| 최초 오류 변환 | 같은 파일363행, TimeoutError를 `CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT`으로 변환 |
| 호출 경로 | `events:401 → messages:268 → receive:214 → receive_message:363` |
| 프로세스 | Runtime PID1880324, StartTicks101117933, UID1000, `soc-operations-runtime.service` |
| 판정 시각 | monotonic1011216.938786786초, KST10:34:01.020254 |
| 실제 대기 | 5.001229196초, 마지막 메시지 이후5.001262828초 |
| 후속 Root 표시 | Coordinator의 `observe_service_health:371`, KST10:34:02.218388에 COLLECTOR_EARLY_EXIT |

Root Collector는 Runtime의 실패 STOP을 받은 뒤 종료됐다. 따라서 마지막 Coordinator
표시는 최초 원인과 다르다. 이전 수정 `e2876d9`가 Snapshot의 Runtime 오류를 먼저 확인하도록
변경했으며, 이 조사에서는 그 수정을 다시 발명하지 않았다. 과거 실행 파일과 first-error.json은
그대로 보존한다. 수신 Timeout의 발생 이유와 오류 표시 순서 결함은 독립적인 문제다.

## Clock 비교

DNS/Runtime의 Boot ID는67d54395-bd0f-4e00-867b-58b7f20342fb이고, DNS Trace는
`time:[4026531834]`를 기록한다. Root TCX의 당시 Boot/Time Namespace는 기록되지 않았다.
Root Control24의 bracketed wall−monotonic offset과 Runtime 실패 시 offset은 약7.683µs
차이로 일치한다. 큰 Clock offset이나5초 Wall Clock 이동 증거는 없지만 Root의 정확한
Boot/Time Namespace까지 완전히 검증했다고 표현하지 않는다. 새 계측에는 이 식별을 추가했다.

아래 monotonic은 원본 ns를 초로 표시했다. TCX 생성 측 시각은 메시지 구성 직전의 Clock bracket이다. 지연 필드는 소켓 수신
직후가 아니라 Clock/Sequence 검증 시각에 계산된 값이므로 **생성 측 Clock→검증**으로 쓴다. DNS의 send 완료는
각 Trace가 가리키는 **이전 Record**에 대한 값이다. 현재 Record 송신 완료로 바꾸지 않는다.

## 보존된 Sequence별 기록

| 채널 | Seq | 생성 mono(s) | 수신 mono(s) | 생성→수신/검증(ms) | 송신 증거 |
|---|---:|---:|---:|---:|---|
| TCX_CONTROL | 1 | 1011184.475150317 | UNKNOWN | 0.24797799999999998 | UNKNOWN |
| TCX_CONTROL | 9 | 1011194.875325372 | UNKNOWN | 0.7877179999999999 | UNKNOWN |
| DNS_HELPER | 1 | 1011200.422696202 | UNKNOWN | UNKNOWN | UNKNOWN |
| TCX_CONTROL | 14 | 1011200.527351108 | UNKNOWN | 0.30636800000000003 | UNKNOWN |
| DNS_HELPER | 5 | 1011201.230246224 | 1011201.230728911 | 0.482687 | 이전 Record만 0.027577ms |
| DNS_HELPER | 74 | 1011207.961954171 | 1011207.962230393 | 0.276222 | 이전 Record만 0.031126ms |
| TCX_CONTROL | 21 | 1011208.123541292 | UNKNOWN | 0.334183 | UNKNOWN |
| TCX_CONTROL | 24 | 1011211.904138053 | UNKNOWN | 33.412682 | UNKNOWN |
| DNS_HELPER | 96 | 1011215.782149313 | 1011215.783343305 | 1.193992 | 이전 Record만 0.027381ms |
| DNS_HELPER | 105 | 1011217.656452506 | 1011217.656916715 | 0.464209 | 이전 Record만 0.028497ms |

이 표는10개 **서로 다른 보존 Snapshot**이다. 전체 Sequence1..105를 매 Record 기록한
파일은 존재하지 않는다. 빠진 번호의 생성·송신·수신 시각을 보간하지 않았다. DNS1은 READY,
DNS105는 CLOSED에 연결된다. 중간 Metadata Trace의 원래 Message type은 모두 저장되지
않았으므로 중간 Record 전체를 Heartbeat라고 단정하지 않는다.

## 프로세스별 타임라인

| 시각·mono | TCX Collector | DNS Helper | Runtime/Observer |
|---|---|---|---|
| KST10:33:23.395 | Kernel 부착 소유 ATTACH_OWNED | 아직 미시작 | 서비스 시작 |
| 1011184.475s | Control1 | 미시작 | 인증된 Producer READY 통과 |
| 1011200.423s | Control 진행 | Metadata READY1 | Helper 연결 |
| KST10:33:45.932 | 수집 중 | 승인된 로컬 DNS 공급 시작 | Packet/Transaction 처리 |
| 1011202.792s 부근 | Packet12 수신 완료 구간 | UDP1·TCP1 처리 | 마지막 Data Progress 완료 |
| 1011211.125s | 마지막 Data Record20 검증 | 계속 실행 | SQLite update는1011211.218부터 pending |
| 1011211.904s | Control24 생성, Worker Stage INSTALLED_INTEGRITY | 계속 실행 | 마지막 TCX 수신1011211.938s |
| 1011215.782s | 새 송신 여부 UNKNOWN | Metadata96 생성·수신 | DNS Reader는1.194ms에 수신 |
| 1011216.048s | 새 송신 여부 UNKNOWN | 계속 실행 | 독립 Runtime Control31 갱신 |
| 1011216.939s | PID/Start Identity SAME_PROCESS | 계속 실행 | TCX 5초 Timeout, 실패 STOP 요청 |
| 1011217.240s | STOP ACK·진단 Seal | 종료 중 | 동일 채널 ACK 검증, 약0.300초 |
| 1011217.656s | 정리 완료 | CLOSED105 수신·최종 Counter | DNS Cleanup 검증 |
| KST10:34:02.218 | 서비스 종료 뒤 | CLOSED | Coordinator가 후속 종료를 먼저 표시 |

두 번째 UDP는 TCP 종료 후35초 대기 계약상 아직 공급 전이었다. DNS Transaction2를
3으로 올리거나 Loss라고 단정하지 않는다. Runtime Window0, RF/LR0, API0인 실패 시험이다.

```mermaid
sequenceDiagram
    participant C as TCX Collector PID1880296
    participant R as Runtime PID1880324
    participant D as DNS Helper PID1880520
    C->>R: Control24 (mono 1011211.904s)
    Note over C,R: TCX 수신 완료 5.001초 공백; 송신/IPC 상태 UNKNOWN
    D->>R: Metadata96 (수신 지연 1.194ms)
    R->>R: 독립 Control31 갱신
    R->>R: TCX receive Timeout (1011216.939s)
    R->>C: 동일 소켓 STOP
    C-->>R: 진단 Seal / 검증된 ACK (약0.300초)
    D-->>R: CLOSED105 / 최종 Counter
```

## CPU·Scheduling·저장 상태

| 대상 | 증거 | 판정 |
|---|---|---|
| Root Collector PID1880296 / Start101117866 | 실패 시 SAME_PROCESS, 서비스 종료0, 초기 CPU25% 설정, 총 CPU6.815s | 해당5초의 cpu.stat/schedstat 없음. Throttling·GIL·스케줄링 원인 UNKNOWN |
| DNS Helper PID1880520 / Start101118654 | 상태S·nice0, cpu.max `10000 100000`, 총191 periods/147 throttled, throttled_usec12145908 | 누적12.145908초 Throttling 관측. 단일 시점 누적값이며 TCX 공백의 구간 delta가 아님 |
| DNS Helper schedstat | CPU1.407840053s, runqueue wait12.405982831s, timeslices422 | 해당 Helper의 누적 대기. Root Collector 카운터 아님 |
| DNS Helper 종료 | 서비스 inactive/ExecMainStatus0, CLOSED105·최종 Counter 검증 | Runtime 자신의 waitpid exit_code는None. 서비스 증거와 Runtime 관측을 구분 |
| Runtime PID1880324 | Control31, DNS Reader 수신, 초기 CPU50% 설정 | 전역 프로세스 정지는 관측과 불일치. TCX Task의 scheduling 지연은 배제 못함 |
| Runtime 저장 | Snapshot0038에서 update pending, 시작mono1011211.218; 최종 max update5.416646초 | 저장 지연은 확인. TCX 공백과 겹치지만 독립 Root 송신을 막았다는 직접 증거 없음 |
| Runtime 상태 조회 |0038 acquisition query13.076ms/read0.597ms, Runtime age1.020s/source age5.131s | 오래된 조회 결과를5초 수신 Timeout의 원인으로 확정할 근거 없음 |
| GUI | 같은 Runtime Snapshot을 조회; 실패 종료2에서 CLI가 GUI를 종료, 이후 읽기 전용 재연결 | GUI callback·최종 repaint 시각은 보존되지 않음. GUI가 원인이라는 증거 없음 |

저장 max duration에는 최대 작업의 정확한 시작/끝 쌍이 따로 저장되지 않았다. 다른
Snapshot의 pending 시작을 그 최대 duration에 무조건 연결하지 않는다. 현재 Host PSI나
현재 cgroup 상태를 과거 시험의 CPU/I/O 증거로 대신 사용하지 않는다.

## IPC·Lock 판정

- TCX는 AF_UNIX SOCK_SEQPACKET이고 코드상 양 끝이 nonblocking이다. 당시 FD의 실제
  `O_NONBLOCK`, `SO_SNDBUF/RCVBUF`, `FIONREAD/TIOCOUTQ` 값은 없다.
- Runtime의 앱 Receiver Queue Depth0, dropped batches0, Runtime Drop/SourceGap0이 보존됐다.
  커널 Receive Queue/Sender Queue나 잠금 대기를 측정한 값은 아니다.
- Control과 Data 송신은 기존 ControlTransport.lock을 공유한다. 정책/파일 무결성 작업은
  이 lock 밖에 있고, lock 안의 recv/send는 nonblocking으로 설정된다. 코드에 공유 lock이
  있다는 사실만으로5초 lock 경합이 실제 발생했다고 판정할 수 없다.
- EAGAIN은 기존 Control 코드에서 계속 처리되지만 과거 성공/실패 송신 카운터는 없다.
  마지막 Sequence24 이후 미생성·send 실패·buffer 적체·수신 Task 지연을 구분할 수 없다.
- EOF·BrokenPipe·ECONNRESET이 최초 오류라는 증거는 없다. 실패 뒤 같은 채널의 STOP ACK를
  검증했다는 사실은5초 동안 데이터가 정상 전달됐다는 증명이 아니다.

## 변경: 복구 추측 대신 최소 진단

실제 장애 원인을 확정하지 못했으므로 송신 구조·Lock 정책·Worker 전략·Timeout을 바꾸지 않았다.

1. 기존 Root ControlTransport에 최대64개 송신 시도 Ring을 추가했다. 채널/Sequence,
   Lock 요청·획득, send 시작·완료, 반환 길이, EAGAIN/오류, process/thread CPU Clock,
   비소모성 소켓 버퍼 조회를 기록한다. 누락 Ring 개수와 누적 Outcome을 별도로 센다.
2. Control Record에는 이전 Control 송신 시도 결과와 Root Boot/Time/PID/Start Identity를
   포함한다. 현재 send 완료는 다음 Record 또는 종료 시 Ring에서만 확인한다.
3. 기존 Data Worker가 cpu.stat을1초 주기와 시작/종료 시점에 읽어 bracketed 시각과 함께
   보관한다. 검증된 자기 cgroup 경로만 사용한다. Control 스레드는 파일 I/O·fsync를 하지
   않고, 추가 Root 스레드·서비스·권한은 없다. 실패·권한 부족은 UNKNOWN으로 기록한다.
4. Control 스레드가 종료된 이유, 마지막 Lock 대기/CPU 시각을 기록한다. 종료 시 Ring과
   CPU 표본을 기존 hash-chain Audit의 CONTROL_TRANSPORT_DIAGNOSTICS에 순서대로 추가한다.
   감사 장벽이 내구성을 보장하며 이 진단 Record 자체는 Capture/정리 권한이 아니다.
5. Runtime은 최대64개 수신 대기의 시작/완료·길이·Envelope Sequence/Clock을 보관한다.
   잘못된 타입은 None으로 남겨 원본 Payload가 진단 필드에 섞이지 않도록 했다. Envelope
   수신은 Attestation/Feature 승인이 아니다. Timeout 뒤에는 비소모성 소켓 버퍼·실제
   nonblocking만 조회한다. Observer Boot/Time Identity는 시작 시 고정하며 수신·STOP에
   파일 I/O를 추가하지 않는다. Root CPU 표본은 앞의 Root Data Worker에서 얻는다.
   데이터 재수신·재접속·타이머 재설정은 하지 않는다. Raw Payload는 기록하지 않는다.
6. TCX5초, Worker5초, DNS2초·Runtime5초 계약 및 Queue/CPU/메모리·Admission은 그대로다.
   STOP ACK·Seal·최초 오류·소유 범위 Cleanup을 대체하거나 승격하지 않는다.

FIONREAD는 커널이 반환한 byte 값 그대로 저장한다. 이번 Kernel의 일반 사용자
SOCK_SEQPACKET 검증에서는4B·8B를 순서대로 넣었을 때12B, 첫 Record를 읽은 뒤8B를
반환했다. 이를 Record 수로 바꾸거나 다른 Socket 종류/플랫폼에 그대로 외삽하지 않는다.
TIOCOUTQ도 커널 byte 값으로 보존하고 Packet 수로 환산하지 않는다. Root 계측이 바뀌었으므로
향후 시험은 새 SHA/Artifact/Launcher 검토가 필요하다. 설치본과 과거 실행 파일은 바꾸지 않았다.

## 다음 시험의 판별 기준 — 실행 지시가 아님

| 관측 조합 | 좁힐 수 있는 단계 | 여전히 단정할 수 없는 것 |
|---|---|---|
| Control 생성/Lock 획득 자체가5초 이상 비고 Lock wait가 큼 | 공유 Lock 대기 | 누가 왜 오래 보유했는지는 추가 Stage/CPU와 대조 |
| 생성은 계속되나 send=EAGAIN·send queue가 쌓임 | 송신 Backpressure | 수신 Task 지연과 Kernel 처리 지연의 추가 구분 |
| Kernel send 성공은 계속되나 Timeout 시 FIONREAD>0 | 수신/이벤트루프 경로에 미소비 Record 존재 | Kernel send 성공이 사용자 검증 성공은 아님 |
| wire 수신 완료 뒤 검증이 늦음 | 파싱/검증/Task Scheduling | 단순히 Deadline을 연장해서 해결하지 않음 |
| Root CPU throttled delta·wall gap·thread CPU gap이 함께 확인 | 해당 Root cgroup의 CPU 압박과 상관 | GIL/다른 I/O가 동시에 개입했는지 별도 확인 |
| 모든 Record 생성/송신이 정상이나 Observer만 오래된 Snapshot 사용 | 상태 게시/조회 | 실제 Packet 처리 정상 여부는 별도 |

이 표는 미래 진단 기준이다. 위 시나리오가 과거 실제로 발생했다고 주장하지 않는다.

## 검증·Git 진행 상태

운영 계측 Commit: `62567c1905650492f230be47960d2992c37d3158`.
최종 결과는 [validation-final.json](evidence/native-tcx-gap-20261103/validation-final.json)에 있다.

| 검증 | 결과 |
|---|---|
| Workspace 관련 비권한 회귀 |838 PASS,194.70초; 실행 전후 Source 동일 |
| 독립 Export 동일 회귀 |838 PASS,188.42초; Workspace와 동일 Source SHA |
| 새 장애 주입 |9개: 송신/이전 send 시각·실제 UNIX Backpressure·Lock 지연·CPU Counter Fixture·Unread Socket Timeout·Ring 상한·잘못된 타입 비노출·Kernel FIONREAD·최초 오류 보존 |
| 기존 회귀 |Heartbeat 지연/5초 Timeout/2초 DNS/Slow Storage/Crash/STOP ACK/누락/실패 Cleanup/CLI/Policy Gate/LLM Mock 포함 |
| GUI |실제 Tk 창의 Fixture·JSONL/FAKE_HTTP 오류·UNKNOWN 비용·Cleanup·승인 버튼·종료/재연결; Screenshot4개, Native/API 검증으로 계산하지 않음 |
| Native 빌드6개·기존 Native 컴파일·Supervisor·Wheel |Workspace2회/Export1회 각 SHA 일치; Kernel 활성화 없음 |
| Ruff/Format/Diff |PASS,1588파일 Format 확인 |
| 금지 실행 Guard |두 최종 회귀에서 금지 시도0; 실제 서비스 제어/권한 상승/모델 Worker/외부 연결 금지. Doctor의 고정 비권한 systemctl show만 허용 |
| 보존 |실행 원본796개·이전 Artifact2554개·사용자 파일164개 SHA 일치; 설치8개 SHA/inode/mtime 동일; Ledger81행/체인 동일 |

실제 모델 추론이 들어 있는 test_runtime.py/test_capture_admission.py/
test_stream_integration.py 전체 실행은 이번 제한에 따라 분리했다. resource_scope의 순수
검증은 별도 node로 포함했다. 이 파일들을 삭제하거나 Assertion을 바꾸지 않았다.

첫 Export 회귀는 기존1.3초 게시 시험에서 Sequence1을 관측해1 FAIL/837 PASS였다.
같은 시험을 변경 없이 단독 재검증한 뒤 전체를 재실행해 최종838 PASS를 얻었다.
원본 실패 로그와 재검증 로그를 보존했다. 이를 과거 Native5초 공백의 원인으로 해석하거나
반복 가능한 원인이 해결됐다고 주장하지 않는다. 초기 Guard가 고정 read-only query를
서비스 변경과 함께 차단한 문제도 분리해 수정했으며 제품 정책은 바꾸지 않았다.

최종 Wheel SHA: `ddcf130ac403bb501a265f28c9c5233cb91c27ac8234eafc3ba48c5bd29f1548`.
Source SHA: `9f68b8242c4aa47f5ad2fdef550e32227bea003ee8a989d9760ed873cb4adeea`.
원본 Root Audit8012행의 해시 체인을 검증했고, Root 전용 Rollback 백업은 새 권한 조회 없이
기존 증거를 유지했다. 해당 백업의 현재 bytes를 재검증했다고 주장하지 않는다.

## 산출물·최종 판정

- [Sequence CSV](evidence/native-tcx-gap-20261103/sequence-evidence.csv),
  [Sequence 출처](evidence/native-tcx-gap-20261103/sequence-evidence.json)
- [프로세스별 타임라인](evidence/native-tcx-gap-20261103/event-timeline.json),
  [RCA 요약](evidence/native-tcx-gap-20261103/rca-summary.json)
- [기존 Audit 체인 확인](evidence/native-tcx-gap-20261103/original-audit-chain-check.json)

**기존 증거 기반 원인 분류 완료·최소 계측 비권한 검증 완료. 근본 원인 UNKNOWN 유지.**
실제 Native 재시험·모델·API는 실행하지 않았다. 새 코드·Root Artifact는 설치하지 않았고,
새 승인·예약도 만들지 않았다. 변경한 계측의 Native 동작은 아직 UNVERIFIED이며, 이후
필요한 경우 별도의 새 Binding 검토를 거쳐야 한다. 이번 결과는 운영 안정성 성공 판정이 아니다.
