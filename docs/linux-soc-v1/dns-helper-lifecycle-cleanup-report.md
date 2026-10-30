# DNS Helper Lifecycle·Cleanup 최종 안정화

기준: `feat/one-command-runtime`, `6026fa7`. 구현: `5b14a67fd3927e6105d8d2e57b525725428703ec`.
판정: **비권한 생명주기·Cleanup 회귀 VERIFIED / 후속 Live BLOCKED**.
기존 실제 Native·DNS 결과는 PARTIALLY_VERIFIED이며 1시간 운영 통과가 아니다.
이번 작업은 Root·sudo·Namespace 진입·TCX Capture·DNS 트래픽·모델 Action·외부 API·예약·정책 발급을 수행하지 않았다.

## 1. 조사 대상과 시점 구분

실제 실패 실행은 `cd78b59`의 동결 Artifact였다. `6026fa7`에는 이미 socket readiness를
먼저 읽고 heartbeat 침묵을 판정하는 비권한 수정이 포함돼 있었다. 이를 재구현하지 않고 보존했다.
이번 추가 수정은 실패 후 STOP/CLOSED 증거 보존, Helper 프로세스 상태, Cleanup 판정에 한정했다.

원본 실행:
`.git/packet-dns-heartbeat-recovery-20261030T010933Z/final/review/execution/`.
원본 Helper 증거는 같은 review의 `dns-session/`에 있다.
새 비권한 증거·빌드는 `.git/dns-helper-lifecycle-recovery-20261030T014733Z/`에 보관했다.

| 항목 | 확인된 실제 증거 |
|---|---|
| 실행 Session | 49525e9b-74fa-4983-9254-8ca1b7d249c4 |
| DNS Session | 58d76ffc-7d19-426b-b452-4a7fb4e1accb |
| Namespace / Scope | net:[4026532232] / lo / Ingress |
| Helper PID / Start Time | 2703050 / `/proc/stat` start ticks `66480133` |
| Helper UID/GID / Capability | 1000/1000, Eff/Prm/Inh/Amb0, Bounding NET_RAW, NoNewPrivs1 |
| Native / DNS / ELIGIBLE | 34 / UDP2·TCP1 거래3 / 4; INCOMPLETE1 유지 |
| 모델 / API | 0 / 0, 신규 Action 없음 |
| 실행 시간 | Root 전체200.629109373초, Collector 시작 이후199.709640756초 |

## 2. HELPER_HEARTBEAT_OR_PROCESS_STALE RCA

| 시각(UTC) | 증거와 한계 |
|---|---|
| 01:20:18.289675 | Root 시험 시작 기록 |
| 01:20:34.572129 | verified-ready.json mtime; payload에 PID·Start Time·Socket FD5/inode116328856이 결합됨 |
| 01:20:34.640529 | Supervisor가 Helper READY를 관측 |
| 01:21:20.582277 | 로컬 DNS UDP2/TCP1·45초 관측 완료; dnsmasq 정상 정리 |
| 01:23:22.993988 | 마지막 주기적 Supervisor 관측: Helper RUNNING, Counter895, snapshot의 heartbeat age0.149672689초 |
| 01:23:32.530235 | transport-failure.json mtime: STALE, Counter933, metadata14 전달, Queue0, counter_issue 없음 |
| 01:23:32.846617621 | Root Audit SERVICE_STOPPED·owned Cleanup VERIFIED, 원격 TCX STOP ACK 확인 |
| 01:23:33.402385 | 외부 Root 관측 오류 COLLECTOR_EARLY_EXIT |
| 01:23:33(초 단위 journal) | DNS Helper 서비스 Deactivated successfully |
| 01:23:38.640947 | Root 정산 완료, 5개 서비스 MainPID0, Runtime Exit2 |

**실제 Helper 종료는 확인됐다.** 저장된 서비스 정산은 Result=success/ExecMainStatus0이며,
현재 동일 PID가 `/proc`에 없다. 그러나 heartbeat 오류가 난 바로 그 시점의 Helper 생존 상태와
그 순간의 소켓 대기 메시지·reader scheduling gap은 기록되지 않아 UNKNOWN이다.
프로세스가 먼저 crash했다고 단정하지 않는다. 서비스 정상 종료를 전체 실행 성공으로 해석하지 않는다.

원본에는 Helper의 개별 heartbeat 송신 timestamp가 없었다. Supervisor 시각·receiver의 age·
파일 mtime은 서로 다른 관측이다. 이들을 Helper 송신 시각으로 환산하지 않았다.
당시 GUI 개별 frame 갱신 시각도 저장되지 않았다. GUI는 Runtime heartbeat mirror를 읽었으며,
그 뒤의 실제 Tk 검증 로그는 재연결 검증 시각이지 사고 시각이 아니다.

확인된 실패 경로:

```text
HelperCapture._read_loop: 2초 heartbeat 침묵 판정
→ reader_error 기록, 기존 코드는 channel.shutdown(SHUT_RDWR)
→ DNSProducer.events / close: 동일 채널 종료
→ Helper는 EOF/STOP 조건으로 capture.close 후 CLOSED 송신 시도
→ 수신 채널은 이미 닫혀 최종 CLOSED·Counter 영수증을 남길 수 없음
→ Runtime의 DNS 실패·Cleanup UNVERIFIED, Native 종료 절차
→ 외부 Controller는 Collector 종료를 먼저 보고 COLLECTOR_EARLY_EXIT 기록
```

`stream_helper.run()`은 트래픽이 없어도 주기적으로 heartbeat를 보낸다. dnsmasq 정상 종료와
DNS 질의가 더 없다는 사실만으로 Helper STALE를 정당화하지 않는다. 이전 2초 지연의
구체적 원인(스케줄링·I/O 등)은 여전히 UNKNOWN이다.

## 3. 기존 Cleanup 자원별 판정

| 자원 | 증거 | 판정 범위 |
|---|---|---|
| DNS Helper 프로세스 | 저장된 서비스 종료·MainPID0·현재 원 PID 부재 | 종료 확인, 오류 시점의 생존 여부는 UNKNOWN |
| Helper AF_PACKET FD5 | READY에서 소유권 확인, 종료 후 원 프로세스 부재 | 프로세스 종료는 확인; CLOSED·최종 Counter는 누락 |
| dnsmasq Listener / DNS Client | 고정 거래 완료·client_fds_closed·서비스 정상 종료, 저장된 Namespace socket 검사 | 당시 로컬 공급원·client 정리 확인 |
| TCP Listener/Client | 2연결·요청2·응답2·35초 간격·socket_cleanup VERIFIED, 종료 검사 | 해당 고정 공급원 소유 자원 정리 확인 |
| TCX Collector / BPF Link·Map | 원격 STOP ACK, Root Audit Stop, 저장된 net/map/link 검사·owned socket 부재 | 소유 TCX 정리 VERIFIED |
| Worker / Controller | Runtime Exit2·서비스 cgroup/PID0, Root 종료 정산 | 종료 확인, 성공 실행으로 승격하지 않음 |
| Queue | 읽기 전용 SQLite 검사: PENDING1 / POISON1 | 원본 유지; 전부 처리됐다고 판정하지 않음 |
| Audit / Flush | Audit22행 hash chain·detail digest·state digest 재검증, final_flush VERIFIED | 저장된 Audit 정합성 확인 |
| 전체 Runtime Cleanup | 원본 UNVERIFIED, DNS verified-closed.json 없음 | **UNVERIFIED 유지** |
| 전역 Kernel / Program1145 | 이번 작업에서 새 권한 검사 없음, 과거 UNKNOWN·UNVERIFIED 보존 | **UNKNOWN / UNVERIFIED 유지** |

정상 서비스 Exit0은 프로토콜 ACK·최종 Counter 검증을 대체하지 않는다.
누락된 CLOSED를 재발급하거나 원본 Cleanup·FAILED·false·UNKNOWN을 수정하지 않았다.

## 4. 최소 운영 코드 수정

- `continuous/dns_source.py`:
  - 정상 CLOSED, heartbeat 지연, 실제 PID·Start Time·프로세스 종료 관측을 분리한다.
    receiver의 heartbeat 관측 UTC와 CLOSED 관측 UTC·STOP 송신 시각을 기록한다.
    외부 서비스의 exit code는 관측자가 알 수 없으므로 None으로 남긴다.
  - heartbeat 실패 시 입력 Admission은 즉시 실패 상태를 유지한다. 같은 연결에서 STOP을
    한 번 보내고 최대5초·64개 메시지 안에서 종료 증거만 수집한다. 새 Collector·Helper를 시작하지 않는다.
    뒤늦은 Packet은 검증·계수 후 격리하며 애플리케이션·AI에 전달하지 않는다.
  - Session·Identity·Counter·Replay·Schema 위반은 기존대로 즉시 disconnect한다.
    지연 후 ACK가 와도 `completion_verified()`는 False다. 소유 자원 Cleanup과 데이터 처리 성공을 혼동하지 않는다.
  - 동시에 Owner STOP이 오면 이미 진행 중인 bounded ACK 수집을 회수한다. 즉시 ACK 누락으로
    오판해 Cleanup 실패를 추가하지 않는다.
  - Cleanup VERIFIED는 정상 CLOSED/Counter, 원 Helper identity 종료, Listener/Channel FD 종료,
    reader join, 파일·디렉터리 fsync가 모두 확인된 뒤에만 게시한다.
    ACK 누락·잘못된 Counter·진단/Audit 기록 실패는 UNVERIFIED로 남긴다.
  - Cleanup 기록 중 취소도 소유 writer를 join한다. 취소 후 뒤늦게 성공 영수증을 게시하지 않으며,
    상태는 FAILED/UNVERIFIED다. 기록 SHA는 durable commit 반환 뒤에만 공개한다.
  - 기존 admitted Session의 재사용을 listener 생성 전에 차단한다. 실행 중/종료 후 replay로
    이전 READY·CLOSED·Cleanup 증거를 덮어쓰지 않는다.
- `network_capture/helper_transport.py`: 기존 fail-closed 기본 동작을 유지하면서 DNS 전용
  bounded 종료 hook을 분리했다. 진단 쓰기 실패가 최초 오류 코드를 덮어쓰지 않게 했다.
  heartbeat와 CLOSED의 관측 timestamp도 별도로 표시한다.
- `continuous/service.py`: DNS 종료 증거 수집이 진행 중이어도 최초 DNS 오류를 Supervisor
  snapshot에 표시한다. 기존 더 이른 오류가 있으면 보존한다.
- `gui/continuous_view.py`: Helper 프로세스·heartbeat lifecycle·Cleanup을 분리해 표시한다.
  정상 CLOSED 후는 ENDED_AUTHENTICATED_CLOSED, 실패 후 종료는 ENDED_AFTER_STREAM_FAILURE다.
  과거 기록에 없는 값은 NOT_RECORDED이며 현재 상태를 소급 삽입하지 않는다.
- 현재 calibrated helper Source manifest만 새 transport SHA에 맞췄다. 기존 영수증·historical fixture·
  모델 fingerprint·Namespace·Root 권한·2초 heartbeat 상한·5초 ACK 상한·실행 자원 제한은 유지한다.

## 5. 비권한 검증

**Workspace 537 PASS / 독립 Export 537 PASS**, 각각 기존 stress1건 deselected.
이미 통과한 5,000-event stress는 반복하지 않았다. Ruff·Format·Diff PASS.

실제 일반 사용자 자식 프로세스와 AF_UNIX 통신으로 다음을 검증했다. Kernel·AF_PACKET·Target
권한 경계만 테스트에서 모의하며, 이 결과를 Native 검증으로 보고하지 않는다.

- 정상 STOP→CLOSED→실제 자식 Exit0→FD·reader 정리, 종료 후 heartbeat age 증가에도 STALE로 표시하지 않음.
- 실제 자식 Exit7→DISCONNECTED 오류·Cleanup UNVERIFIED. Exit Code는 테스트 소유 부모가 별도 확인.
- 실제2초 침묵→입력 차단→STOP→정상 CLOSED/Exit0. 소유 Cleanup은 확인돼도 stream completion은 실패 유지.
- ACK 뒤 늦은 Packet 격리, Replay/Counter가 잘못된 ACK 차단, ACK 없는 5초 대기 종료.
- Owner STOP·실패 ACK 경합, Helper PID에 신호를 보내지 않는 수신기, 살아 있는/종료된 Session 재접속 차단.
- 디스크 부족·최초 진단 기록 실패·Cleanup commit 취소·Audit drain. 최초 오류 보존, 성공 허위 게시·orphan writer 없음.
- 기존 실제 Native34·DNS3·모델0·오류·Cleanup UNVERIFIED를 실제 Tk 5개 페이지와 2회 종료/재연결에서 확인했다.
  원본에 없는 Helper lifecycle 필드는 NOT_RECORDED다. GUI 종료는 Backend Stop을 실행하지 않았다.

초기 Export에서 ACK와 후속 Audit fsync를 합친 wall time을 7초로 검사한 테스트가 실패했다.
원본 실패 로그를 보존했다. 최종 테스트는 **ACK 단계의 기존5초 제한을 직접 측정**하며,
전체 종료/Audit는 기존 Owner shutdown 범위에서 검증한다. 코드의 ACK 상한을 늘리지 않았다.

## 6. 재현 빌드·Identity

- 구현 Git `5b14a67fd3927e6105d8d2e57b525725428703ec` / Tree `0625f5a9e3648a2c0adcdc6f51cab4000a3fec0b`.
- Source archive `8f1a303aa44e3d151a920216c69fa520009b00ca6123f8e0dcba514ed247fd5f`.
- Source file map `de8c39907cfaa86f52e503915525aeeb2565e8cabbe64017ddae270f6cda3394`.
- Wheel `fbfa6225b541d0711dbef5f6633ceb54ed3ebfb6859fde26d42787c37c78ad56`: 두 번 빌드한 bytes 일치.
- Native6개 두 번 빌드 SHA 일치. BTF libbpf userspace parse 성공, Kernel load 없음.
- 설치된 Root BPF/provider/service/policy/Collector unit의 bytes는 변경하지 않았다.
- 두 격리 Controller/Helper Python의 의존성122개·interpreter/cfg2개, 총124개 파일 고정 SHA 확인.
  Python -I -B, Pydantic2.13.5, 메모리256MiB·CPU20초 import probe PASS. ML 모듈을 로드하지 않았다.
- 최종 Artifact 상태 **GUARDED_NO_LIVE_EXECUTION**. 새 정책·승인·모델 Action·예약 발급 없음.

원본 실행·Namespace Lease·설치 파일·Rollback·Ledger81행 및 Runtime SQLite·Queue·Audit SHA를 보존했다.
각 증거 SHA는 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/dns-helper-lifecycle-recovery-20261030T014733Z/preserved-evidence-sha.json`과
`preserved-runtime-audit-verification.json`에 있다.

## 7. 다음 실환경 시험 최소 조건

1. 기존 미확인 Cleanup의 범위를 독립적으로 검토하고, 필요한 소유 자원 정리 증거를 실제로 확인한다.
   과거 누락된 CLOSED·최종 Counter를 임의 생성하거나 프로그램 전역 Cleanup을 VERIFIED로 승격하지 않는다.
2. 정확한 새 Source·Helper bundle·Runtime·Namespace·Session·Ledger Binding으로 기존 승인 계약을 충족한다.
   필요한 Root 범위·R1 위험 수용·트래픽·시간·자원·STOP Scope를 확인하고 소비된 영수증은 재사용하지 않는다.
3. Scope 직접 확인·sudo 인증 및 Namespace 내부 check PASS 후에만 승인된 1회 시험을 진행한다.
4. 새 시험에서 STOP 송신·정상 CLOSED·원 PID 종료·FD·reader 종료·Audit durable commit을 각각 수집한다.
   정상 종료와 시간 초과/실제 process exit를 구분해 판정한다. 실패하면 최초 오류를 보존한다.
5. RF/LR Action·DNS9·실제 LLM API는 이번 작업에서 허용하거나 실행하지 않았다.

**기존 전체 Cleanup이 실제 증거로 VERIFIED되기 전까지 신규 Root·Native 시험은 BLOCKED다.**
이번 작업의 완료는 운영 코드와 비권한 검증의 안정화이며, Kernel 재시험·1시간 운영 검증 완료가 아니다.

후속 읽기 전용 증거 재검증·새 미시작 Session·Root Manifest·종료 시험 요청서는
[Cleanup 증거 검토 보고서](dns-helper-cleanup-evidence-review.md)에 정리했다.
이 후속 준비도 기존 전체 Cleanup을 VERIFIED로 승격하거나 새 실행 권한을 발급하지 않았다.
