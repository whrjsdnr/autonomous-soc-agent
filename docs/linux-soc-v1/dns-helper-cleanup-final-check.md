# Cleanup 현재 상태 최종 확인 및 권한 검사 준비

2026-10-30. 운영 Source `5b14a67`, 문서 기준 `3589c68`.
**현재 Host에서 관측 가능한 소유 잔류는 발견되지 않았다. 다만 Target·Root 검사가 미완료여서 재시험은 BLOCKED다.**
이번 작업은 Root 검사·설치·Namespace 진입·Native Capture·DNS/TCP 트래픽·모델·API·예약·영수증 발급을 수행하지 않았다.
운영 코드·정책·기존 실행 검토서는 변경하지 않았다.

## 현재 Snapshot과 과거 종료 증거

새 읽기 전용 증거 경로:
`.git/cleanup-final-readonly-review-20261030T030948Z/`.
`current-readonly-snapshot.json`은 이번 관측이고, 과거 실행 자료는
`.git/packet-dns-heartbeat-recovery-20261030T010933Z/final/review/execution/`이다.

| 항목 | 현재 일반 사용자 권한 관측 | 아직 확정할 수 없는 것 |
|---|---|---|
| Namespace | Target mount dev4/inode4026532232, Root 소유, Lease·boot·Scope 일치. 현재 Host는 net:[4026531833] | Target 내부 lo/route/socket/TCX 상태: 진입하지 않았음 |
| Collector·DNS Helper·dnsmasq·TCP 공급원 | 서비스4개 inactive/dead·MainPID0 | 현재 Target의 다른 socket/link 잔류 여부 |
| Runtime·Worker | Runtime failed/Exit2·MainPID0, 해당 서비스 cgroup 없음. 과거 snapshot은 Worker STOPPED | 다른 프로세스를 검색·종료하거나 그 소유권을 추정하지 않음 |
| 원 프로세스 | Collector2702904·Helper2703050·dnsmasq2703292·Runtime2702924 모두 `/proc`에 없음 | 오류 순간 liveness·당시 STOP ACK는 현재 PID 부재로 복원 불가 |
| Controller/Root Launcher | 과거 terminal 종료코드2 기록 보존 | 독립 PID/Start Time 기록이 없어 현재 별도 PID 추적은 불가 |
| 소유 서비스 cgroup | 고정5개 cgroup 경로 모두 없음, systemd ControlGroup도 비어 있음 | 시스템 전체 프로세스 정리를 증명하는 것은 아님 |
| Collector Unix socket | `/run/soc-agent-continuous/1000.sock` 없음 | Target의 Helper AF_PACKET FD/inode116328856, abstract Unix endpoint는 권한 검사 필요 |
| Host Unix 표 | 과거 Helper Session의 abstract endpoint 일치 행 없음 | Host 음성 결과를 Target 부재로 확대하지 않음 |
| 설치본 | 새 Root Manifest의 현재7개 파일 SHA와 일치 | 백업7개 내용은 PermissionError로 UNKNOWN 유지 |
| Audit·Queue | 보존 Runtime Audit22행·detail/state digest 재검증, Queue PENDING1/POISON1 유지 | 보존 대기 작업이 모두 처리됐다고 판정하지 않음 |
| Ledger | 81행·SHA·chain 일치, 기존99개 SHA 보존 | 새 승인·예약·정산을 생성하지 않음 |

과거 DNS Helper 서비스 정상 Exit0은 확인되지만 `verified-closed.json`·`cleanup.json`이 없다.
실제 물리 자원이 남았다는 증거는 아직 없으며, 전체 Cleanup 미완료가 입증된 것도 아니다.
현재 확인된 문제는 **종료 프로토콜 증거 누락과 현재 권한 검사 범위의 부족**이다.
최초 heartbeat 지연 원인은 여전히 UNKNOWN이다.

## 영역별 독립 판정

| 영역 | 과거 실행 Cleanup 판정 | 현재 상태 판정 |
|---|---|---|
| Helper | UNVERIFIED: CLOSED·최종 Counter 누락 | 원 PID 부재. Target 소켓 metadata 확인 대기 |
| Collector | VERIFIED: 해당 소유 TCX STOP ACK·당시 Link/Map/socket 정리 | 원 PID·서비스·소유 socket 없음. 현재 Target TCX 조회 대기 |
| Root 전체 | UNVERIFIED | 관련 서비스/cgroup 잔류 관측 없음. Root·Target 검사 미완료 |
| Runtime 전체 | UNVERIFIED: DNS 종료 증거 미충족 | 원 Runtime PID 없음·Audit 정합성 확인. 실패 기록·보존 Queue 유지 |
| Global Kernel | UNVERIFIED | 현재 BPF metadata 조회와 소유권 확인 미수행. Program1145 UNKNOWN 유지 |

현재 잔류 부재가 확인되더라도 과거 Cleanup 판정을 소급 변경하지 않는다.
Global BPF 프로그램 ID 변화나 타 서비스의 자원을 이 프로젝트 소유로 단정하지 않는다.

## 정확한 권한 검사 계획 — 준비만 완료

명령 전체 argv·고정 Namespace 검사 body·실행 파일 SHA·백업 기대 SHA는
`privileged-readonly-inspection-plan.json`에 고정했다. 사람이 검토할 자료는
`readonly-inspection-review.md`다. 계획 SHA256:
`f14a76ec7387df51ee63527ceecd2c5afb5e80f5e828db3867bbed7781bd35b0`.
사용자 SHA 직접 입력은 필요하지 않다.

기존 Root coordinator의 `namespace()`·`kernel()` 경로를 재사용했다.
Root 실행 coordinator 전체를 import/실행하지 않고, Namespace 검사용 `INTERNAL` literal만
AST로 추출했다. 과거 종료 검사와 동일하게 소유권 없는 TIME_WAIT inode0만 허용하는 후보다.

| 명령 수 | 준비된 검사 | 정확한 권한 범위 |
|---|---|---|
| 1 | `/usr/bin/nsenter --net=/run/netns/soc-native-b3 /usr/bin/python3 -I -B -c <고정 INTERNAL>` | 기존 Target만 단기 진입, inode·lo·route·cookie·TCP/UDP 표. Cookie/flags 조회용 unbound UDP FD1개 생성·종료, bind/connect/send 없음 |
| 1 | 같은 nsenter 경로 + `/usr/lib/linux-tools/6.8.0-147-generic/bpftool -j net show` | 현재 Target TCX metadata 조회만 |
| 1 | 같은 nsenter 경로 + `/usr/bin/cat /proc/net/packet /proc/net/unix` | Target AF_PACKET/AF_UNIX metadata. 실제 packet/payload 수집 없음 |
| 3 | 고정 bpftool의 `-j link show`, `-j map show`, `-j prog show` | 전역 metadata 조회만. 소유권 독립 확인, load/dump/update/delete/attach/detach 금지 |
| 1 | `/usr/bin/stat --format=… -- <고정 백업7개>` | 저장된 설치 기록의 고정 backup 경로만. regular/non-symlink·Root 소유권 확인 |
| 1 | `/usr/bin/sha256sum -- <동일 백업7개>` | 원본 pre-install SHA와 대조. 설치·교체·권한 변경 없음 |
| 1 | `/usr/bin/sha256sum -- /var/lib/soc-agent/continuous/1000.jsonl` | 현재 raw Root Audit SHA만 읽어 저장된 snapshot과 비교. Append/수정 없음 |

**별도 승인할 제안 범위: 명령9개·각15초·전체최대180초·동시1개·자동 재시도0.**
실행 전 현재 Binding·boot·Namespace·Ledger·binary SHA를 다시 확인하고, 사용자가 Scope를
직접 확인한 뒤 사용자 터미널에서 sudo 인증해야 한다. 인증 대기 터미널은 열지 않았다.
서비스가 다시 active가 되거나 예상하지 못한 PID/Link/Map/Socket·백업 불일치가 보이면
검사를 중단하고 증거만 보존한다. 서비스 Stop·잔류 삭제·수리·Native 재시작 권한은 없다.
환경 변수·cmdline·비밀번호·API 키·Host 인증 로그는 조회·기록하지 않는다.

## 기존 재시험 Artifact·Session 재확인

기존 새 실행 검토서:
`.git/dns-helper-cleanup-evidence-review-20261030T023558Z/review/approval-package-final.md`.
이번 읽기 전용 검사 계획은 이 Native 검토서를 대체하거나 승인하지 않는다.

| 항목 | 기존 후보와 일치하는 Binding |
|---|---|
| 운영 Commit / Tree | `5b14a67fd3927e6105d8d2e57b525725428703ec` / `0625f5a9e3648a2c0adcdc6f51cab4000a3fec0b` |
| Source archive | `8f1a303aa44e3d151a920216c69fa520009b00ca6123f8e0dcba514ed247fd5f` |
| Root Manifest | `9496cbb705daff518a6646095f2023436dee83749cd459b80ac3e113395256fa` |
| Wheel | `fbfa6225b541d0711dbef5f6633ceb54ed3ebfb6859fde26d42787c37c78ad56` |
| Native 요청서 | `eae0c29e235c4ee774f4724485a765a8e2d92043383600dbde0b00547b3b832d` |
| Runtime Session | `f4147fc4-40e3-4a01-bc32-267f4f58ed88` |
| DNS Session | `bf76008d-6899-48d7-a4bb-7563b816d1d6` |
| Release / Scope | `0.6.3` / `net:[4026532232]`, lo/Ingress |
| Ledger81行 | `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` |

Native6개·Wheel 이중 빌드 bytes, 동결 Source, Helper closure803개 및 Controller Python124개를
다시 SHA 대조했다. 기존 Source 그대로여서 새 빌드·새 Native Session을 불필요하게 만들지 않았다.
공식 `soc-agent doctor`의 Host 읽기 전용 검사는 PASS, Target 내부 검사는 승인 대기 BLOCKED다.
비실행 Preview·변조/Replay·TTY 경계·Host 진단 단위 회귀는 Workspace/독립 Export 각각 **9 PASS**다.
모의 Root 경계 테스트이며 실제 Root 검사는 아니다. 기존537/537·집중53/53·coordinator11·GUI 검증은
직전 동일 운영 Source의 결과로 재사용했으며 이번 실행 결과와 구분한다.

## 안전한 재시험 가능 여부와 남은 인간 승인

**현재 재시험 불가 / BLOCKED.** Host 가시 범위에서 잔류가 발견되지 않았다는 사실만으로
미수행 Target·Root 검사를 PASS 처리하지 않았다. 다음 단계는 위 읽기 전용 권한 검사 승인이다.
검사 이후에도 과거 Cleanup UNVERIFIED·FAILED·false·UNKNOWN은 보존한다.

그 다음 실제 재시험에는 현재 자원 검사 결과, 정확한 후보의 Root 설정·TCX·시간/자원·
TCP/DNS Scope·R1 잔여 위험에 대한 별도 인간 결정과 기존 계약 검증이 필요하다.
기존 영수증은 재사용하지 않는다. Target 내부 check PASS·사용자 Scope 확인·sudo 인증 전에는
설치·예약·Capture·트래픽을 시작하지 않는다.

후보 Scope는 전체최대3600초, TCP127.0.0.1:18080/Client18081·18082/최대38연결,
DNS127.0.0.53:53/UDP2·TCP1이며 정확한 payload·간격·자원 제한은 원 검토서 그대로다.
RF/LR는 봉인된 ELIGIBLE 작업별 모델 Action 승인이 별도로 필요하다. DNS9·외부 API는 제외한다.
후보 만료 상한은 **2026-10-30 17:36:32.192496 KST**이며 연장하지 않았다.
만료·Ledger·Scope·Artifact 변경 시 기존 후보를 그대로 실행할 수 없다.

기존99개 증거 SHA, 설치본, Ledger81행, SQLite·Queue·Audit를 보존했다.
이번 저장소 변경은 문서뿐이며 실제 Cleanup 작업이나 실환경 재시험을 수행했다고 보고하지 않는다.
