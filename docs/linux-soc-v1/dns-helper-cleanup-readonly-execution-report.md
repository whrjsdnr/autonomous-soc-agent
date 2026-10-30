# 승인된 Cleanup 읽기 전용 검사 결과

2026-10-30, 기준 문서 `9055f52`, 운영 Source `5b14a67`.
**승인된 Root 조회9개 각각1회·모두 Exit0. 현재 승인 Scope의 소유 잔류 없음 확인.**
Native 재시험·설치·트래픽·모델 권한은 부여하거나 실행하지 않았다.

## 승인·인증·실행 증거

승인 대상은 `.git/cleanup-final-readonly-review-20261030T030948Z/readonly-inspection-review.md`다.
검사 계획 SHA256 `f14a76ec7387df51ee63527ceecd2c5afb5e80f5e828db3867bbed7781bd35b0`,
검토서 SHA256 `a66658c17a7d3c557607c7d24eff21edd20be08f58d2eeebcf1aad21387957d9`를 대조했다.
Git·Source·Artifact·Session·Namespace·Lease·Ledger·실행 파일·명령 인자를 재검증한 뒤
실제 사용자 터미널의 Scope `yes`와 직접 sudo 인증을 확인했다. 입력·비밀번호는 기록하지 않았다.

실제9개 조회 증거:
`.git/cleanup-readonly-auth-recovery-20261030T032841Z/`.
각 stdout/stderr·argv·시각·child exit는 `01-…json`부터 `09-…json`에 있으며,
`inspection-final-report.json`, `readonly-inspection-audit.jsonl`9행에 결과와 SHA를 보존했다.
Root 조회는 승인된 argv 그대로이며 Root 실행 파일을 설치하거나 별도 Root wrapper를 실행하지 않았다.

## 9개 검사별 결과

| 검사 | 결과 | 실제 관측 |
|---|---|---|
| 1. Namespace·lo·route·cookie·TCP/UDP | PASS / Exit0 | net:[4026532232], lo ifindex1/up, cookie8855, 외부 route 없음, TCP/TCP6/UDP/UDP6 소켓 행0 |
| 2. Target TCX metadata | PASS / Exit0 | XDP/TC/flow_dissector/netfilter 부착 목록 비어 있음 |
| 3. Target Helper sockets | PASS / Exit0 | `/proc/net/packet`, `/proc/net/unix` 모두 header만 존재. AF_PACKET·Unix 소켓 행0 |
| 4. BPF Link show | PASS / Exit0 | 전역 Link 목록 `[]` |
| 5. BPF Map show | PASS / Exit0 | 전역 Map 목록 `[]` |
| 6. BPF Program show | PASS / Exit0 | 11개 ID1992–2002. 이름 sd_devices/sd_fw_egress/sd_fw_ingress, type cgroup_device/cgroup_skb. 프로젝트 ingress 프로그램 없음 |
| 7. Root 백업7개 metadata | PASS / Exit0 | 모두 regular file, uid/gid0, mode600. Symlink 아님 |
| 8. Root 백업7개 SHA | PASS / Exit0 | 원 설치 전 기대 SHA와7개 모두 일치 |
| 9. Root Audit SHA | PASS / Exit0 | raw Audit SHA `5c29014401daaaaa3279ea0afb914e70dabf5e4de5616b1a1ea2e028276092cd`, 보존 snapshot과 동일 |

관측 시각: 2026-10-30T03:29:11Z, KST12:29:11.
Scope 확인·인증·검사 전체 **3.834초**, 실제9개 command elapsed 합계 **0.203초**다.
전체180초·각15초 제한 이내이며 timeout0, 최종 terminal exit0이다.
Namespace 검사의 cookie 조회용 임시 unbound UDP FD는 조회 후 닫혔다.
DNS/TCP 요청·bind/connect/send·AF_PACKET 생성·Capture는 수행하지 않았다.

11개 기존 BPF 프로그램은 삭제하거나 변경하지 않았다. 이름/type 관측만으로 모든 프로그램의
소유권을 확정하지 않으며, 시스템 전체 BPF가 비어 있다고 보고하지 않는다.
조회 후 일반 사용자 서비스 재확인에서도 관련5개 서비스 MainPID0·ControlGroup 비어 있음을 확인했다.

## 최초 오류·RCA·인증 수정

첫 인증 시도 증거는 `.git/cleanup-readonly-execution-20261030T032410Z/`에 그대로 보존했다.
ordinary terminal launcher에 추가한 `sudo -k -v` 조합이 자격 증명을 캐시하지 않는 문제가 있었다.
인증 returncode0 뒤 첫 `sudo -n`이 `sudo: a password is required`로 거부됐다.
이때 sudo exit1·wrapper exit2였고, **실제 Root 검사 실행은0개**였다. Kernel·Namespace 오류가 아니다.

설치된 sudo1.9.15p5의 `/usr/share/man/man8/sudo.8.gz`는 `-k`와 인증 옵션을 함께 쓰면
캐시를 갱신하지 않는다고 명시한다. 기존 운영 터미널의 `sudo -v` 흐름으로 ordinary launcher만 수정했다.
Root 명령·인자·검사 계획은 바꾸지 않았다. 사용자가 새 터미널에서 Scope와 인증을 다시 직접
완료한 뒤에만 미실행9개 조회를 각각1회 수행했다. 자동 Root 재시도·소비된 Native 승인 재사용은 없었다.
첫 권한 거부 stdout/stderr·최초 오류·수정 후 성공 결과는 분리 보관했다.
운영 Source나 sudo 정책·Host 설정은 변경하지 않았다.

## 현재 자원과 과거 Cleanup 판정 분리

| 영역 | 현재 승인된 Snapshot | 과거 실행 Cleanup 판정 |
|---|---|---|
| DNS Helper | 원 PID 부재, Target AF_PACKET/Unix 소켓0 | **UNVERIFIED**: 당시 CLOSED·최종 Counter 없음 |
| TCX Collector | 원 PID·소유 Unix 경로 없음, Target TCX 없음, Map/Link 없음 | **VERIFIED**: 당시 소유 TCX STOP ACK·정리 증거 범위 |
| Root 소유 자원 | 관련 서비스 정지, 백업7개 정합성 확인, 승인 Scope 잔류 없음 | **UNVERIFIED**: 당시 Helper 종료 영수증을 보완하지 않음 |
| Runtime | 원 PID 부재, Audit 정합성 유지, Queue PENDING1/POISON1 보존 | **UNVERIFIED**: 당시 aggregate Cleanup 미검증 유지 |
| Global Kernel | 현재 Link/Map0, 기존 프로그램11개 유지 | **UNVERIFIED**: Program1145 원인 UNKNOWN·과거 전역 증거 부족 유지 |

따라서 현재 물리 Cleanup 미완료·잔류가 확인된 것은 아니다.
**이번 승인 범위의 현재 자원 전제조건은 PASS**지만, 과거 Helper 종료 기록을 소급해 성공으로
바꾸지는 않는다. 최초 heartbeat 지연 원인도 UNKNOWN이다. 시스템 전체 무관 자원의 정리나
장시간 Native 안정성까지 VERIFIED로 확대하지 않는다.

## Native 재시험 가능 여부

이제 “현재 Target 자원·Root 백업을 확인하지 못함”이라는 사전 검증 차단은 해소됐다.
다만 이번 승인은 읽기 전용이므로 실제 Native 재시험 권한은 **별도 승인 대기**다.
정확한 기존 후보의 신규 Root 설정·TCX·TCP/DNS·시간/자원·R1 위험 수용과 사용자 인증이 필요하다.
RF/LR는 실제 봉인된 ELIGIBLE 작업별 별도 Action 승인을 유지한다. API·DNS9는 제외한다.

후보 `.git/dns-helper-cleanup-evidence-review-20261030T023558Z/review/approval-package-final.md`는
변경하지 않았다. 운영 Commit `5b14a67fd3927e6105d8d2e57b525725428703ec`,
Root Manifest `9496cbb705daff518a6646095f2023436dee83749cd459b80ac3e113395256fa`,
Runtime Session `f4147fc4-40e3-4a01-bc32-267f4f58ed88`,
DNS Session `bf76008d-6899-48d7-a4bb-7563b816d1d6`, Release0.6.3,
Namespace net:[4026532232]·lo/Ingress다. Source·Wheel·Helper·Collector 상세 SHA는 기존 Binding 그대로다.

기존 후보 만료 상한 **2026-10-30 17:36:32.192496 KST**와 입장 시 필요한 잔여 시간을 유지한다.
새 실제 실행 전 최신 자원·정책·Binding을 다시 확인해야 한다. 이번 현재 Snapshot은 영구 권한이 아니다.
기존 영수증을 재사용하거나 과거 UNVERIFIED를 승인 영수증으로 대체하지 않는다.

## 보존

기존99개 증거 SHA·설치·Rollback·Runtime SQLite/Queue·Audit·Ledger81행은 변경하지 않았다.
기존 Root Audit raw SHA도 실제 권한 조회로 동일함을 확인했다.
새 결과·9행 읽기 전용 검사 Audit만 별도 디렉터리에 저장했다.
Legacy Ledger의 기존 사용량을 증감·초기화·환급하지 않았으며 Native·트래픽·모델·외부 API 실행0이다.
