# Packet·DNS 및 Helper Cleanup 재시험 준비

2026-10-30. **PREPARED / PENDING_EXPLICIT_EXECUTION_APPROVAL**.
운영 Source `5b14a67`, 검토 문서 기준 `263614b`.
새 승인 시스템·운영 코드·수집기를 개발하지 않았다. 통과한 Cleanup 검사9개를 재사용했으며
추가 Root 조회·Native·DNS·모델 실행, 예약·승인 영수증 발급을 하지 않았다.

## 하나의 사용자 검토 패키지

위치: `.git/packet-dns-cleanup-final-retest-review-20261030T034224Z/approval-package.md`.

새 통합 요청서는 현재 자원 사전 검증, 기존의 정확한 미시작 Native 실행 계약, R1 잔여 위험,
Root 설치·TCX·TCP/DNS·시간/자원·필수 종료 증거를 묶었다. 이 통합 검토와 그 안에 명시한
기반 Native 요청서를 함께 명시적으로 승인해야 한다. 기존 승인이나 읽기 전용 검사 승인을
Native 권한으로 전환하지 않는다. 각 결정은 기존 CLI 계약으로 독립 검증한다.

| Binding | 값 |
|---|---|
| 새 통합 요청서 SHA256 | `897c3ef03d2c382392759152b5f1718f45381209562bb6ae252041aa982e155d` |
| 새 패키지 SHA256 | `b2094ca567167d47f6418bcfcd8162b4a074282bf12b6da8fa49573012a5d8db` |
| 기반 Native 요청서 SHA256 | `eae0c29e235c4ee774f4724485a765a8e2d92043383600dbde0b00547b3b832d` |
| 문서 Git / Tree | `263614b200b49b1cf171605cbd76f57cf0a3aacf` / `ca6740979a6620fc61ecb21504ced6f3668b8a84` |
| 동결 운영 Git / Tree | `5b14a67fd3927e6105d8d2e57b525725428703ec` / `0625f5a9e3648a2c0adcdc6f51cab4000a3fec0b` |
| Source archive SHA256 | `8f1a303aa44e3d151a920216c69fa520009b00ca6123f8e0dcba514ed247fd5f` |
| Wheel SHA256 | `fbfa6225b541d0711dbef5f6633ceb54ed3ebfb6859fde26d42787c37c78ad56` |
| Root Manifest SHA256 | `9496cbb705daff518a6646095f2023436dee83749cd459b80ac3e113395256fa` |
| Runtime Session | `f4147fc4-40e3-4a01-bc32-267f4f58ed88` |
| DNS Session | `bf76008d-6899-48d7-a4bb-7563b816d1d6` |
| Release / Scope | `0.6.3` / `net:[4026532232]`, lo/Ingress |
| Ledger81行 SHA256 | `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` |
| 이번에 사용한 Cleanup 결과 SHA256 | `ffc74178e9c1c165953b750eb22aad8a53ad42d32b7cd73c4577207f6f1b617f` |

위 Session은 아직 admitted/실행되지 않았다. READY/CLOSED/실행 예약·소비 marker 부재와
SQLite Store ID·초기 STOPPED/NOT_STARTED를 확인했다. 검증된 빌드와 미시작 Session을 유지했으며
소비된 영수증이나 과거 실행 Session을 재사용하지 않는다. 문서 커밋과 운영 Source를 구분했다.
모든 Source·Native6개·Controller/Helper·모델 상세 Identity는 통합 JSON과 기반 요청서에 있다.

## 정확한 실행 Scope·예상 시간·자원

- 기존 Namespace만 사용한다. 새 Namespace 생성·삭제나 Host 설정 변경은 없다.
- Root Manifest의 고정7개 경로를 기존 coordinator로 백업·설치하는 승인 후보이다.
  실제 내용 변경은 설치 정책 JSON·Runtime unit·DNS Helper unit의3개 설정이며,
  나머지4개는 동일 bytes지만 기존 coordinator의7개 경로 처리에 포함된다.
  Root Collector/BPF/Provider 실행 bytes 변경·추가 패키지·서비스 enable은 없다.
- 전체 Root 시험 최대3600초. 정상 경로 약58~60분을 예상한다. Owner STOP3500초,
  Drain 대기3570초까지, 나머지는 Cleanup 예산이다. 순수3600초 수집을 보장하지 않는다.
  Launcher·READY·Capture 시작/종료·STOP·ACK·Drain·Cleanup 시각을 별도로 기록한다.
- Collector128MiB/CPU25%/Tasks4, Window180초. Runtime512MiB/CPU50%/Tasks32·UID1000/Cap0.
  DNS Helper512MiB/CPU10%/Tasks4·소켓 개방 뒤Cap0. dnsmasq64MiB/CPU10%/Tasks8·최대90초.
  Queue32, Runtime 저장256MiB, Root Audit64MiB, 최소여유1GiB. 저장량은 주기적 확인이며
  hard filesystem quota가 아니다. Collector start1회, 자동 재시작·재시험0회다.
- TCP127.0.0.1:18080·Client18081/18082. 세대당2연결, 내부35초 간격, 최대19기동/38연결.
  기동 간격 최소180초·새 세대 조건, 3380초 이후 새 공급원 기동 없음.
  고정 요청 `SOC-CONTINUOUS-PROBE/1\n`, 응답 `SOC-CONTINUOUS-OK/1\n`이다.
- DNS는 로컬 dnsmasq127.0.0.53:53·native-0516.localhost IN A, UDP2/TCP1뿐이다.
  IDs c201/c202/c203·고정 payload SHA, TCP close 후35초 late UDP·45초 관측을 유지한다.
  Collector/Helper READY 전 생성, 외부 연결, 대체 포트·임의 트래픽은 금지한다.

상위 후보 만료는 **2026-10-30 17:36:32.192496 KST**다. 기존 입장 계약상3900초 이상 남아야 한다.
연장하지 않았으며 만료/Binding 변경 시 그대로 실행할 수 없다.

## Helper 종료와 Cleanup 필수 판정

`mandatory-result-evidence.json`을 통합 요청서 SHA에 결합했다.

1. 실제 Native Packet>0, DNS 거래3개(UDP2/TCP1), Window 봉인·Attestation VERIFIED·Network14 ELIGIBLE≥1.
   마지막 INCOMPLETE/UNKNOWN Flow를 적격으로 바꾸지 않는다.
2. 새 Helper READY의 PID·Start Time·FD 소유권, 정확한 Session의 최종 CLOSED·Counter 검증.
   DNS의 STOP ACK는 STOP 요청에 대한 인증된 CLOSED다. 별도의 없는 ACK 필드를 만들어내지 않는다.
3. `dns-session/cleanup.json`: 정상 stream completion·CLOSED·원 프로세스 identity 종료·
   Listener/Channel FD 종료·reader join·cleanup VERIFIED를 모두 확인한다.
   STOP/CLOSED timestamp·Counter와 file/directory fsync 이후 Runtime에 게시된 evidence SHA가 필요하다.
4. TCX의 generation/policy-bound STOP_CAPTURE·STOP ACK와 owned Cleanup VERIFIED,
   Root Audit SERVICE_STOPPED·서비스 종료·소유 자원 정리를 확인한다.
5. Runtime Collector/Worker STOPPED, Cleanup/final_flush/Audit VERIFIED가 필요하다.
   미승인 모델 작업·Queue 잔여는 보존·별도 보고하며 성공을 만들기 위해 삭제하지 않는다.
6. Root/Terminal Exit0만으로 성공하지 않는다. 누락·오류·Cleanup 실패는 최초 단계/errno/자식 종료코드와
   함께 기록하고 후속 실행을 중단한다. Stream 실패와 Cleanup 성공도 별도로 판정한다.

과거 Program1145·heartbeat UNKNOWN, FAILED·false, Helper/Root/Runtime/Global Cleanup UNVERIFIED는
유지한다. 이번 결과로 전역 Kernel 과거 Cleanup을 소급 승격하지 않는다.

## 승인 조건·검증·다음 단계

필요한 인간 결정은 **R1 조건부 위험 수용, 고정 Root 설치, Native TCX, 고정 TCP, 로컬 DNS**다.
승인 이후에도 기존 CLI가 정확한 Binding·정책·Scope를 검증하고 사용자가 직접 yes/sudo 인증해야 한다.
실행 후보는 기존 `soc-agent start --home <기반 검토 profile> --gui`이며 이번에는 실행하지 않았다.
실제 GUI·status·stop도 같은 profile을 사용한다. 사용자 SHA 복사·입력은 필요하지 않다.

모델 Action은 실제 봉인된 ELIGIBLE 작업별 **별도 승인**이다. 이번 Capture 승인으로 RF/LR를
자동 실행하지 않는다. 모델0회라면 전체 Native AI 릴리스 완료로 보고하지 않는다.
DNS9·외부 API·Host 인증 수집도 이번 실행 후보에서 제외했다.

기존 Root Manifest·Helper closure803개·동결 Source·현재 Ledger와 전체99개 보존 SHA를 확인했다.
완료된 Cleanup9개 증거·새 요청서·필수 결과 조건의 digest도 대조했다.
공식 비소비 Native Preview PASS이며 실제 Root/Native 실행·예약0이다.
고정 coordinator의 비권한 계약 회귀11 PASS. 동일 Source의 기존 Workspace/Export537/537,
집중53/53·Native/Wheel 재현 빌드는 재사용했고 반복 실행하지 않았다.

최종 상태는 **재시험 준비 완료 / 명시적 실행 승인 대기**다.
다음 실제 시험에서 Packet·DNS·Helper 종료·Root/Runtime Cleanup을 먼저 판정하고,
실제 모델 Action 결과와 남은 운영 검증 범위를 구분해 릴리스 판정을 수행한다.
