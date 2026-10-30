# DNS Helper Cleanup 증거 재검증 및 종료 시험 준비

검토일: 2026-10-30, Asia/Seoul. 운영 구현 `5b14a67`, 이전 보고서 `520b43f`.
**비권한 검증 PASS / 새 실환경 실행 BLOCKED**. 이번 작업은 운영 코드를 변경하지 않았다.
이미 검증한 수정본·재현 빌드를 재사용하고, 과거 Cleanup 증거와 새 실행 후보를 분리했다.

## 독립 Cleanup 판정

조사한 실제 실행은 `cd78b59` Artifact의 Runtime Session
`49525e9b-74fa-4983-9254-8ca1b7d249c4`, DNS Session
`58d76ffc-7d19-426b-b452-4a7fb4e1accb`다.
원본 경로는 `.git/packet-dns-heartbeat-recovery-20261030T010933Z/final/review/`다.

| 영역 | 판정 | 확인한 증거와 한계 |
|---|---|---|
| Helper Cleanup | **UNVERIFIED** | 저장된 Helper 서비스 Result=success/Exit0, 원 PID2703050의 현재 부재 확인. 그러나 authenticated CLOSED·최종 Counter 영수증 없음 |
| Collector Cleanup | **VERIFIED** | 해당 실행의 소유 TCX 원격 STOP ACK, Root SERVICE_STOPPED, 저장된 Target TCX 검사, Link·Map·소유 socket 정리 범위 |
| Root-owned Resource Cleanup 전체 | **UNVERIFIED** | 공급원·client socket 정리와 서비스 PID0 확인. DNS Helper 프로토콜 종료 증거를 포함한 전체 판정은 미충족 |
| Runtime Cleanup | **UNVERIFIED** | Collector·Worker STOPPED, Runtime Exit2. Audit·final_flush VERIFIED는 전체 Cleanup을 뜻하지 않음 |
| Global Kernel Cleanup | **UNVERIFIED** | 당시 전체 program ID 목록은 변했으며 소유권·인과관계 확인 불가. Program1145 원인 UNKNOWN 유지 |

읽기 전용으로 Root Audit SHA·hash chain·이전 prefix, Runtime Audit22행·detail20개·state digest,
Namespace 종료 snapshot을 검증했다. 기존 Queue는 PENDING1/POISON1로 보존했다.
Root Audit의 정상 Stop을 DNS stream 성공으로 확대하지 않았다.

2026-10-30T02:35:58Z 이후의 현재 서비스 조회에서도 Collector·DNS Helper·dnsmasq·TCP 공급원은
inactive/MainPID0, Runtime은 failed/Exit2/MainPID0였다. 현재 PID·서비스 상태는 당시 순간의
상태나 누락된 STOP ACK를 대체하지 않는다. 현재 Target Namespace에 진입하지 않았다.
Root 백업7개는 일반 사용자에게 읽기 권한이 없어 내용 SHA 재검증은
**UNKNOWN_READ_PERMISSION**이다. 저장된 백업 경로·설치 기록은 보존했다.

## UNKNOWN으로 남는 원인

최초 heartbeat 침묵의 syscall·스케줄링·socket backlog, 오류 순간 Helper liveness,
Helper 개별 송신 timestamp 및 당시 GUI frame timestamp는 기록이 없어 UNKNOWN이다.
Helper가 먼저 crash했다고 확정하지 않는다.

원본 receiver가 실패 후 채널을 닫아 최종 CLOSED 수신 경로를 잃은 결함은 이전 구현에서 수정됐다.
과거 CLOSED·Counter는 소급 생성하지 않았다. 기존 FAILED·false·UNKNOWN도 변경하지 않았다.
운영 코드 수정 내용은 [생명주기 안정화 보고서](dns-helper-lifecycle-cleanup-report.md)를 참조한다.

## 수정본 비권한 재검증

- Workspace 집중 회귀 **53 PASS**, 독립 Export 동일 회귀 **53 PASS**.
- 실제 고정 Root coordinator의 비권한 계약·READY·오류 보존·Stop 경로 **11 PASS**.
  Root·서비스 제어 경계만 모의했으며 승인 영수증은 메모리 fixture로만 사용했다.
- 정상 종료, 실제 일반 사용자 자식 Exit7, heartbeat 지연, ACK 누락, socket 종료,
  Cleanup commit 실패·취소, Owner STOP 경합, Session 재사용 차단을 재확인했다.
- 실제 Tk의 Dashboard·Continuous·AI Analysis·Investigation·System 및 2회 종료/재연결 PASS.
  보존된 실제 Native34·DNS 거래3·모델0·DEGRADED·Cleanup UNVERIFIED를 표시했다.
  원본에 없는 lifecycle 필드는 NOT_RECORDED이며 GUI 종료로 Backend를 중지하지 않았다.
- 공식 `soc-agent` Entry Point의 `doctor`, `start --preview`, `status` PASS.
  새 private profile은 STOPPED/NOT_STARTED다. Preview는 실행 권한이 아니다.
  Host 검사에서 Target 내부 check는 BLOCKED로 남겼고 Namespace Scope를 우회하지 않았다.
- 새 격리 Helper Python의 interpreter/의존성124개, 전체 Helper closure803개 파일을 SHA로 확인했다.
  `-I -B`, 메모리256MiB·CPU20초 import probe PASS, ML import·추론 없음.
- Ruff PASS, Format1308파일 PASS, Diff PASS.

동일 운영 Source에서 이미 완료한 Workspace/Export 각각537 PASS 및 Native6개·Wheel 이중 빌드는
반복하지 않았다. 두 빌드의 실제 bytes·SHA와 동결 Source를 다시 대조했다.
BTF 검증은 기존 비권한 libbpf parsing이며 이번에도 Kernel load 검증이 아니다.

## 새 Artifact와 실행 후보 Binding

새 증거 디렉터리:
`.git/dns-helper-cleanup-evidence-review-20261030T023558Z/`.
정확한 파일 목록은 `final-artifact-binding.json`, 검증 결과는 `final-verification.json`이다.

| 항목 | 정확한 Identity |
|---|---|
| 운영 Git | `5b14a67fd3927e6105d8d2e57b525725428703ec` |
| 운영 Tree | `0625f5a9e3648a2c0adcdc6f51cab4000a3fec0b` |
| Source archive SHA256 | `8f1a303aa44e3d151a920216c69fa520009b00ca6123f8e0dcba514ed247fd5f` |
| Source canonical digest | `a50924b4496ac5b0d1ec7298ef8d9e4614f8e64459c568b38a6490d5b0a66fcf` |
| 새 검토 Source file-map SHA256 | `d4f8c93e0dca1add4f6fc52c9f3239f6a9288bcd7565ac0aa17eed5a59a47baa` |
| Wheel SHA256 | `fbfa6225b541d0711dbef5f6633ceb54ed3ebfb6859fde26d42787c37c78ad56` |
| Root Manifest SHA256 | `9496cbb705daff518a6646095f2023436dee83749cd459b80ac3e113395256fa` |
| Root Collector service.py SHA256 | `afdf9c86e5098ead73bcd1e27311ee419b1eef5d393a449b1dd95c4abd315041` |
| TCX BPF SHA256 | `da58d00289ce04a3c818f8ca5b776f1b2fccaaef9b96f324f60a24904bcde8f6` |
| Provider SHA256 | `62e4610379f9dc3b8f2a5fb070009dfcdcdbf2c1a5a0f6d76c0c2a22b6296bff` |
| Controller Python manifest SHA256 | `eff01eaa4ee17b4e6320c0121431e46c9a74c4a4899acf5a1e93c26b9fb21e04` |
| Helper Python closure SHA256 | `2ea7b502e1658ac78ff873548b7b4728d7ce67d039af05009f59e5c56a49ea50` |
| 새 Runtime Session | `f4147fc4-40e3-4a01-bc32-267f4f58ed88` |
| 새 DNS Session | `bf76008d-6899-48d7-a4bb-7563b816d1d6` |
| Release / Namespace | `0.6.3` / `net:[4026532232]`, lo/Ingress |
| Ledger81행 SHA256 | `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` |
| 새 요청서 SHA256 | `eae0c29e235c4ee774f4724485a765a8e2d92043383600dbde0b00547b3b832d` |
| 사용자 검토 패키지 SHA256 | `d1d70849b662a73733f69800ec561d087a760172b32d26818156a7d2662993b9` |

빌드 당시 file-map SHA `de8c39907cfaa86f52e503915525aeeb2565e8cabbe64017ddae270f6cda3394`와
새 검토 file-map SHA는 JSON 직렬화 bytes가 다르다. 두 map의 경로·파일 SHA는 완전히 같고
canonical digest도 같다. SHA를 덮어쓰거나 이 두 파일을 같은 bytes라고 보고하지 않았다.
보고서 커밋은 문서 변경만 포함하며 실행 Artifact는 위 운영 Commit에 동결돼 있다.

Root Manifest는 기존7개 고정 경로 후보를 대조한다. 실제 bytes가 달라지는 후보는 설치 정책 JSON,
일반 사용자 Runtime unit, 새 Session을 가리키는 DNS Helper unit의 **3개 설정**이다.
Root Collector·BPF·Provider 실행 파일 변경은 없다. 새 후보의 승인·영수증·실행은 모두 미발급/미시작이다.

## 다음 실환경 시험 최소 조건과 BLOCKED 해제 여부

새 검토 자료는 `review/approval-package-final.md`, 요청서는 `review/approval-request-final-v2.json`이다.
사용자가 SHA를 복사하거나 입력할 필요 없이 기존 CLI가 대조한다.

1. 기존 Cleanup의 누락 범위와 현재 소유 자원을 검토해야 한다. 필요한 Namespace 내부 socket/TCX,
   백업7개 내용·권한 검사는 별도의 정확한 읽기 전용 권한 Scope와 인증을 먼저 확보한다.
   과거 CLOSED 부재는 소급 복원할 수 없으며 위험 수용만으로 VERIFIED가 되지 않는다.
2. 신규 Root 설정·Helper 실행·TCX·TCP/DNS·시간/자원·R1에 대한 인간 결정과 기존 계약 검증이 필요하다.
   이전 영수증은 재사용하지 않는다. 현재 준비 자료의 만료 상한은 **2026-10-30 17:36:32.192496 KST**이며,
   정책 유효기간을 연장하지 않았다. 만료·Ledger·Binding 변경 시 다시 검증한다.
3. Scope는 기존 Target lo/Ingress, 전체최대3600초, Queue32/Storage256MiB를 유지한다.
   TCP127.0.0.1:18080·Client18081/18082·최대38연결, DNS127.0.0.53:53·UDP2/TCP1이다.
   포트·payload·간격·UID·Capability·한 번의 실행 제한은 요청서에 고정했다.
4. Target 내부 비소비 check PASS, 사용자 직접 Scope 확인과 sudo 인증이 필요하다.
   새 시험에서는 STOP→CLOSED/Counter→원 PID 종료→FD/reader 종료→파일·디렉터리 fsync를 각각 수집한다.
   Stream 실패와 Cleanup 성공은 별도로 판정한다. 자동 Root/Native 재실행은 하지 않는다.
5. RF/LR는 실제 봉인된 ELIGIBLE 작업별 별도 Action 승인까지 차단한다.
   DNS9·외부 API·Host 인증 수집·외부 네트워크는 이 시험 후보에 포함하지 않는다.

**현재 BLOCKED는 해제하지 않았다.** 비권한 성공은 Kernel 종료 증거를 대체하지 않는다.
새 Artifact·미시작 Session·실행 계약 준비는 완료했지만 기존 전체 Cleanup은 UNVERIFIED다.
어느 영역의 VERIFIED도 다른 영역으로 확대하지 않았으며 새 Root/Native/DNS 시험은 수행하지 않았다.

## 보존 및 Git

기존 증거·설치·Ledger·Runtime SQLite·Queue·Audit 총99개 SHA 재확인, 변경 없음.
Ledger81행·Campaign Root12/Native4·Batch3 Root9/Native1의 기존 기록을 보존했다.
최신 통합 시험의 별도 Root Audit를 Legacy Ledger로 역산해 추가하지 않았다.
이번 저장소 변경은 이 보고서와 기존 보고서의 연결 문서뿐이다. 운영 Source·승인·예약은 변경하지 않았다.

후속 현재 Snapshot과 정확한 읽기 전용 권한 검사9개는
[최종 Cleanup 확인 보고서](dns-helper-cleanup-final-check.md)에 정리했다.
과거 판정과 이 검토서의 Native Artifact·Session·요청서는 변경하지 않았다.
