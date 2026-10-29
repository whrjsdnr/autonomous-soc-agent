# SOC Agent Operations Verification — 비권한 사전 검증

## 1시간 Native 시험 — 최종 승인 검토 추가

2026-10-29, 실행 기준 Git **`62ba2739ae1d394731182763583daacf196bfd06`** /
Tree **`9a84e7117cc7083de390bb93ea3f873b833382bd`**에서 비권한 준비를 이어서 완료했다.
이 절의 요청이 아래 이전 초안보다 우선한다. **실제 시험은 여전히 BLOCKED(인간 승인 대기)**다.
이번 추가 작업의 Root·Namespace 진입·Capture·TCP·Native 모델·API·예약·승인 영수증 발급은
모두0회다. 기존 API2회 성공은 이전 보존 Native Incident의 결과로만 유지한다.

### 확정된 검토 자료와 실제 파일

공통 Git 디렉터리:
`.git/one-hour-operations-review-20261029T030123Z/`.

| 자료 | SHA256 |
|---|---|
| 최종 `approval-request-final-v2.json` | `4e8856136e15c91738a998545dbee867c331d00cc9384343eee3c1f10deac5cd` |
| 정책 입력 `scope-input-v2.json` | `40f1ad747c319c40e210cb7227fc7c4ababb6764220a1c55d708e9b1a37b0188` |
| 최종 Root 설치 Manifest `root-install-manifest-v3.json` | `5038a5f0f822f9063939f6ca516602e8614affa75e7cf541a330fd63cf2dae24` |
| 설치 계약 후보 `continuous-installation-v2.json` | `a250b68cb424d6be7bb842eda65c03bc470d5ade9dd6d61e3b7f01fafebf845d` |
| 새 Runtime 설정 `runtime-config-v2.json` | `294b84e4aa8c9bc25dadcbb7aee6a8a91e4851c81eb67bd5f6ce0794eef8ba7c` |
| 일반 UID system unit `soc-operations-runtime.service` | `8e8e64167bb01983ab87d496b57447e2da55416cbec043b788b542681f7c5618` |
| Git62ba273의 실제 Source tar snapshot | `5bc09c637970385070c9cc334a87298dff6ee08ca01068b179e77a30ffd2c2bb` |

사용자가 SHA를 입력할 필요는 없다. 사람용 자료는 같은 디렉터리의 `approval-package-final.md`이며
프로그램이 요청·Source·Runtime·모델·파일·Scope·Ledger를 대조한다. 후보 설치 계약과 이 요청의
유효기간 상한은 **2026-10-30 12:04:19.131099 KST**다. 실제 인간 승인 시점+24시간보다
길게 허용하지 않으며, 만료·남은 실행 시간 부족·Binding 변경 시 시작하지 않는다.
실제 실행 Source는 검증된 Git62ba273 export로 동결했다. 이후 보고서 전용 Commit을 실행 코드
변경으로 혼동하지 않으며 실행 중 checkout을 교체하지 않는다. 기존 Diagnostic Release/Image
승인을 이 Continuous 설치 Manifest로 재사용하지 않는다.

현재 승인 상태는 다섯 항목 모두 **PENDING**이다: 관리자 설치 정책/고정 설정 설치,
Root Namespace check·고정 서비스 제어, R1 조건부 위험 수용, Native Continuous1회,
로컬 TCP 공급. 하나의 사용자 검토에 묶되 기존 계약에 따라 각 결정을 독립적으로 기록한다.
모델 Action은 봉인 이후 실제 입력에 대해 별도로 검증하며 아직 발급하지 않았다.

### 이번 점검에서 발견한 실행 환경 문제와 준비한 수정

현재 `systemctl --user show`는 **user bus 없음**으로 실패한다. 기존 일반 사용자 unit을
설치·시작했다고 보고하거나, 자원 제한 없이 CLI process로 대체하지 않는다.
기존 `continuous service-unit` 출력에 UID/GID1000·Capability 0을 명시한 **system manager용
후보 unit**을 준비했다. CPU50%·Memory512MiB·Tasks32·NoNewPrivileges·자동 재시작 없음은
유지하며, AF_UNIX만 허용하고 Source/Home은 read-only, 새 Runtime directory만 writable이다.
모델/AI/GUI가 Root로 실행되는 변경이 아니다. `systemd-analyze verify` PASS지만 실제
User1000 cgroup·Worker 생명주기는 승인된 실환경 시험에서 확인해야 한다.

따라서 승인할 고정 Root 설정은 **4개**다. BPF/Provider/Root service/policy 실행 코드와
기존 Helper는 교체하지 않는다.

| 설치/교체 대상 | 변경 |
|---|---|
| `/etc/systemd/system/soc-continuous-collector.service.d/trial-limit.conf` | 240초→3600초 후보. 실행 승인 전 적용 안 함 |
| `/etc/systemd/system/soc-continuous-tcp-trial.service` | 무효 RuntimeMaxSec만 제거, 유효 TimeoutStart90초/Stop5초와 격리 유지 |
| `/etc/soc-agent/continuous-installation.json` | 새로운 이 시험의 인간/R1 검토 입력 SHA와 유효기간에 결합. `native_model_inference=false` 유지 |
| `/etc/systemd/system/soc-operations-runtime.service` | 현재 파일 없음. 고정 UID1000 ordinary Runtime, 512MiB/50%CPU/Tasks32/최대3650초/Restart=no |

기존3개 파일 백업 및 신규 unit의 설치 전 부재를 Manifest에 명시했다. 설치 직후 daemon-reload와
실제 적용된 제한·UID·Capability를 재검증하며, enable/상시 시작/패키지 설치/다른 서비스 변경은
허용하지 않는다. 백업·Rollback은 보존한다. 신규 unit의 Rollback 삭제도 그 정확한 설치 파일과
승인된 복구에만 해당한다. 현재 `/etc`와 실제 서비스 상태는 전혀 변경하지 않았다.

설치 Manifest 초안에서 교체 대상 두 파일이 unchanged assertions에도 포함된 충돌을
사전 검증 중 발견해 최종 v3에서 제거했다. 교체 전 SHA 검증은 `replacements`에 그대로
유지한다. 초기 초안과 수정 기록은 남겼고, 승인·설치에 사용하지 않았다. 정책 입력→후보 정책
출력→최종 설치 Manifest 순서를 지켜 자기 자신의 출력 SHA를 승인 입력에 요구하지 않는다.

### 시간·자원·TCP·모델·종료 계약

- 기존 Namespace `net:[4026532232]`, lo/Ingress. Host `net:[4026531833]`와 mount/boot/Lease
  증거는 일치한다. **이번 내부 check는 미수행**이며 승인 후 실제 lo/Route/Cookie·빈 포트를 확인한다.
- Collector **최대3600초 systemd 실행 상한**, 시작 최대1회, 오류 재시작0.
  128MiB/CPU25%/Tasks4/MEMLOCK8MiB, 180초 또는4000 callbacks/Window,
  전달 최대4096/Window·ring256KiB·per-CPU 분당4096 admission은 유지한다.
- ordinary 서비스 UID1000/Capability0, 최대3650초는 수집 종료 후 Drain용 여유를 포함한다.
  Queue32, 저장256MiB heartbeat 관측 상한, Window512, seen100000, heartbeat1초다.
  Root Audit64MiB, 시작 전 가용 공간1GiB 이상, private0700/0600, 기존 증거 자동 삭제 없음이다.
  Root 과거 Audit 최대행616bytes×3700행 추정은 약2.3MiB로 상한보다 작지만 미래 크기의 보장은 아니다.
- 인증된 TCXProducer의 **RUNNING·새 `counter_state.generation`·fresh Root heartbeat**를 확인한 뒤
  generation당 기존 helper1번, 시작 간격 최소180초, 최대20번이다. 존재하지 않는 별도 READY
  프로토콜을 가정하지 않는다. Collector 시작3560초 이후 새 helper를 시작하지 않는다.
- Listener127.0.0.1:18080, source18081/18082, 총TCP 최대40연결·요청40·응답40.
  고정 payload와 helper의 시작2초 대기/첫 연결 EOF후35초 간격을 유지한다.
  중첩·대체 포트·실패 helper 재시도·DNS·외부 연결은0이다.
- 실제 Native Window/Flow가 봉인·적격 검증된 후 기존 exact job/output/implementation/model
  Action을 검토한다. 수집 승인으로 미래 job의 권한을 발급하지 않는다. 최대 모델 호출40회,
  10개 이상 서로 다른 적격 Window의 RF/LR 처리와 시간대별 진행을 목표로 한다.
  부족하면 실측 범위만 보고하며 무인 연속 AI 운영을 주장하지 않는다.
- 새 Native Incident의 LLM 경로는 **SCRIPTED**, 이번 Scope의 외부 API는 **0회**다.
  이전 실제 API2회는 재사용 승인이 아니며 새 API는 별도 입력·호출·비용 승인 없이는 호출하지 않는다.
- 3595초까지 owner-bound 정상 Stop을 요청하고 3600초 hard limit을 backstop으로 둔다.
  Root STOP ACK/최종 drain/seal/소유 FD·Map·Link·Socket·cgroup 및 ordinary35초 Stop을 확인한다.
  이 **1시간 시험 envelope에는 startup과 종료가 포함**된다. 실제 Kernel 부착·READY·수집 시간을
  각각 기록하며, 3600초보다 짧은 수집을 정확히1시간 수집 성공으로 반올림하지 않는다.
  엄밀한3600초 수집이 필수이면 이 Scope만으로 그 성공을 보장하지 않는다.

시험 시작은 인간 승인→사용자 Scope `yes`·직접 sudo 인증→고정 파일 백업/설치/제한 확인→
Namespace 내부 check→새 ordinary Store 초기화→Root Collector READY→UID1000 Runtime→
인증된 generation/heartbeat→TCP 순서다. GUI는 이 서비스에 Attach하고 관측/Stop/재연결한다.
별도 GUI Start로 cgroup 밖 프로세스를 띄우지 않는다. 봉인 후 실제 모델 Action 검토가 남으며,
승인 대기 Queue를 Drain 성공으로 처리하지 않는다. 실제 모델 NORMAL/UNKNOWN_ANOMALY·
불일치는 그대로 기록하며 정상 TCP를 공격으로 위조하지 않는다.

최초 오류·단계·errno·자식 종료 코드와 후속 Cleanup 오류를 분리하고, Cleanup 불확실 시
후속 실행을 중단한다. 기존 Program1145 UNKNOWN·과거 Cleanup UNVERIFIED·FAILED/false는
이번 위험 수용의 미해결 조건으로 보존한다. Kernel 장애 주입과 자동 Native 재실행은 없다.

### 이번 추가 비권한 검증

| 항목 | Workspace | 독립 Export |
|---|---:|---:|
| Worker 실제 exit·복구, Queue Full, checkpoint 손상/재구성, Audit 손상, Cleanup 실패, 모델 품질 차단, Controller dependency·빌드 | 19 PASS | 19 PASS |
| 실제 Tk 종료·Backend 유지·재연결·보존 Native 결과 | 2 PASS | 2 PASS |
| 새 Native 빌드 | 6개 SHA 일치 | 6개 SHA 일치 |
| 새 Wheel | `ee5bd7624b26c0537fae83ebeb89eda7b6a96ce0a99900a5097bcb3dd1534ef8` | 동일 |
| Controller 기존 builder | 같은 입력2파일 재현 | 같은 입력2파일 재현 |

각21개 관련 테스트가 통과했고 Ruff/Format/Diff 및 두 후보 unit의 verify도 통과했다.
Native6개는 기존 성공본과도 동일하다. Controller 증거는 합성 Namespace의 guarded
compile-only 검증이며 실제 권한 실행 Artifact가 아니다. 제품 Source는 바꾸지 않았다.
이전107 PASS·실제 PCAP 결과와 API 증거도 보존했다.

Legacy Ledger81행/SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`,
Campaign Root12/Native4·Batch3 Root9/Native1은 불변이다. 새 설치 계약 후보는 검증했지만
활성화하지 않았다. `future-runtime`·모델 승인 디렉터리도 아직 만들지 않았고 실제 예약은0이다.
최종 검증·보고서 Commit/Push는 새 증거 디렉터리의 `completion.json`에 기록한다.

**현재 실행 결과: 시간·Packet·Window·Flow·ELIGIBLE·Native RF/LR·새 Incident 모두 미수행.
새 GUI Native LIVE·실제 장시간 Heartbeat/Drop/Drain·실환경 Cleanup도 미검증이다.
판정은 BLOCKED(승인 대기), RC READY와 기존 제한 시험 VERIFIED는 유지한다.**

---

2026-10-29 KST. **이번 장시간 운영 시험 판정: BLOCKED — 새 운영 실행 승인 대기.**
비권한 사전 검증은 통과했다. 기존 `RELEASE_CANDIDATE_READY`와 제한된 Native 성공은
보존했다. 이번에 Root 설치·Namespace 진입·TCX Capture·트래픽 생성·서비스 활성화·
예약·기존 승인 소비·Legacy Ledger 변경은 하지 않았다.

사용자가 후속 메시지로 실제 API 사용을 별도 승인하여, 보존된 실제 Native Incident에
대한 새 API 계획·읽기 전용 조사·평가·Audit를 완료했다. 이는 새 Live/장시간 운영
검증이 아니며 기존 Native SCRIPTED 결과를 덮어쓰지 않는다.

## 중단 지점 복구와 RC 보존

실제 개발 worktree는 `/home/geonug/kdt-linux/continuous-soc-runtime`, branch는
`feat/continuous-runtime`이다. 시작 시 미커밋 변경은 없었다.
기본 `autonomous-soc-agent` worktree의 기존 사용자 변경은 건드리지 않았다.

| 식별자 | 검증된 값 |
|---|---|
| 실행 코드/RC Git | `1f34c60a6cbfdcbdc88c03e0a436b836a5046062` |
| RC Tree | `0396e8e92596bbb23fae1644ff01d16583ba0463` |
| Source 653개 canonical map | `3d6dcb836c07bc2bbdef1f90f89b3b04886072dc266ec45fd5d09c11bdb57ce5` |
| ordinary Runtime Python code identity | `c1c79f53d4951fe4b06589a27609a3c82b139ce6911a2205505e2f6a24a09844` |
| RC Release manifest | `342c4b8a456665cf777818b3626e4a8dc91503db0cbed21bd24df1a64ff0f635` |
| RC wheel | `ee5bd7624b26c0537fae83ebeb89eda7b6a96ce0a99900a5097bcb3dd1534ef8` |
| Model manifest | `26df75bba7b071b7079c8cb994c9ea2bbde39a610aa787a480141744b39cdb80` |

보고서 Commit은 위 실행 코드 동결과 구분한다. 이번에는 제품 Source·README·모델·빌더를
변경하지 않았다. RC의 Workspace/Export Native 6개·wheel 재현 빌드와 Controller 두 파일
compile-only 검증을 재사용하고 실제 산출물 SHA를 다시 대조했다. 불필요한 새 Artifact나
승인 Framework를 생성하지 않았다. BPF는 기존 `verify_object()`로 libbpf 파일 파싱만
수행했으며 Kernel Load는 하지 않았다.

검증 증거는 공통 Git 디렉터리의
`.git/operations-preflight-20261029T023445Z/`에 별도 보존한다.
기존 `.git/soc-agent-rc-20261029T015342Z/final-verification.json`,
`release-manifest.json`, `final-source-files.json`, 모델·성공 증거·설치·Lease·Ledger
18개 baseline 파일의 해시가 전부 일치했다.

## 설치·서비스·Namespace·권한

실제 설치의 기존 `continuous-installation.json`과 Root 소유 파일 검증은
`continuous.native.policy.installed()`를 재사용했다. 실행 권한을 발급하는 함수가 아니다.

| 항목 | 이번 확인 결과 |
|---|---|
| Root Collector | `inactive/dead`, MainPID 0, 마지막 systemd Result success |
| TCP helper unit | `inactive/dead`, MainPID 0, 마지막 Result success |
| 설치 파일 | BPF·provider·service·policy 및 unit/helper SHA가 성공 시험 설치 증거와 일치 |
| Runtime Dependency | Python·libbpf·libelf·libz·libc 기존 5개 SHA 검증 통과 |
| 설치 계약 | 파일/권한/시간 검증 통과, 만료 `2026-10-30T00:14:33.187737+00:00` (KST 09:14:33) |
| Host | `net:[4026531833]` |
| Target mount | `/run/netns/soc-native-b3`, dev 4 / inode 4026532232 / root 소유 |
| Namespace Lease | boot/dev/inode·Host 생성 provenance·기존 SHA 일치 |
| Target 내부 lo/Route/Cookie | **이번 미조회**. 권한 진입 승인 후 재검증 필요 |
| Rollback | 기존 설치/백업 경로·이전/신규 SHA 기록 보존. Root private 백업 내용은 재조회하지 않음 |

설치 계약이 아직 유효하다는 사실은 이미 소비된 240초 시험을 다시 실행할 권한이 아니다.
Host에서 Target 내부 check가 통과한 것처럼 보고하거나 Scope mismatch를 우회하지 않았다.
Diagnostic의 기존 Supervisor/Controller/R1/R2 계약과 Continuous 서비스 권한도 구분한다.

현재 Root unit은 `/usr/bin/python3 -I`로 고정 설치 파일을 실행하며 systemd가 승인된
Namespace에 진입한다. Capability는 BPF/NET_ADMIN/CHOWN, NoNewPrivileges, 읽기 전용
시스템/제한된 writable path, AF_UNIX/AF_NETLINK, 자동 재시작 없음이다.
ordinary Runtime·모델·GUI는 일반 사용자로 분리된다. Controller READY 게시/읽기와 최신
Ledger R1 요청 생성은 기존 운영 함수의 집중 회귀로 확인했다. Continuous의 실제 데이터
수신 경계는 Root SO_PEERCRED·설치 policy·Namespace/generation에 결합된 Unix transport다.

### 현재 제한과 장시간 시험 차단 지점

| 구성 | 현재 계약 |
|---|---|
| Root Collector | 128MiB, CPUQuota 25%, TasksMax 4, MEMLOCK 8MiB, Stop 10초, Restart=no |
| 실제 활성 resource drop-in | `RuntimeMaxSec=240s` — **장시간 실행 불가** |
| ordinary Runtime 생성 unit | 512MiB, CPUQuota 50%, TasksMax 32, Stop 35초, Restart=no. 생성만 했으며 설치/시작 안 함 |
| TCP helper | UID/GID1000, Capability 0, 64MiB, CPUQuota10%, Tasks4, TimeoutStart90초/Stop5초 |
| Root capture | Window180초 또는 callback4000, 전달 최대4096/Window, ring256KiB, per-CPU 분당4096 admission, 5초 관측 lease |
| Root Audit | hash-chain append, 64MiB 상한 |
| ordinary 저장 | 설정된 directory 크기 heartbeat 검사, 상한 도달 시 중단. 강제 filesystem quota는 아님 |

TCP oneshot의 기존 RuntimeMaxSec90초는 systemd가 무시하는 경고가 있지만,
TimeoutStartSec90초가 실제 상한을 유지한다. `systemd-analyze verify`로 경고를 재현하고
무효한 RuntimeMaxSec 한 줄만 제거한
[검토용 unit 수정본](operations-verification/soc-continuous-tcp-trial.service)을 준비했다.
TimeoutStartSec90초·TimeoutStopSec5초와 나머지 격리/자원/포트 계약은 유지했다.
수정본은 같은 verify에서 경고 없이 통과했다. 설치 unit은 무단 변경하지 않았다.
Window detach/reattach 간 미관측 구간은 명시하며 Flow를 이어 붙이지 않는다.
Diagnostic의 300초/4096 등 제한을 삭제하거나 장시간 권한으로 해석하지 않는다.

### 탐색한 오류와 수정 상태

| 확인된 문제 | RCA·수정 | 상태 |
|---|---|---|
| API 설정 파일0644 | 인증 정보 파일의 불필요한 타 사용자 읽기 권한. 파일 내용은 유지하고0600으로 제한 | 수정·재확인 완료, Git에 키/파일 미포함 |
| Unix 소켓 회귀의 AF_UNIX path too long | 검증 harness의 긴 basetemp가 OS 소켓 경로 상한 초과. 짧은 private `/tmp` 경로로 실패 케이스만 재검증 | 양 환경 PASS, 제품 소켓/Assertion 변경 없음 |
| TCP oneshot RuntimeMaxSec 경고 | oneshot에 적용되지 않는 설정. 해당 한 줄 제거하고 유효한 TimeoutStart90초/Stop5초 유지 | 검토용 수정본 verify PASS, 실제 `/etc` 적용은 Root 승인 대기 |

이번 탐색·회귀에서 추가 제품 코드 실패는 확인되지 않았다. 기존240초 cap·exact 모델 Action·
Root private 백업 조회 거부는 정상 권한 경계다. 이들을 오류로 분류해 삭제하거나 자동 승인하지
않는다. 과거 Program1145 원인 UNKNOWN도 새로운 근거 없이 해결됐다고 바꾸지 않는다.

## 비권한 검증 결과

| 이번 검증 | Workspace | 독립 Git Export |
|---|---:|---:|
| Capture/Eligibility/모델 Action 차단/READY·R1/Worker·Stop·Cleanup/Queue·Quota·Audit/API 경계 집중 회귀 | 103 PASS | 103 PASS |
| 실제 Tk GUI Start·Stop·닫기·재연결·기존 Native 결과 표시 | 4 PASS | 4 PASS |
| 실제 PCAP 공식 CLI | ELIGIBLE, RF/LR 2, NORMAL Incident 1, Audit·읽기 전용 결과 검증 | 동일 |

관련 pytest 합계 **각107 PASS**와 별도 PCAP CLI 성공이다. RC 전체 관련323 PASS 및
가상5시간/5000-event 내구성은 기존 고정 로그를 재사용했고 재실행하지 않았다.
이번 다중 Window 검증은 72분 상당 합성 이벤트 시간/25개 seal·crash 재구성·Replay 거부로,
실제72분 Kernel 운용이 아니다. Auth/Packet Fixture 실제 모델과 API FAKE_HTTP 테스트도
실제 Native/API 시험과 구분한다. 실제 API는 아래 별도 시도만 해당한다.

첫 집중 회귀는 두 환경 모두 **102 PASS / 1 FAIL**이었다. 실패는 증거 디렉터리 밑의 긴
`--basetemp` 때문에 테스트 Unix socket bind가 `AF_UNIX path too long`으로 거부된 것이다.
제품 socket 경로나 보안 검증 문제가 아니다. 최초 로그를 보존하고 짧은 `/tmp/soc-ops-*`
경로에서 해당 테스트만 재실행해 양쪽 PASS했다. Assertion/품질 기준/실행 코드는 변경하지 않았다.

Ruff check / Ruff format check / Git diff check PASS. Source는 두 환경에서 동일하다.
Source·설치·Ledger 등의 해시는 종료 직전에도 대조한다. `verify.py`, `preflight.json`,
`workspace-tests.log`, `export-tests.log`, `*-unix-path-recheck.log`, `*-gui.log`,
`*-pcap-cli.log`와 immutable 결과/Audit를 새 증거 디렉터리에 보존한다.

## 실제 API — 보존된 Native Incident 조사

사용자의 추가 API 승인에 따라 기존 Provider Adapter·Planner·GovernedExecutor·Read-only Tool·
ThreatAssessor·Audit 저장소를 재사용했다. 제품 추론 경로를 Mock으로 대체하거나 과거 모델
Action 영수증을 재사용하지 않았다. 기존 Native RF/LR **결과를 읽기 전용으로 검증**했고
새 모델을 호출하지 않았다.

| 항목 | 이번 실제 결과 |
|---|---|
| Incident | `c37a311d-436d-57eb-a698-3166f1b7dd6b` |
| 원본 결과 SHA | `87e7d2d4fc00cb0abd63993abfec09a96b6ed1b4b7cfa431fd1dd229dbbeef33` |
| 원본 Capture Window | `9a0854fc5718e7cf826e2ecec42cb83789b694d4a4b46c8fd37068065c16d79e` |
| 적격 Flow | `9636b57bb24ae46b91f3627707d49a2676b2f950109ee2b39f0fcac6dd0f41cb` |
| Provider/model | 기존 `https://api.openai.com/v1` / `gpt-5-mini` |
| 호출 | 계획1 + 평가1 = **2회**, 재시도0, 신규 모델/Capture0 |
| 생성·실행 | Pydantic 계획 검증, 허용된 `read_local_source_report` 1회, 평가 완료 |
| 사용량 | prompt 2817 / completion 4198 tokens |
| 비용 추정 | `$0.00910025`, 공급자 청구서가 아닌 보수적 로컬 추정 |
| Audit | 새 private 저장소10건·API intent/response·hash binding 검증 PASS |
| 상태 | `COMPLETED_READ_ONLY`, 임의 Shell/Host 변경0 |
| 결과 SHA | `da8609edc3ede6561802aa78b411cbd7d7415b94163a4e8232d4c2e726ac03af` |

기존 호출 한도2회·timeout120초·최소 간격1초·사용자가 허용한 금액 상한 없음 조건을
유지했다. 가격은 [공식 gpt-5-mini 문서](https://developers.openai.com/api/docs/models/gpt-5-mini)의
표준 uncached 입력$0.25/출력$2.00 per million 기준으로 확인했다. 새로운 모델로 바꾸지 않았다.

외부 요청은 기존 allowlist projection으로 최소화했다. IP·계정·도메인·Source 내용·파일 경로는
전송하지 않고 Incident/Evidence ID·digest·모델 advisory만 사용한다. 원본 Window/Flow와
모델/Feature provenance는 로컬 원본 결과 SHA에 결합된다. LLM 가설을 관측 사실로 승격하지
않으며 모델 이상은 공격의 증명이 아니다. API key는 로그/Git/증거로 복사하지 않았다.
기존 선택된 `.env`가0644였으므로 파일 바이트를 변경하지 않고0600으로 제한했다.

새 조사 결과는 `retained-native-real-api/`의 **별도 조사 sidecar**다. 원본 GUI 보고서의
SCRIPTED 값을 바꾸지 않았으며 이번 GUI 테스트는 기존 verified Native 보고서를 표시한다.
새 sidecar의 GUI 자동 수입은 검증하지 않았다. 이를 새 Live Native→LLM→GUI 전체 성공으로
보고하지 않는다. 과거 Offline 실제 API Incident와도 별개다.

## 사용자 단일 검토용 장시간 시험 제안

아래는 **미승인 제안**이다. 실행 예약·정책 영수증이 아니며 자동으로 집행하지 않는다.
정확한 JSON은 같은 증거 디렉터리의 `operations-review-request.json`이다.
요청서 SHA: `ad3c7d7b96d9b9ac9a04d3041ae4a375ed54a3d4396636d6dbb1e858f30d133b`.
사용자가 SHA를 복사/입력할 필요는 없고 프로그램이 대조한다.

| 검토 항목 | 제안 Scope |
|---|---|
| 목적/시간 | 전용 Loopback의 **최대3600초(1시간)** 제한 운영 시험, Collector start 최대1회, 자동 재실행0 |
| Namespace/부착 | 기존 `net:[4026532232]`, lo/Ingress만. 내부 check PASS·기존 hook 소유권 충돌 없음 필요 |
| Root 변경 | 기존 실행 파일/Capability 그대로. fixed `trial-limit.conf`240→3600초 후보와 TCP oneshot의 무효 RuntimeMaxSec 한 줄 제거. 새 인간·위험 검토에 결합된 설치 계약 필요 |
| Collector 자원 | 현재128MiB/25%CPU/Tasks4/MEMLOCK8MiB/Stop10초 유지 |
| ordinary Runtime | UID1000, 512MiB/50%CPU/Tasks32, Queue32, heartbeat1초, shutdown10초, unit Stop35초 |
| 보관 | Runtime256MiB 관측 상한, Window512/seen100000, RootAudit64MiB, 시작 시 가용1GiB 이상. 원본 자동 삭제 없음 |
| 정상 트래픽 | 기존 고정 helper/unit의 **최대20번** 명시적 시작. 인증된 새 Window READY 후 Window당1번, 총 TCP40 연결/요청40/응답40 이하 |
| TCP 상세 | Listener127.0.0.1:18080, source18081/18082, 고정 `SOC-CONTINUOUS-PROBE/1\n` 요청과 `SOC-CONTINUOUS-OK/1\n` 응답. helper 시작2초 후 첫 연결, 첫 EOF35초 후 둘째 |
| 트래픽 중단 | helper 중첩/대체 포트/재시도 없음. 3560초 이후 새 helper 금지. 포트 충돌·READY 지연·helper 실패 시 후속 트래픽 중단 |
| 네트워크 영향 | Loopback만, DNS0/외부 연결0/Host Auth0/방화벽·사용자 서비스 변경0 |
| 모델 | RF/LR, VERIFIED Attestation·ELIGIBLE·Schema/Fingerprint 일치 후 **기존 exact job/output/implementation Action 승인**. Capture 권한으로 자동 발급 안 함 |
| LLM | 이번 보존 Incident API2회는 완료. **향후 새 Live Incident API 추가0회가 기본**. 별도 승인이 없으면 SCRIPTED |
| R1 | Program1145 UNKNOWN, 과거 전역 Cleanup UNVERIFIED/FAILED/false, 장시간 Kernel 미검증·capture gap·연구 모델 한계에 대한 새 Scope의 인간 판단 필요 |
| Stop/실패 | ordinary 명시적 Stop→owner-bound Root STOP/ACK→detach·최종 drain/seal→Audit→종료 코드/소유FD·Map·Link·socket·cgroup 비교. 실패 시 최초 오류 보존·자동 재실행 금지 |

후보 drop-in 내용은 `[Service]\nRuntimeMaxSec=3600s\n`이며 SHA는
`8482c57098b8f18adf95a1430df3070a7231bfc7d76243306b394975564e32f7`이다.
파일을 private 증거에만 만들었고 `/etc`에는 적용하지 않았다. 기존 파일의 백업·복원이
가능해야 한다. 상시 enable/재시작/패키지 설치·새 Root 실행 파일 설치는 제안에 없다.
TCP unit 수정 후보의 SHA는
`f60965a471430d81c77bac3c3fde48800da71e450f85b2f779f8ea1d89f9ef5e`이며,
현재 설치된 `d9c4cb88e3e0765ea2308bcd5838748080d83bd4ac1ac5a35a2def0d806074e8`와
구분한다. 두 고정 설정 파일만 승인된 설치 단계에서 교체할 수 있다.
Helper20번/총TCP40개는 **새 승인이 필요한 확대 범위**이며 과거2연결 영수증을 재사용하지 않는다.

원본 Packet payload/인증 로그 수집을 추가하지 않는다. 기존 Root transport는 metadata다.
일반 Runtime 저장 상한은 heartbeat 관측값이어서 검사 사이 쓰기 초과 가능성이 있다.
강제 디스크 quota·암호화·보존 만료 자동 삭제가 구현/활성화됐다고 보고하지 않는다.
원본 Audit/Queue tombstone/백업을 삭제하지 않는 보관 계획으로 별도 시험 디렉터리를 쓴다.

### 실행 전 남은 순서와 독립 승인

1. 위 시간·트래픽·Root fixed-file·Namespace·자원·R1 제안을 인간이 검토한다.
   새 승인 유효기간은 설치 계약과 일치해야 하며 과거 소비/만료된 권한을 재사용하지 않는다.
2. 승인 후 기존 설치/TTY 경로에서 사용자 Scope `yes`·직접 sudo 인증,
   최신 Ledger/실행 파일/Runtime/모델/Lease/소유 자원 재검증, 내부 check를 수행한다.
   그 전에는 서비스 시작/예약을 하지 않는다.
3. 새 설치 policy의 **실제 SHA**로 fresh ordinary Runtime 설정을 생성·검증한다.
   변경된 정책에 기존 input pin을 그대로 쓰지 않는다. 현재 Source 코드 무결성 pin을 유지한다.
4. Collector 인증 READY 후에만 승인된 helper를 진행한다. Heartbeat/Queue/Drop/Window/Audit를
   GUI와 대조하며 실패 시 중단한다. Kernel 장애 주입/자동 재시작은 제안하지 않았다.
5. 실제 봉인 job의 Session·Window·output·implementation이 생긴 뒤 기존 모델 Action 검토를
   진행한다. **현재 계약으로는 미래 미확정 Window의 모델 권한을 미리 자동 발급할 수 없다.**
   수집 Scope 일괄 승인이 모든 Window의 무인 AI 실행 권한이라는 약속을 하지 않는다.
6. 정상 Stop/Drain/모든 queue 상태·미처리/POISON 입력 보존·Audit·Cleanup을 독립 판정한다.
   Cleanup VERIFIED와 분석 대기 Queue 완전 처리는 별개다. 승인 대기 job이 있으면 임의
   drain 성공으로 바꾸지 않고 보존한다.

따라서 **지금은 “sudo만 입력하면 전체 운영 E2E 보장” 상태가 아니다.** Root 장시간/트래픽
승인과 새 설치 Binding이 필요하고, 모델은 봉인 이후 exact Action 단계가 남는다.
이 경계를 없애는 신규 승인 시스템이나 정책 우회는 구현하지 않았다.

## Ledger·예산·최종 판정

Legacy Ledger **81행**, 전체 SHA
`07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`.
체인/명시적 settlement 포함 미정산 Root0·Native0 확인.
Campaign Root12/Native4, Batch3 Root9/Native1을 유지했다. 사용량 환급/초기화는 없다.
Diagnostic OBSERVE_ONLY 기록은 Continuous 장시간 권한이 아니다.
이번 실제 API authorization/response는 새 private API Audit에만 기록했으며 Legacy Ledger는
수정하지 않았다. 실제 Continuous 시작은 별도 Root Audit/승인 증거로 계측한다.

기존 제한 시험의 Native20 / Window2 / ELIGIBLE1 / RF·LR2 / Incident1 / Cleanup VERIFIED,
마지막 Flow INCOMPLETE, 기존 과거 FAILED·UNKNOWN 이력을 보존했다.
이번 새 Native 수집량·Window·적격 후보·Native 모델 호출·Live Incident는 모두 **미수행**이다.
GUI 새 Native LIVE/실제 Kernel 장시간·실제 Kernel 장애·복구·현재 전역 Cleanup은 미검증이다.
DNS9는 학습 추출 계약 미완료로 계속 차단한다.

**RC 보존: RELEASE_CANDIDATE_READY. 비권한 사전 검증: PASS.
이번 실제 장시간 운영 시험: BLOCKED(별도 승인 필요).**
새 API 조사 subcomponent는 보존 Native Incident 기준 검증됐으며 OPERATIONS_VERIFIED로
승격할 근거는 아니다. 최종 보고서 Commit/Push 및 종료 해시는 같은 증거 디렉터리의
`completion.json`에 고정한다.
