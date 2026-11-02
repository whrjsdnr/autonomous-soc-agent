# Runtime Heartbeat / Storage Isolation

작성: 2026-11-02, Asia/Seoul. 기준 HEAD `43b2042`, 브랜치
`feat/one-command-runtime`. 이번 검증은 일반 사용자 Replay와 장애 주입이다.
Root 설치, Namespace 진입, TCX Capture, DNS 트래픽, Host 인증 로그 수집,
외부 API, Native Model Action, 운영 승인 발급·소비는 수행하지 않는다.

## 실제 실패와 RCA

보존된 1시간 시도는 전체 202.567초 / 검증된 순수 수집 193.593초에서
`RUNTIME_HEARTBEAT_STALE`로 중단됐다. Packet34, DNS3, Window2,
Attestation VERIFIED, ELIGIBLE4 / INCOMPLETE1, Drop0 / Source Gap0,
TCX·Helper·Root 소유 범위·Runtime Cleanup VERIFIED다. 이 결과는 1시간
운영 성공이 아니다. 과거 UNKNOWN·FAILED·false·UNVERIFIED를 변경하지 않는다.

Runtime 저장 작업 최대 지연 8.246초와 외부 관측 Heartbeat Age 8.454초가
기록됐다. 당시 `operation=counts`는 마지막 관측 작업이므로 최대 지연의
정확한 작업이라고 단정할 수 없다. 실제 fsync / SQLite lock / 파일 시스템 /
CPU quota / scheduler 중 정확한 지연 원인은 **UNKNOWN**이다.

코드에서 확인하고 비권한 재현한 결함은 상태 게시가 Queue counts와 SQLite
상태 갱신의 같은 직렬 저장 경로를 기다린다는 점이다. 이벤트 루프가 살아
있어도 8.3초 저장 지연으로 기존 외부 검사에 Stale 상태가 전달됐다.
관측 샘플 사이의 긴 간격을 Producer의 실제 연속 Heartbeat 간격으로
해석하지 않는다. Kernel Event 생산 중단을 입증한 증거도 없다.

## 최소 수정

- `continuous/service.py`: 별도 Control task가 캐시된 Queue/Auth 상태로
  원자적 관측 파일을 게시한다. 기존 5초 생존 계약을 유지하며 데이터용
  heartbeat 설정이 이 계약을 늘리지 않는다. 저장·Window 작업의 진행은
  별도로 계측하고 진행 중인 작업의 5초 지연은 `DEGRADED`로 표시한다.
  정상 무트래픽 대기는 정체로 승격하지 않는다. 여러 단계를 정상 완료하는
  긴 이벤트는 시작 이후의 총시간이 아니라 같은 관측 Task의 마지막 성공적인
  저장 단계와 다음 저장 단계의 실제 시작으로 진행 여부를 판단한다. 저장 순서
  대기와 획득 후 쓰기는 별도 단계이며 단일 I/O의 정체 검사는 유지한다.
  다른 Task의 counts 조회는 해당 관측의 진행 시각을 갱신하지 않는다.
  느리지만 아직 실패하지 않은 durable 쓰기를 새 fatal 오류로 취급하지 않는다.
  저장 완료 후 정상 상태로 복구한다. 실제 저장 예외·Queue overflow·Control 게시
  실패·승인된 전체 Deadline의 기존 종료 처리는 유지한다. 생존 lease를 늘리거나
  데이터를 먼저 ACK하지 않는다.
- `continuous/store.py`: 살아 있는 Heartbeat 관측만 fsync 없는 원자적
  교체로 게시한다. 이는 임시 상태 관측이며 durable commit 영수증이 아니다.
  Queue, Incident, Audit, SQLite transaction, 최종 상태의 기존 내구성 설정과
  검증을 유지한다. Start/승인 판정은 authoritative DB를 사용한다.
- DNS/Auth Audit, 인증 Journal claim/ack, 입력 읽기, 저장량 조회도 기존
  저장 Worker 경계로 옮긴다. 최대 저장 지연과 그 작업명을 함께 기록한다.
- `continuous/cli.py`, `process_identity.py`: monotonic lease와 PID/start ticks/
  boot ID/UID를 확인한다. 종료·PID 재사용을 RUNNING으로 표시하지 않는다.
  Stop은 정확한 일반 사용자 CLI 프로세스의 pidfd에만 전달하므로 SQLite
  lock을 기다리지 않는다. 신호 수신 Audit은 저장소가 다시 가능할 때 기록하며,
  신호 발신자를 인간 승인자로 추정하거나 실행 권한을 부여하지 않는다.
- `tcx_producer.py`: 수신 transport의 현재 generation에 STOP을 결합한다.
  transport ACK 수신과 순서대로 처리된 최종 Seal/ACK 검증을 분리한다.
  transport ACK만으로 `remote_cleanup=VERIFIED` 또는 모델 적격성을 부여하지 않는다.
  기존 Namespace·정책 SHA·generation·권한 검증과 실행 상한을 유지한다.
- 종료 중 중복 STOP, async 초기화 중 Stop 손실, 정상 종료의 Worker/DNS
  조기 종료 오판, Queue ACK 전에 결과 완료가 노출되는 경합을 수정했다.
  최초 오류와 후속 Cleanup 오류는 별도로 보존한다.
- 기존 GUI는 Control 생존, 저장 작업, Data Progress, 게시 오류를 표시한다.
  Native / Replay와 실제 API / SCRIPTED 구분을 유지한다.

전체 파일 시스템이나 OS scheduling이 멈추면 Python 프로세스가 Heartbeat나
STOP을 보장할 수 없다. 게시 실패·늦은 게시·미회수 작업은 성공으로 위장하지
않으며 외부 lease와 미검증 Cleanup 판정을 유지한다.

## 검증 범위

실제 10초 저장 지연, SQLite EXCLUSIVE lock, Busy timeout, Audit/Seal 지연,
게시 writer 실패·지연, monotonic/wall clock, PID 재사용·실제 프로세스 종료,
제한된 일반 사용자 CPU 부하, 무트래픽/실제 Data Progress 정체,
STOP/ACK 지연·누락, 최종 Seal 처리 순서, 첫 오류 보존, GUI 재연결을 확인한다.
CPU 부하는 systemd의 실제 Native CPU quota 시험과 구분한다.

회귀 중 발견한 테스트 환경 문제도 기록한다. 긴 증거 디렉터리의 Unix socket
경로가 AF_UNIX 길이 제한을 초과해 격리 `/tmp` basetemp로 변경했다. 새 생명주기
테스트에 섞인 잘못된 JSONL 입력은 유효한 FIXTURE excluded 관측으로 교체했다.
기존 테스트를 삭제하거나 Assertion·보안 조건을 완화하지 않았다. 수정 전 실패와
중단된 검증 로그는 성공 결과와 별도로 보존한다.

첫 20분 시도는 약4분에서 `CONTINUOUS_DATA_PROGRESS_STALLED`로 종료됐다.
개별 저장 최대4.974초, 이벤트 전체 처리7.290초였고 여러 단계가 완료됐는데
이벤트 총시간을 정체로 판단하는 결함을 발견했다. Heartbeat 게시 오류는 없고
Cleanup은 VERIFIED였다. 이 실행을 20분 성공으로 합산하지 않는다. 같은 Task의
실제 진행 시각을 반영한 수정과 6초 이상 정상 다단계 진행 테스트를 추가했다.

다음 시도도 마지막 정상 샘플826초 뒤 Data Progress 판정으로 중단됐다.
Heartbeat 게시 오류와 Drop은 없고 Runtime Cleanup VERIFIED다. 최종 관측에서
이벤트 전체7.883초, 누적 개별 저장 최대5.394초를 확인했다. 당시 정체 판정 순간의
상세 저장 Snapshot이 없으므로 정확한 I/O 지연 원인은 UNKNOWN이다. 별도 재현에서는
저장 대기3초 + 획득 후 쓰기3초를 정상 수행해도, 두 단계를 합산해 중단하는 측정
결함을 확인했다. 단계 시작 시각을 분리했고 최초 정체 순간의 Snapshot도 최종
durable Audit에 남기도록 했다. 이 두 실패 실행을 최종20분 성공에 합산하지 않는다.

그다음 시도는 마지막 정상 샘플351초 이후 중단됐다. 새 진단 Snapshot에서
`retain` 단일 작업이 관측 시점5.580초, 최종6.672초 걸린 것을 확인했다.
Control 게시 오류는 없고 Cleanup VERIFIED였다. 이는 저장 작업이 실제로 느린
사례이며, SQLite lock / fsync / 호스트 scheduling 중 세부 지연 원인은 UNKNOWN이다.
추가한 watchdog이 지연 관측을 곧바로 전체 STOP에 결합한 것은 요구사항보다
과도했다. 이 새 동작을 수정해 지연은 DEGRADED로 관측하고 실제 I/O 실패와
구분한다. 실제 Runtime에6.2초 `retain` 지연을 주입해 DEGRADED → RUNNING 복구,
Collector 재시작0·Source Gap0·정상 Stop/Cleanup을 검증했다.
기존 테스트의 보안 Assertion은 유지했으며, 이번에 추가한 테스트의 지연/오류
분류를 명시적 복구·독립 STOP·실제 실패 중단 검증으로 바로잡았다.

Workspace 회귀 중 Source Guard의 `SOURCE_CHANGED_DURING_BUILD`도 발생했다.
분석 중 Source를 수정한 시각과 겹쳤으며 Guard를 완화하지 않고 최종 Source를
고정해 검증한다. 고정된 독립 Export의 중간 수정본 회귀는1,819 PASS였지만,
최종 수정본의 검증 결과를 아래 절에 따로 기록한다.

## 최종 결과

**판정: RELIABILITY_INTEGRATED / 20분 비권한 통합 PASS. 실제 Native 재시험은 별도다.**

| 검증 | 결과 |
|---|---|
| 전체 관련 Workspace / 독립 Export (복구형 분류 직전) | 각각1,820 PASS, Source 고정 |
| 마지막 복구형 분류 변경의 영향 경로 Workspace / 독립 Export | 각각948 PASS, 동일 Source SHA / 검증 중 변경0 |
| 집중 저장·Control·STOP·Recovery | 43 PASS |
| 실제 Tk 생명주기·세 도메인 표시 | 별도4 PASS; DNS/Auth는 FIXTURE/저장 증거 |
| Ruff / Format / Diff | PASS /1,544 files / PASS |
| Native6 / legacy compiler / guarded Supervisor2개 wrapper | Workspace2회 + Export1회 SHA 일치, 실행·활성화0 |
| Wheel | 세 빌드 SHA 일치 |

마지막 수정은 느린 저장의 DEGRADED/복구 분류다. 동일한 보호 Source의 Native 기반
회귀는 재사용했고, Runtime·Queue·Window·SOCRuntime·LLM·GUI·CLI 및 Source Guard /
Controller 진단을 영향 경로948건으로 양쪽에서 재검증했다. 이를 최종 수정 후 전체
1,820건을 다시 실행했다고 보고하지 않는다. protected Policy/Approval/Native/ebpf_tc/
DB/Model Admission Source와 기존 Root health 함수4개는 불변이다.

- Source672; Backend Code Identity:
  `808479ba502afdc04418b1c0b849ac7a39707f168f9bca50eec8ea7186fffe33`.
- 최종 Wheel SHA:
  `e9de710dc18fed330f0dda4baca6a9786520cb02906f93085d3449e4aaf505e0`.
- 최초 기준 HEAD `43b2042`; 최종 코드 Commit은 `c6405d7`이다.

### 실제 경과 시간20분 통합

`soc_agent.cli`의 실제 setup → doctor → start → status → gui → stop 경로,
생산용 `ContinuousRuntime`, 실제 저장 PCAP, 실제 RF/LR Artifact,
SCRIPTED 조사·평가, 실제 Tk를 사용했다. Native 권한 경계에만 모의 Unix
Control 채널을 사용했다. Kernel/Root/실제DNS/HostAuth/API/Native Model Action은0이다.

- **1,200.132397초** 연속 시험. 가상 이벤트 시간으로20분을 대신하지 않았다.
- 입력1,035건 중 PCAP packet619 / excluded416. Native event0, DNS0, Auth0.
- Flow/job207, ELIGIBLE206 / 종료 INCOMPLETE1. INCOMPLETE를 추론하지 않았다.
- **RF/LR Prediction406 / Incident203**, 모델 오류0, Source Gap0, Drop0, 중복0,
  Collector restart0. 정상 분류를 포함한 Incident 객체 수이며203개 공격 탐지라는 뜻이 아니다.
- 모델 Queue DONE203 / PENDING4 / CLAIMED0. 미처리4개를 보존했다.
  전체 Queue를 완전히 비웠다고 보고하지 않는다.
- SCRIPTED Orchestration DONE202 / PENDING1: 마지막 조사 checkpoint는 보존했다.
  이번 Session의 조사 결과이며, 과거 실제 API 결과와 혼합하지 않았다.
- GUI 정상 종료·재연결3회, 별도 실제 `soc-agent gui` CLI 실행/종료 후 같은 Backend
  PID 유지. 일반 창 닫기는 실제 Tk로, 별도 CLI GUI 종료는 소유 GUI PID 신호로 검증했다.
- Heartbeat observer1,189회 게시 관측, 관측 간격 최대 **2.092초** / Age 최대2.095초.
  관측되지 않은 wire 간격이나 실제 Kernel heartbeat 검증으로 확대하지 않는다.
- Control writer 최대1.090초, 저장 작업 최대 **5.268초**. 1초 이하 주기 상태 관측에서
  DEGRADED 전환0 / fatal 오류0. 저장 지연 자체가 없었다고 주장하지 않는다.
- Stop 후 **STOPPED / Runtime Cleanup VERIFIED**, Source/model 소유 자식 종료,
  SQLite408개 `integrity_check=ok`, Runtime Audit1,423행과 세부 digest 검증,
  Queue207행 payload/digest 검증. Source672 byte SHA 불변.
- Replay이므로 TCX ACK / Helper / Root / Global Kernel Cleanup은 해당 시험의 검증 대상이
  아니다. 과거 실제 Native의 Cleanup 판정을 이 결과로 갱신하지 않는다.
- 기존 증거·설치481개 SHA 및 Ledger81행
  `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` 불변.

증거: `soak20-recovery/verified-result.json`, `heartbeat-observer-result.json`,
`replay-soak-final.json`, `public-gui-cli-result.json`, 실제 GUI screenshot3개,
`workspace-recovery-final-result.json`, `export-recovery-final-result.json`,
`recovery-build/reproducible-builds.json`, `security-boundaries-recheck.json`.

증거 위치:
`.git/runtime-storage-isolation-20261102T013653Z/`.

## 다음 실환경 시험

수정된 Source / Wheel / Artifact·Root Manifest·새 Session·Release·Namespace·
최신 Ledger Binding을 고정한 짧은 Native 시험 승인이 필요하다. 기존에 소비된
600초 또는 1시간 영수증은 재사용하지 않는다. Namespace `net:[4026532232]`,
`lo / Ingress`, 정확한 Root 변경 목록, TCP/DNS 공급원·횟수·포트·페이로드,
전체 Deadline·자원·저장량, R1 위험 수용, STOP ACK·Helper CLOSED·Root/Runtime
Cleanup을 별도로 검증한 후 사용자 Scope 확인과 직접 sudo 인증을 거친다.
RF/LR Native Model Action과 외부 API는 별도 승인으로 유지한다.

이번 Replay 성공은 실제 Native 재시험이나 1시간 운영 성공을 대신하지 않는다.


## Git / 후속 실제 시험

운영 코드·테스트 Commit: `c6405d7`. 검증된 코드·테스트와 이 보고서만 선별 Commit/Push한다. 설치본·Rollback·Ledger·
Native 성공/실패 증거는 Commit 대상이 아니다.

사용자는 Replay 통과 후 실제 Native20분 통합시험을 요청했다. 기존 고정 Launcher를
새 Source/Session에 재결합해 순수 수집1,200초 목표·전체1,800초·Root8경로 중4개
구성 변경·TCP8연결/DNS UDP2·TCP1·Queue32의 검토 패키지를 준비한다. Window180초는
유지하므로 완전한 다음 Window까지 기다리면 실제 수집은 약21분이 될 수 있다.
Root Namespace/Artifact/R1/트래픽과 직접 Scope yes·sudo 인증은 실제 실행 전 필수다.
봉인된 ELIGIBLE 작업의 RF/LR Action은 별도 승인, 실제 API/DNS9/HostAuth는 제외한다.
이 문서의20분 PASS는 해당 Native 시험을 이미 수행했다는 뜻이 아니다.

## 후속 실제 Native 단일 시험 결과

2026-11-02 새 Binding의 명시적 승인·사용자 TTY Scope yes·직접 sudo 인증 후
Native20분 시험1회를 실행했다. 전체66.986초에 DNS
`HELPER_HEARTBEAT_OR_PROCESS_STALE`로 중단됐다. Runtime12건·격리2건의 Native
이벤트와 완료 DNS Transaction2건을 확인했지만 Runtime Window0개, 목표시간 미달이다.
TCX·Helper·기록된 Root 소유 Cleanup은 VERIFIED, **Runtime Cleanup은 UNVERIFIED**다.
자동 재실행하지 않았다. 기존 Replay20분 PASS와948건 회귀 결과는 보존하되
실제 Native 안정성 검증 완료로 해석하지 않는다.

상세: [Native20분 실환경 시험 결과](native20-storage-recovery-result.md).
최종 실환경 판정은 PARTIALLY_VERIFIED이며 1시간 시험 진행 조건을 충족하지 못했다.
