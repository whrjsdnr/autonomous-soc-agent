# Control Identity 8초 Startup 경계 RCA

## 범위와 최초 증거

기준 운영 코드 a481b98, 기준 보고 b6692d4의 Export 전체 회귀는 901 PASS / 1 FAIL이었다.
실패는 `tests/unit/continuous/test_storage_control_isolation.py::test_exact_cli_stop_bypasses_real_locked_sqlite`,
358행의 `AssertionError: ordinary CLI did not publish control identity`다.
CLI child는 `python -m soc_agent.cli continuous run <fixture-runtime>`으로 시작한다.
Observer는 Spawn 이후 기존 monotonic 8초 동안 `observation.json.snapshot.control`을 기다린다.
실패는 테스트가 SQLite `BEGIN EXCLUSIVE`를 실행하는 360행 **이전**이다.
따라서 이 실패를 잠긴 DB에서 STOP 자체가 실패했다는 증거로 해석하지 않는다.

원본 로그는 `.git/authentication-if-final-20261104T000307Z/final-validation/export-quiet-disk-tests.log`에
그대로 남긴다. 당시 child의 단계별 timestamp, CPU throttling, fsync trace는 없다.
**그 실패 회차가 정확히 왜 8초를 넘겼는지는 UNKNOWN**이다. 현재 재현에서 확인한 구조적
의존성과 과거 단일 실패의 직접 원인을 구분한다.

## 확인한 시작 의존성

수정 전 Continuous CLI의 import는 `realtime.models → external_runtime` 및
`ingestion.__init__ → store → governance/assessment/fusion`을 통해 Application과 ML을
Controller에 미리 로드했다. Authentication/Network package의 eager public exports와
AnalysisService의 OfflineWorkflow import도 동일 경로를 확장했다.
Control만 시작하는 CLI가 NumPy·sklearn·Application을 불필요하게 기다렸다.

`ContinuousRuntime.run()`은 Control task를 Investigation DB 초기화, Queue 복구,
시작 Audit/Ingress 재구축 **뒤에** 생성했다. Investigation 초기화를 Event로 막은
비권한 테스트에서 기존 코드는 Control observation을 만들지 못했다. 수정본은 같은
지연 중에도 Identity를 게시하고 STOP을 받는다. 이는 확인된 구조적 결함의 재현이며,
과거 Native TCX 송신 공백의 근본 원인이 밝혀졌다는 의미는 아니다.

## 최소 수정

- `FeatureRow`를 기존 저수준 `security_ai.external.models`에 두고 과거 import 위치는
  동일 class의 compatibility alias로 유지한다. 필드·Schema·Fingerprint는 바꾸지 않는다.
- ingestion/authentication/network public exports는 기존 package 방식의 lazy resolution을
  재사용한다. Worker가 실제로 요구하는 시점에는 기존 구현을 그대로 import한다.
- AnalysisService의 결과 검증과 Store의 Audit/DDL은 기존 구현에 위임한다.
  Audit import는 SQLite write transaction **밖**에서 끝내어 import가 write lock을 늘리지 않는다.
- UID·Source authority·단일 Runtime lock 검증 후 기존 Control task를 먼저 시작한다.
  초기화 단계는 `STARTING`이며 수집 READY 또는 RUNNING으로 표시하지 않는다.
  DB flags/Investigation/Queue/Ingress 초기화는 기존 storage 경계를 통해 수행한다.
- 뒤늦게 만들어지는 동일 DNS Producer의 상태 observer를 Control에 연결한다.
  별도 Producer, 재연결, 추가 권한은 만들지 않는다.
- 초기화 중 STOP은 새로운 Collector 시작을 막고, 소유 초기화 thread의 종료를 기다린다.
  Control 게시 실패는 조용한 STOP으로 바꾸지 않고 최초 예외로 전파한다.
- STARTING도 중복 Start/Release 변경 차단 및 기존 PID·Start identity/5초 lease 검증 대상이다.
  Data Progress 정체는 기존 DEGRADED 판단을 유지한다.

기존 8초 Assertion, Heartbeat 2초/5초 계약, Model Admission, API 비용·권한 계약,
Root/Namespace/Source 검증을 변경하지 않았다. 기존 테스트의 Assertion을 수정하지 않았다.

## Monotonic 측정 방법

소유 fixture child에만 out-of-tree `sitecustomize` profile을 주입했다. Parent Spawn,
child interpreter 준비, module import 종료, Runtime init, SQLite open, identity 생성,
Control publication 완료, Observer 수신을 같은 boot의 `time.monotonic()`으로 연결한다.
Observer polling 자체와 profile overhead가 포함되므로 수치를 일반 운영 SLA로 확대하지 않는다.
`INTERPRETER_READY`는 sitecustomize 진입 시각이며 CPython의 내부 초기화 전체를
직접 계측했다는 의미는 아니다. SQLite connect/commit wrapper 시간과 fsync 단독 시간도 다르다.

수정 전 비교 회차도 네 환경 모두 통과했다. 아래는 중간 수정본에서 마지막 STARTING guard
보완 전 얻은 비교값이며, 최종 고정 소스 회귀 결과는 별도 증거 JSON을 따른다.

| 환경 | 수정 전 Spawn→Observer | 수정 후 Spawn→Observer |
|---|---:|---:|
| Workspace / 일반 디스크 | 4.5192초 | 0.6040초 |
| Export / 일반 디스크 | 3.5717초 | 0.7565초 |
| Workspace / tmpfs | 3.3246초 | 0.6556초 |
| Export / tmpfs | 3.8305초 | 0.6540초 |

일반 디스크 Workspace에서 module import 종료는 4.1853→0.4131초였다.
단순 timeout 확장이 아니라 Control에 필요하지 않은 의존성을 제거한 결과다.
파일 cache와 다른 프로세스의 부하는 통제하지 않았으므로 전후 차이 전체를 특정 import의
순수 CPU 비용으로 환산하지 않는다. 승인·설정 검증에 필요한 초기 DB 읽기까지 우회해
어떤 디스크 정지에서도 8초를 보장한다는 설계가 아니다. 검증 불가 시에는 계속 차단한다.
최종 계측에는 self CPU time/context switch/major fault/self I/O와 공유 cgroup cpu.stat도
기록한다. 공유 cgroup counter를 해당 child만의 throttling으로 해석하지 않는다.
과거 실패 시점의 CPU·Disk·scheduler·lock 인과관계는 복원할 자료가 없어 UNKNOWN이다.

## 수정 과정에서 발견한 회귀

첫 전체 회귀는 906 PASS / 2 FAIL이었다. 로그를 intermediate-regression에 보존했다.
하나는 기존 DNS silence/cleanup의 6초 테스트 경계 실패다. 이것만으로 Timeout 계약이나
DNS 상태 판단을 바꾸지 않았다. 다른 하나는 초기 Control writer 오류가 발생한 뒤
startup STOP 분기가 먼저 반환하여 동일 오류가 Cleanup 후속 오류로만 기록되는 경합이었다.
Control task 결과를 초기화 STOP 분기에서 확인해 최초 오류로 보존했다. 이 Assertion을
완화하지 않고 해당 테스트와 기존 8초 테스트를 포함한 집중 10건이 통과했다.
초기 lazy Audit import를 transaction 안에 둔 중간 수정도 locked-SQLite 테스트에 실패했으며,
import를 transaction 밖으로 옮겨 해결했다. 실패 로그는 삭제하지 않는다.

## 검증 범위와 안전 경계

Workspace/독립 Export의 일반 디스크·tmpfs 회귀는 같은 Source pin을 전후 확인한다.
GUI 승인·Authentication IF Admission·LLM Mock·SOCRuntime·Queue/Checkpoint·STOP/Cleanup을
기존 운영 entry point와 fixture에서 검증한다. 실제 모델/외부 API 호출은 guard로 차단한다.
실제 추론을 실행하는 세 legacy test 파일은 이번 실행 금지 범위 때문에 제외하고
순수 resource contract 항목만 별도로 실행한다. 이를 전체 저장소 무제한 테스트라고 부르지 않는다.
Native/Supervisor 빌드는 compile-only이며 BPF load/capture를 수행하지 않는다.

실제 Host Journal, Root 설치·sudo, TCX Capture, DNS 트래픽, RF/LR·IF Action,
외부 API, 실행 예약, 영수증 발급/소비를 수행하지 않는다.
과거 Cleanup UNKNOWN/UNVERIFIED를 소급 변경하지 않는다.

최종 수치·새 Binding·검토 명령·Commit은 검증 완료 후 아래 결과 절과 portable evidence에 기록한다.


## 최종 고정 소스 검증 결과

Code Commit `b7505cabd08b0a431652796ee087c81f00643475` / Tree
`29d8182546859e97d49db1347bb4355e358d4dec`로 검증 소스를 고정했다.
Workspace·독립 Export·후보 Export·별도 frozen worktree의 Source 682개 SHA가 모두 같다.
회귀 중 Source 변경은 없었다. 새 테스트 7개는 기존 Assertion을 수정하지 않고 추가했다.

| 구분 | 일반 디스크 | tmpfs |
|---|---|---|
| Workspace 전체 관련 회귀 | 908 PASS / 1 FAIL | 907 PASS / 2 FAIL |
| Export 전체 관련 회귀 | 909 PASS | 909 PASS |
| Workspace Authentication·GUI·IF/API 승인 집중 | 109 PASS / 1 FAIL | 110 PASS |
| Export Authentication·GUI·IF/API 승인 집중 | 107 PASS / 3 FAIL | 109 PASS / 1 FAIL |

전체 관련 회귀의 기존 8초 테스트와 새 Startup 테스트는 네 환경 모두 통과했다.
별도 집중 10건도 통과했다. 시험별 횟수를 합쳐 고유 테스트 수 또는 Live 성공으로 표시하지 않는다.

최종 Source에 추가한 계측 실행도 네 환경에서 기존 8초 Assertion을 통과했다.
각 단계는 Spawn을 0으로 한 monotonic 초다.

| 환경 | Interpreter | Import 완료 | Runtime init | SQLite open | Identity 생성 | 게시 완료 | Observer |
|---|---:|---:|---:|---:|---:|---:|---:|
| stable-workspace-disk | 0.0322 | 0.7612 | 0.8710 | 0.8715 | 1.8714 | 1.8745 | 1.9114 |
| stable-export-disk | 0.0204 | 0.5538 | 0.6688 | 0.6692 | 0.7974 | 0.8061 | 0.8099 |
| stable-workspace-tmpfs | 0.0185 | 0.4211 | 0.5431 | 0.5436 | 0.6034 | 0.6208 | 0.6549 |
| stable-export-tmpfs | 0.0309 | 0.4996 | 0.6099 | 0.6105 | 0.6908 | 0.6975 | 0.7055 |

현재 계측 프로세스는 `/init.scope`이며 공유 cpu.stat의 nr_periods/nr_throttled는 0이었다.
Native Root 서비스의 25% quota 안에서 시험했다는 의미가 아니다. 해당 과거 실패의
CPU throttling 원인과 현재 startup 성능을 동일한 관측 구간인 것처럼 비교하지 않는다.
추가로 회귀 도중 시스템 pressure 표본에서 CPU·I/O·메모리 대기가 함께 관측됐다.
이것은 공유 환경의 표본이며, 실패 순간의 syscall/스케줄링 trace 또는 인과관계의 증거는 아니다.

### 남은 실패와 UNKNOWN

1. 일반 디스크 Workspace `test_ten_second_write_does_not_block_heartbeat_or_stop`:
   관측 Sequence 18개/기대20개. 마지막 Control sequence28, Data Progress DEGRADED,
   게시 최대1.1233초, 게시 오류 없음. 해당 실행의 표본 수 Assertion은 실패로 유지한다.
   디스크/Thread scheduling 중 지연 원인은 UNKNOWN이다.
2. tmpfs Workspace `test_closed_without_process_exit_remains_unverified_at_shared_deadline`:
   5.5초 테스트 대기 경계 Timeout. Cleanup을 VERIFIED로 변경하지 않는다.
3. tmpfs Workspace `test_dns_status_reader_lock_does_not_block_control_or_stop`:
   status read thread 호출2회/기대1회. STOP·Control Assertion 이후 read coalescing
   기대가 실패했다. 요청·완료 시각/lock 대기 자료가 부족해 원인은 UNKNOWN이다.
   final Cleanup의 최신 status 읽기를 임의로 생략하여 통과시키지 않았다.
4. Authentication 집중 일반 디스크 Workspace의 managed lifecycle, Export의
   `changed_input`·composed E2E·SSH parity, tmpfs Export의 `rejected` 시나리오:
   fixture child READY Timeout 또는 5초 STOP 대기 후 Cleanup UNVERIFIED다.
   저장한 Workspace 실패에서는 child returncode -9/forced=true/STOP ACK=false,
   수집 Queue DONE3·drained=true이며 조사 RUNNING1/PENDING1을 보존했다.
   IF 승인 경계를 뚫고 실제 추론한 실패가 아니다. 일부는 fixture 입력 준비에서 실패해
   본래 IF Assertion에 도달하지 못했다. 직접 hang 원인은 UNKNOWN이다.

이 결과를 성공 회차로 덮어쓰거나 같은 실패를 무한 재시도하지 않았다.
변경하지 않은 Authentication/DNS 경로의 실패를 이번 Commit의 회귀라고 단정할 근거도 없다.
추가 독립 계측이 필요한 항목과 확인된 Startup 설계 결함 수정을 구분한다.

### 빌드·정적 검사

Native/BPF/Provider·legacy Native·Supervisor·Wheel을 Workspace 두 번과 Export 한 번
compile-only로 재현했다. 세 회차의 각 Artifact SHA가 모두 일치했다.
Export 빌드는 실제로 Export의 build module을 import했음을 확인했다.

- Wheel SHA `1241ef4b97ee3e59740a33eda795f1c71ecc60cc60e9d6dfb38a255a1f02a043`.
- Ruff 전체 Check PASS, 전체 Format Check 1621개 PASS, Git Diff Check PASS.
- 모든 no-live guard의 violations는 빈 목록이다. 실제 Native/Host/모델/API 호출은0이다.
- 사용자 변경164개, 과거 증거797개, Root8 SHA/inode/mtime, Ledger81행/SHA 보존.
- 기존 manager `4e4fb2c90c3a9467-57f8c396184bc1f8`과 설치·Rollback은 유지했다.

[전체 검증 JSON](evidence/control-startup-20261104/verification.json),
[원본 8초 실패 사본](evidence/control-startup-20261104/historical-eight-second-failure.log),
[단계별 timestamp·CPU/I/O](evidence/control-startup-20261104/startup-timelines.json),
[빌드 증거](evidence/control-startup-20261104/reproducible-builds.json),
[보존 검사](evidence/control-startup-20261104/preservation.json)를 제공한다.
원본 `.git` 증거와 현재 실패 fixture의 Cleanup 기록도 그대로 보존한다.

## 새 Binding과 실행 준비 판정

- **STARTUP_STABILITY_VERIFIED**: 이번 비권한 네 환경의 기존8초 경계와 초기화 지연·STOP·
  게시 실패·STARTING stale/중복 차단 검증 범위에 한정한다. 모든 부하에서의 시간 보장은 아니다.
- **PARTIALLY_READY**: 전체 회귀/Authentication 시간 경계 실패가 남아 있어 FULL_E2E_READY를
  선언하지 않는다. 실제 Full Live E2E는 미실행이며 현재 차단한다.
- 실제 장시간 Native·Host IF·LLM Assessment·전역 Kernel Cleanup의 과거 판정은 바꾸지 않는다.

수정으로 Source/Wheel Binding이 바뀌어 새 검토 후보를 한 번 준비했다. 새 후보는
정책 활성화·설치·권한 발급·예약이 아니다. 모든 실제 실행 승인은 PENDING이다.

Source canonical SHA `82c97502caef2b6a73f31dfbd8265e4d41278f9f490cda15e9d9ab160e033ec0`. Root Manifest SHA `db4a73fe7e4e313bf5b8a4c3edb506e86e25befcb1640de963d65a0c02e29552`.

Runtime Session `b26080ac-9cf3-4114-959f-f0c40b91271e`. Namespace `net:[4026532232]` / `lo / Ingress`.

Root8 중 교체 제안3개는 continuous-installation.json, soc-operations-runtime.service,
soc-continuous-dns.service이고 나머지5개는 검증 전용이다. 실제 변경은0이다.
전체600초/수집360초 목표, Host420초, TCP4연결·DNS UDP2/TCP1, Queue32,
기존 CPU·메모리·Storage 상한을 유지한다. RF/LR16회·IF1회는 실제 봉인 적격 입력별
GUI 결정, API Plan/Assessment 합계2회/$0.05/20초/4096토큰/재시도0을 제안한다.
실제 Host 이벤트가 없거나 완결 Window가 아니면 IF를 실행하지 않는다.

기존 정책 만료는 연장하지 않았다. 새 상위 만료 제안은 2026-11-05 09:09:35 KST이며
입장 최소75분을 유지한다. 이 제안 역시 인간 승인 전에는 활성화하지 않는다.
이전 승인·소비 영수증·6분/20분 Session을 재사용하지 않는다.

[통합 검토 설명](Control_Identity_Startup_Full_E2E_Review.md)과
[정확한 고정 Binding·Root8 전문](evidence/control-startup-20261104/approval-package-final.md)을
함께 검토한다. 이전 미검증 Cleanup/잔류 소유권, 새 상위 정책, Release Update,
Root/Native/DNS/R1, Host 읽기, RF/LR, IF, 실제 API를 독립적으로 확인해야 한다.
API Provider·모델·가격·선택 env-file의 유효성은 실행 직전 별도 검증한다.
Doctor의 provider 환경 configured=false 및 기본 SCRIPTED는 실제 API 성공이 아니다.

다음 명령은 새 고정 소스의 **비권한 진단**을 선택한다. SHA/UUID 입력은 필요 없다.

```bash
cd /home/geonug/kdt-linux/autonomous-soc-agent
source /home/geonug/kdt-linux/autonomous-soc-agent/.git/control-startup-rca-20261104T012138Z/use-review-profile.sh
soc-agent doctor
soc-agent start --preview
soc-agent status
```

Doctor exit0/PREFLIGHT_ONLY_NO_INFERENCE. Preview exit1/
AUTHENTICATION_EXACT_HUMAN_APPROVAL_REQUIRED, root_executed=false,
capture_started=false, reservations_created=false다. 설치 대상 변경 오류는 재현되지 않았다.
Wrapper는 새 operator home과 frozen export/src를 선택하며 기본 설치 manager를 바꾸지 않는다.
실제 `soc-agent start --gui`와 `soc-agent stop`은 남은 회귀·새 승인·사용자 Scope/sudo 및
작업별 GUI 승인 조건을 통과한 다음에만 사용한다. 이번 작업에서는 실행하지 않았다.

Git 운영 코드는 b7505ca로 분리 Commit했다. 문서·증거는 후속 별도 Commit으로 Push한다.
원본 주 Worktree의 사용자 변경과 기존 미추적3개는 stage하지 않는다.
