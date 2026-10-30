# Final Runtime Reliability Integration

작성: 2026-10-30, Asia/Seoul. 저장소 `soc-one-command-runtime`, 브랜치 `feat/one-command-runtime`.

**판정: RELIABILITY_INTEGRATED — 운영 코드 수정·비권한 검증 완료.**
실제 Native 1시간 운영과 실제 LLM Assessment는 여전히 미검증이다. 이번 작업의 실제
Root 설치·Namespace 진입·TCX Capture·DNS 트래픽·Host 인증 로그 수집·외부 API 호출·
Native Model Action·운영 승인 발급/소비는 모두 0이다.

## 1. 기준선과 보존

시작 HEAD `ff03776`, 이전 수정 `970c43a`. 작업 디렉터리는 시작 시 깨끗했다.
최종 코드 Commit은 `568e759542bc396cc8306dea2cc0e01c8936b591`, Tree는
`948ac1052bc5dd386bd664ece389d5d2ff48419e`다. 보고서 Commit은 코드 변경을 포함하지 않는다.

기존 실제 시험은 활성 수집 1,080.335초, Packet134 + 종료 중 격리10, DNS3,
정상 Window6, ELIGIBLE9, Prediction8, Incident2, 조사 Task5다. 실제 LLM Plan 성공과
Assessment20초 Timeout, 총비용 UNKNOWN을 보존한다. 이를 이번 Replay 결과와 합산하지 않는다.

- 기존 증거 **2,554개 파일 SHA 불변**. 성공·실패·소비된 승인·이전 보고서를 덮어쓰지 않았다.
- 설치된 Root **8경로 SHA 불변**. 기존 백업·Rollback을 변경하지 않았다.
- Ledger **81행**, SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` 불변.
- Target nsfs inode **4026532232** 유지. Host와 Target을 구분해 메타데이터만 확인했다.
- Program1145 원인 UNKNOWN, 과거 Heartbeat 원인 UNKNOWN, 과거 Runtime/Global Cleanup
  UNVERIFIED, FAILED/false를 유지한다. 새 Kernel 잔류 자원 검사를 수행하지 않았다.

검증 증거는 공유 Git 디렉터리의 다음 위치에 별도로 보존했다.
`.git/overnight-reliability-20261030T120835Z/`

## 2. 최초 Native Timeout RCA

기존 시험의 최초 오류는 `CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT`이다.
11:16:24.126639 UTC에 수신 대기 약5.001초로 실패했고, 마지막 control 수신은
11:16:19.125606 UTC였다. Root heartbeat 간격 최대6.253초를 확인했다.
같은 Producer PID/start identity, 연결된 IPC, receiver queue0/drop0이었다.
마지막 데이터 이벤트는 약145초 전이었으므로 데이터 무트래픽과 control 메시지 공백을 구분한다.
Root의 `COLLECTOR_EARLY_EXIT`는 Runtime STOP 이후 관측된 후속 오류다.

| 원인 후보 | 판정 |
|---|---|
| 단순 무트래픽을 packet timeout으로 판단 | 이번 최초 오류의 설명으로 불충분; control 공백이 실제 존재 |
| Producer PID 교체 / receiver queue 포화 | 당시 기록에서 미관측 |
| 정책/실행 파일 검증·lease 갱신·Kernel poll과 heartbeat의 결합 | 운영 코드에서 확인, 분리 구현 완료 |
| Runtime 상태 게시 인자 평가 중 동기 Queue/SQLite 조회 | 운영 코드에서 확인, 비권한 지연 재현·수정 |
| 조사 Checkpoint/SQLite 작업과 Collector의 같은 asyncio loop 사용 | 운영 코드에서 확인, 전용 Worker loop로 분리 |
| 실제 Root poll·IPC·파일 I/O·CPU quota·OS scheduling 중 정확한 지연 원인 | **UNKNOWN**. 실제 Kernel 재시험 전 원인 확정으로 승격하지 않음 |

## 3. Control/Data Plane 수정

기존 `continuous/native/service.py`에 bounded `ControlTransport`를 연결했다.
Root의 승인된 peer 연결 이후 제어 전송/STOP 수신을 별도 스레드에서 수행한다.
이 스레드는 BPF load·poll·lease 갱신·seal·정책 발급을 수행하지 않는다.

- Root main의 **매 poll 정책·파일 SHA 검증과 기존 5초 Kernel lease**를 유지했다.
- `POLICY_VALIDATE`, `INSTALLED_INTEGRITY`, `LEASE_RENEW`, `KERNEL_POLL`,
  `COUNTER_SNAPSHOT`, `WINDOW_FINISH`, `WINDOW_AUDIT_COMMIT`, `WINDOW_ATTACH` 단계를 기록한다.
- 전송은 nonblocking이다. 제어 메시지는 frame·counter·seal을 만들어내지 않는다.
- STOP은 peer에게 실제 광고한 generation·정책 SHA에 결합한다. 미광고 attach 중간 상태를
  현재 승인된 generation으로 오인하지 않는다. peer disconnect 시 재접속/재부착하지 않는다.
- Root 프로세스는 main + 기존 Audit writer + control의 3개 스레드이며 TasksMax4를 유지한다.

`TCXProducer`는 동일한 인증된 AF_UNIX 채널에서 control과 data를 구분한다.
Control은 제한된 data Queue를 점유하지 않으며 그 자체로 Window 적격성을 부여하지 않는다.
Sequence·clock 단조성·정책/Namespace·수신 freshness를 검증한다.

**수신 timeout5초는 유지**한다. Root worker 단계가5초 이상 진행되지 않으면
`CONTINUOUS_PRODUCER_WORKER_STALE`로 단계와 peer identity를 보존하고 STOP한다.
Buffered old control도 5초 freshness를 통과할 수 없다. 제어 생존과 worker 진행을 따로 판정하며,
수신 latency는 같은 Host monotonic clock에서 계산한 control 전송/수신 간격이다.

`ContinuousRuntime.observed_snapshot()`은 Queue 및 Authentication 상태 조회 자체를 기존
Native storage 경계 안에서 실행한다. `to_thread()` 호출 전에 동기 인자를 계산하던 경로를
제거했다. 승인·Queue capacity·Drop·Source identity·Capture Attestation 기준은 바꾸지 않았다.

## 4. STOP·Helper·Cleanup

### TCX

STOP intent의 wall/monotonic 시각을 send보다 먼저 기록한다. send 도중 취소되면
결과 UNKNOWN을 보존하고 같은 STOP을 자동 재전송하지 않는다. ACK 수신 시각과
send 완료 시각을 별도로 기록한다. 실패 이후 들어온 frame/seal은 진단 격리 대상으로 유지한다.
Worker-stale 실패 뒤에도 동일 채널에서 STOP ACK·진단 seal을 수집하는 운영 receiver 테스트가 통과했다.

### DNS Helper

RUNNING heartbeat2초와 STOP ACK5초를 구분했다. 명시적 STOP 이후에는 정상적인 capture
종료 대기를 heartbeat stale로 오인하지 않고, 기존5초 안에 인증된 CLOSED를 요구한다.
기존 heartbeat 실패가 먼저 발생한 경우에는 그 최초 실패를 보존한다.

CLOSED와 실제 PID/start identity 종료 확인은 **같은 STOP5초 잔여 예산**을 사용한다.
CLOSED 뒤 별도1초만 기다리던 경합을 제거했으며, ACK deadline을 추가로 늘리지 않았다.
ACK monotonic 순서, 최종 Counter, reader 합류, listener/channel 종료, process 종료,
cleanup 증거의 durable 기록을 따로 검증한다. reader의 마지막 ACK 누락 판정을 마치기 전에
소켓을 닫아 `MISSING`을 `INVALID`로 바꾸던 경합도 수정했다.

CLOSED가 있어도 프로세스가 남거나 Audit 기록이 실패하면 UNVERIFIED다.
이전 실제 Helper의 뒤늦은 Exit0으로 과거 Runtime receipt를 수정하지 않았다.

### Investigation Worker

취소된 Worker의 join 결과를 Runtime Cleanup에 반영한다. join하지 못한 스레드는
`UNVERIFIED_THREAD_NOT_JOINED`이며, 늦게 끝나더라도 앞선 판정을 소급 변경하지 않는다.
기존의 취소 후 gather 결과에서 Cleanup 오류를 누락할 수 있던 경로도 수정했다.
소유 Worker join은 Queue 전체 처리·Root·Global Kernel Cleanup을 뜻하지 않는다.

## 5. LLM Timeout·비용·Orchestration

기존 Provider adapter·RetainedAPIClient·ApplicationService·SOCRuntime·Planner·ThreatAssessor를
재사용했다. 실제 요청을 새로 보내거나 승인된 timeout/token/call 한도를 늘리지 않았다.

- 요청 intent에 PLAN / ASSESSMENT와 해당 승인 timeout을 기록한다.
- 실패 receipt에도 latency·종료 시각·미종료 HTTP worker·remote outcome UNKNOWN을 기록한다.
- 사전 `reserved_usd`, 응답 사용량 기반 비용 subtotal, 총비용 UNKNOWN을 구분한다.
- Timeout/취소 후 늦은 응답으로 usage나 총비용을 소급 확정하지 않는다. 자동 재시도는0이다.
- 실패 receipt/Audit 쓰기 오류가 최초 LLM Timeout을 덮지 않도록 원인과 후속 저장 실패를 분리한다.
- Plan·완료된 read-only Tool·Checkpoint를 보존하고 Assessment 실패를 독립 표시한다.
- 불확실한 외부 요청과 in-flight Claim은 자동 재개하지 않는다. 새 명시적 검토가 필요하다.

기존 `consume()`의 Claim·Lock·우선순위·Evidence Revision·Checkpoint·재계획 계약을 유지하면서
`isolated_consume()`가 기존 조사를 전용 thread/asyncio loop에서 실행한다. 동기 Checkpoint
작업이 Collector loop를 막지 않는다. 신규 Orchestrator나 동적 Agent Registry는 만들지 않았다.
조사 heartbeat는 Worker 관측이며 LLM 완료 증거가 아니다. 대기 중 상태·Task identity·API 상태를
갱신하고, 취소 시 owned coroutine을 취소·합류한다. 불확실한 Claim은 재실행하지 않는다.

동일 Incident 중복, 조사 중 Evidence 변경, conflict planning, 제한 replan, priority fairness,
known/unknown error, tool 실패, Checkpoint 복원과 uncertain-claim 차단을 기존 core 회귀로 검증했다.
AI 제안이 Root·Native·DNS·모델 권한을 생성하지 않는다.

## 6. Queue·Storage·GUI

기존 Persistent Queue·cursor·deduplication·POISON·retention·Audit 체인을 유지했다.
Queue full·slow persistence·partial write·disk full·corrupt checkpoint·중복·worker crash·
복구 복사본·retention 검증이 통과했다. 미처리 입력과 실패 tombstone을 임의 삭제하지 않는다.

기존 GUI에 control 단계·receive latency 및 API 요청별 상태/latency·총비용 UNKNOWN·예약 비용을
연결했다. 동일 Task의 Plan·완료 Tool·실패 Assessment를 표시하며, Cleanup UNVERIFIED를
성공으로 바꾸지 않는다. 실제 Tk 종료·재연결에서도 Backend 상태와 저장된 증거가 보존됐다.
Native / PCAP / Fixture / SCRIPTED / API adapter 결과를 실제 실행 증거에 따라 구분한다.

## 7. 실제 경과 10분 PCAP 통합시험

원본 저장 PCAP의 global header와 **첫128개 원본 레코드**를 변경 없이 private prefix 파일로
보존했다. 원본 SHA·prefix SHA·레코드 범위·11,864 bytes를 `input-provenance.json`에 기록했다.
합성 패킷이나 Kernel Capture가 아니다. 기존 단일 CLI setup → doctor → start → status →
GUI 종료/재연결 → stop을 실제로 실행했다.

| 항목 | 결과 |
|---|---|
| 실제 안정성 시험 경과 | **600.106초** |
| Replay 입력 | 128 records = Packet70 + 제외58 |
| Flow/분석 결과 | 36 |
| Feature | ELIGIBLE34 / INCOMPLETE2 |
| 실제 RF/LR Prediction | **68** |
| Incident/분석 결과 | 36; 위협36건을 의미하지 않음 |
| Orchestration Queue | DONE36, 표시 목록은 최신8개로 제한 |
| 분석 Queue | DONE36, 미처리0 |
| Queue Drop / Source gap / 모델 오류 | 모두0 |
| 조사 / 외부 API | SCRIPTED / 실제 외부 호출0 |
| GUI | 실제 Tk 종료·재연결2회, 동일 Backend 유지 |
| 종료 | STOPPED, final flush VERIFIED, 로컬 Runtime Cleanup VERIFIED |
| Storage | SQLite75개 integrity_check ok, Runtime Audit chain VERIFIED |

동시에 운영 `ControlTransport`/`TCXProducer`를 보통 사용자 AF_UNIX socketpair로 시험했다.
594개 control sequence를 수신했고 data Queue/drop0, 가짜 data event0이었다. 제한된 로컬
scheduling 부하를 주었으며 실제 Root cgroup CPU quota 시험으로 주장하지 않는다.

이600초 전체에 새 PCAP 데이터가 계속 생산됐다는 뜻은 아니다. 유한 prefix 처리 후에도
서비스·조사·관측·GUI·Stop이 유지되는 것을 검증했다. Kernel·Native 1시간 검증은 별도다.

## 8. 회귀·장시간 이벤트 시간·재현 빌드

| 검증 | 최종 결과 |
|---|---|
| Workspace 전체 관련 회귀 | **1,795 PASS**, pytest946.13초 |
| 독립 Export 같은 회귀 | **1,795 PASS**, pytest951.46초 |
| Source 무결성 | 두 실행 모두 시작/종료 Source 동일, Workspace/Export canonical SHA 일치 |
| 실제 Tk 별도 GUI 회귀 | 5 PASS; 최종 전체 회귀에도 새 reliability GUI 시나리오 포함 |
| 느린 상태 조회 | 6.1초 지연 중에도 control 수신 계속, data Queue/drop0 |
| Control 장애 | quiet, stale worker, old/replayed control, clock, bounded Queue, same-channel STOP/seal/ACK |
| Helper 장애 | 2.2초 close·1.3초 process exit·종료 누락·Exit7·ACK 누락·Audit 실패 |
| API 장애 | Mock timeout/cancel/late reply/usage 누락/잘못된 구조/저장 실패, 자동 호출 재발행 차단 |
| 가상 장시간 | 600 synthetic events, 약5시간 event-time; Queue1 포화598건 정확히 계측 |
| 가상 Native형 Window | 72분 event-time, 25개 seal·crash 재구성·Replay 거부; Fixture이며 Kernel 성공 아님 |
| 내구성 | 5,000-event 저장 및 관련 Recovery·Audit 회귀 통과 |
| Ruff / Format / Diff | PASS / 1,542파일 PASS / PASS |
| Continuous Native | 6파일, Workspace2회 + Export SHA 동일; BTF userspace parsing, Kernel load 없음 |
| 기존 Native 컴파일 | Workspace2회 + Export 동일, 실행 없음 |
| Supervisor | 2개 guarded Preview 파일, Workspace2회 + Export 동일; 활성화/실행 권한 없음 |
| Controller | 기존 테스트의2파일 재생성, Workspace/Export 각각 같은 fixture Binding 내 일치. 실제 실행 Artifact로 승격하지 않음 |
| Wheel | Workspace2회 + Export SHA 동일 |

테스트·Assertion·보안 검증을 삭제하거나 완화하지 않았다. 최종 코드의 전체 검증은 소스를
고정한 뒤 짧은 private 임시 경로에서 수행했으며 `--import-mode=importlib`을 사용했다.
모델 테스트는 기존 `SOC_RESEARCH_VALIDATION_REPOSITORY` 경로를 명시했다.

### 중간 실패도 보존

- 같은 basename의 테스트 collection 충돌과 잘못된 기본 모델 경로는 검증 실행 설정을 교정했다.
- 중간 회귀 중 구현 파일을 수정해 SourceGuard가 정상 거부한 결과는 별도 보존했다.
  최종 회귀는 Source 고정 전후 SHA를 강제 확인했고 두 환경 모두 통과했다.
- 긴 Export 증거 경로가 AF_UNIX 주소 한도를 넘긴 실행은 보존하고 `/tmp/soc-rel-final-*`로 교정했다.
- 전체 PCAP burst 시험은 기존 Window 보관 상한에서 중단됐다. 최종 Drop352와 pending126을
  보존했고 Stop은 정상 처리됐다. 이를 무손실/장시간 성공으로 보고하지 않는다. 상한을 늘리거나
  Queue를 삭제하지 않고, 별도 prefix 입력으로 위 최종10분 시험을 수행했다.

## 9. Artifact·Git

- Continuous CLI code identity: `bdd04ff1bfc546473adfa7ab69c9b6cfd1cf5d02d2442e220e05f83897a1f9f7`.
- 최종 검증 Source canonical SHA: `7ee997d3ed285a14280f81b1f47d9b9375ab70d7c97367b277144913ae9b0892`.
- Source map 파일 SHA: `82632fd554ca0d54697222064ece71f0f21e753a102558d97fafd1827779663d`.
- 새 Wheel SHA: `d2d3d8aff6679103ff9e0345d59428d193785097c9b85a9fa802f8117362fce5`.
- 새 Root Collector service.py SHA: `3d129b8c7075067ebdb7cb9197c368f95812c364f0d9d13a41677679521178d9`.
- BPF object·provider·policy·unit은 빌드 결과가 기존과 같으며 Root service.py와 Python runtime
  package는 변경됐다. 설치본을 바꾸지 않았고 예전 승인 Binding을 재사용하지 않았다.

전체6파일·Supervisor·Controller·모델 fingerprint와 Git Identity는 private
`final-artifact-identity.json`, 상세 빌드 결과는 `reproducible-builds.json`에 있다.
최종 Push 결과는 같은 증거 디렉터리의 `git-final.json`과 최종 응답에 기록한다.

보존된 Replay 결과의 읽기 전용 UI 확인:

```bash
cd /home/geonug/kdt-linux/soc-one-command-runtime
.venv/bin/soc-agent status --home /home/geonug/kdt-linux/autonomous-soc-agent/.git/overnight-reliability-20261030T120835Z/bounded-pcap-soak/replay-profile
.venv/bin/soc-agent gui --home /home/geonug/kdt-linux/autonomous-soc-agent/.git/overnight-reliability-20261030T120835Z/bounded-pcap-soak/replay-profile
```

이 프로필은 실제 Native 실행용이 아니다. 기존 Native 프로필을 새 코드로 자동 재실행하지 않는다.

## 10. 다음 실환경 시험의 최소 조건

1. 이번 Source/Wheel/Root service·새 Session·Release·Root Manifest·Namespace·최신 Ledger에
   결합된 새 검토 자료를 기존 CLI로 만들고 검증해야 한다. 예전 승인/소비된 Session은 사용하지 않는다.
2. 우선 기존 전용 Namespace `lo/Ingress`, 전체600초 이내의 짧은 시험을 검토한다.
   기존 고정 공급원 TCP 최대4연결, DNS UDP2/TCP1, 외부 연결 없음, 기존 자원·저장 상한 유지.
   정확한 포트·페이로드·일정·전체 Deadline은 새 검토 패키지에 고정하고 인간 승인받아야 한다.
3. 새 R1/Root/Native/트래픽 승인·유효기간·사용자 Scope 직접 확인·sudo 인증 후 최대1회 실행한다.
   새 control 단계/latency, worker 진행, seal·Counter·STOP ACK·Helper CLOSED·실제 종료·
   Root/Runtime Cleanup을 독립 판정한다. 실패 시 자동 재실행하지 않는다.
4. Native RF/LR는 실제 봉인된 ELIGIBLE 입력별 별도 Model Action 승인 후에만 실행한다.
5. 실제 LLM 재검증은 보존 Incident/Revision과 새 attempt에 별도 API 승인이 필요하다.
   최신 Provider/가격·요청/토큰/비용·deadline을 검토하고 불확실한 과거 호출을 재사용하지 않는다.
   기존20초 Assessment의 원격 실패 원인은 여전히 UNKNOWN이다.
6. 짧은 시험이 성공한 뒤에만 순수3,600초 수집·별도 전체 상한의 새 운영 시험을 검토한다.

이번 판정은 비권한 신뢰성 통합 완료다. 실제 Kernel 안정성·실제 LLM Assessment·
과거 Global Cleanup·무중단 운영·DNS9·Host Authentication Live 검증을 포함하지 않는다.
