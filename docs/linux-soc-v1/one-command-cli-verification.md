# 단일 CLI 운영 경로 검증 · 2026-10-29

## 최신 보강 · 실제 Native 장시간 시험 준비

기준선 `7e37a26`에서 기존 구성 요소를 유지하며 다음 운영 경로를 보강했다.

- `start --preview`: Source·고정 Controller·Config·현재 Ledger·Namespace/Lease·one-shot
  표식 검증. 승인·예약·sudo·Root·Collector 실행이 전혀 없는 사전 검사다.
- Native `start --gui`: 승인된 고정 터미널 경계 전 비권한 조회 GUI를 별도 연결한다.
  실제 권한·TTY·인증은 기존 Entry Point가 처리한다. 실패 시 소유 GUI만 회수한다.
- `doctor`: PASS/WARN/BLOCKED/FAIL 및 Host/Target scope를 구조화했다. Python·의존성·
  모델 SHA/Manifest/Network14 Fingerprint·Namespace mount·Root 설치·고정 systemd 조회·
  Queue/Checkpoint/Audit·Storage·GUI·API 설정을 읽기 전용으로 검증한다.
  Target 내부에서는 기존 `inspect_current_isolation` 관측을 재사용한다. Host에서 진입하지 않는다.
- `setup --recover-from`: 검증된 STOPPED Replay의 격리 복사본만 복구한다. Native 권한,
  기존 승인, POISON 재시도나 attempt 초기화는 제공하지 않는다.
- 재시작 때 복원한 이벤트 시각을 지워 마지막 Window ID가 달라지는 결함을 수정했다.
  보관 상한에서도 동일한 기존 작업의 재전달은 허용하되 새 Window 상한과 입력 SHA 검증은 유지한다.
- Stop 요청은 `STOPPING / OPERATOR_REQUEST`를 먼저 게시한다. 새 고정 실환경 감독자는
  이를 Collector 장애와 구분하고 승인된 소유 자원만 정리해야 한다.

### 실제 보존 Queue 33건 복구

증거: `.git/one-command-native-finalization-20261029T090002Z/queue-recovery-report.json`.
원본은 이전 CLI 검증의 PCAP128 Runtime이며 원본 DB·입력·보고서·Audit 전체 파일 SHA를
복사 전·후 대조했다. 원본은 DONE3/PENDING33, Cleanup VERIFIED 상태 그대로 보존됐다.

격리 복사본에서 운영 setup/start/status/stop 경로로 176.89초 동안 처리했다.
최종 DONE36 / PENDING0 / CLAIMED0 / POISON0, 기존 DONE3건을 재처리하지 않았다.
추가 Prediction62 / Incident33이며 INCOMPLETE2건은 추론하지 않았다.
기존3건을 포함한 보고서36개·고유 Incident36개·Prediction68개를 원본 Receipt/Audit로
검증했다. Drop0 / 모델 오류0 / 외부 API0 / 소유 Cleanup VERIFIED다.
recovered ingress128 및 duplicate delivery128은 같은 작업의 재추론을 뜻하지 않는다.
단위 회귀에서는 손상 Checkpoint·변조 입력·Native 복구·미검증 Cleanup·동시 writer를 차단하고,
불확실한 in-flight는 기존 retry_limit에 따라 POISON 처리했다. attempt를 환급하지 않았다.

### 비권한 검증과 실환경 경계

Workspace 관련171 PASS(기존5000-event 내구성은 중복 실행하지 않음).
실제 PCAP·모델·운영 CLI·실제 Tk GUI 회귀1 PASS. Root 경계만 모의한 Native Preview/Entry/
TTY/GUI 시작 순서 회귀와 실제 Queue 복구를 별도로 판정한다.
비권한 성공을 Kernel/TCX 실환경 성공으로 보고하지 않는다.

사용자는 실제 Root·TCX 장시간 통합 시험을 요청했다. 다음 새 패키지는 최대3600초 전체
Envelope, 기존 Namespace `net:[4026532232]`, lo/Ingress, 고정 loopback TCP만 사용한다.
Capture 종료를 먼저 준비해 Cleanup 시간을 Envelope 안에 확보하고 실제 수집 시간을 따로 기록한다.
기존 소비된240초/1시간 승인·R1·모델 영수증은 재사용하지 않는다. 정확한 새 패키지 Scope/R1,
사용자 직접 확인·sudo 후에만 실행하며 모델은 봉인된 실제 ELIGIBLE 입력의 별도 Action 승인이 필요하다.
Program1145 UNKNOWN·과거 전역 Cleanup UNVERIFIED·FAILED/false 및 53분대 Timeout 이력은 유지한다.
5초 수신 watchdog은 유지하며, 기존 Timeout의 하위 스케줄링/디스크 지연 원인을 해결했다고 단정하지 않는다.

아래 내용은 `7e37a26` 시점의 기존 검증 기록이다.

검토 기준선은 `feat/one-command-runtime` / `2c811294ba7455974b418190b42b450b204eb2c4`다.
사용자 main의 미커밋 변경 대신 기존 clean worktree
`/home/geonug/kdt-linux/soc-one-command-runtime`에서 수정했다.
증거 디렉터리: `.git/one-command-cli-verification-20261029T081222Z/`.

## 명령별 구현 판정

콘솔은 `pyproject.toml`의 `soc-agent = soc_agent.cli:main`이다.
`cli.main` → `agent_cli.main` → `agent_runtime`으로 전달된다.
기존 `start --gui --monitor total`, `continuous`, `analyze-offline`, `native-recovery`는 유지한다.

| 명령 | 판정 | Entry Point / Backend | 실제 확인과 한계 |
| --- | --- | --- | --- |
| setup | VERIFIED | agent_runtime.setup → ContinuousConfig / AgentProfile / Store.create | 새 private profile·영속 Queue 생성, Source SHA 고정, 기존 Runtime 연결. Root 설치 명령은 아님 |
| start | PARTIAL | agent_runtime.start → continuous.cli.start → ContinuousRuntime.run | Replay Producer·Window·Queue·별도 AI Worker·Incident·Audit의 실제 E2E 통과. Native는 기존 고정 승인 terminal Entry Point에 연결되지만 이번 실환경 시작은 금지·미검증 |
| status | VERIFIED | agent_runtime.status → continuous.cli.observed_status | 실행·종료 Replay와 보존 Native 상태, Heartbeat·Queue·Drop·Window·Prediction·Incident·Cleanup. atomic mirror는 승인 권한 자료가 아님 |
| stop | VERIFIED | agent_runtime.stop → Store.control → Runtime finally / source.close / analysis.close | 소유 프로세스 종료·최종 Flush·Cleanup 확인. 미처리 Queue는 보존하며 완전 Drain을 주장하지 않음 |
| gui | VERIFIED | agent_runtime.gui → gui.__main__.main → production.Desktop → Backend | 실제 Tk mainloop·검증된 보고서·다섯 화면, 실행 중 분리 및 종료 후 재연결. GUI가 외부 Runtime을 종료하지 않음 |
| doctor | PARTIAL | agent_runtime.doctor → profile / SHA / model registry / DNS9 contract | 현재 Python·입력·코드·모델 SHA·고정 Interpreter 가용성·GUI Display 진단. Native Namespace 내부 check·Root 서비스 권한·전체 dependency 실환경 가동을 대신하지 않음 |

`NOT_IMPLEMENTED`인 명령은 없다. PARTIAL은 등록 여부가 아니라 검증 범위와 실제 권한
경계를 반영한다. Native 1시간 운영 전체를 단일 명령으로 재검증한 결과는 아니다.

## 실제 start 데이터 경로

`continuous.cli.start`는 일반 사용자 자식 서비스의 실제 PID·Heartbeat를 검증한다.
Runtime의 독립 collect/consume task가 다음을 실행한다.

```text
ReplaySource / 별도 승인된 TCXProducer
→ observe → StreamingFlows / CaptureWindows
→ complete / handoff → Store.enqueue → EventQueue
→ consume → AnalysisService → 기존 offline workflow
→ Eligibility / RF·LR → Incident / Scripted Investigation / Audit
→ ResultViews.verify_result → GUI
```

Window 종료는 이벤트 시간·Flow 종료/idle 증거에 따른다. Native는 Capture Attestation과
별도 exact Model Action 승인도 필요하다. EOF·Stop·GUI 표시만으로 부적격 입력을 승격하지 않는다.

## 수정한 결함

1. 이미 STOPPED인 Runtime에 `stop`을 호출하면 Cleanup 검증을 생략했다.
   동일한 VERIFIED 검증을 적용하고, UNKNOWN/UNVERIFIED/누락은 실패로 반환한다.
2. 종료 응답에 Queue 처리 완료와 소유 프로세스 Cleanup의 차이가 드러나지 않았다.
   `queue_drain`, `unprocessed_jobs`, `failed_jobs`, `collector_cleanup`을 독립 반환한다.
3. doctor가 모델 SHA 불일치를 보고해도 PCAP start가 서비스 Spawn까지 진행했다.
   선택 모델과 고정 Interpreter가 준비되지 않으면 Spawn 전에 실패한다.
4. Replay 조기 종료에서 `process.wait()`만 사용해 stdout Pipe transport가 남을 수 있었다.
   직렬화된 close에서 소유 자식의 종료와 Pipe Drain을 함께 기다리고, SIGKILL 후 대기도 제한한다.
   실제 포화 Pipe 자식을 두 closer로 동시에 종료하는 회귀를 추가했다.

Root·Native 권한·보안 정책·자원 한도는 변경하지 않았다.

## 실제 PCAP·RF/LR·GUI 결과

`tests/agent_cli_checks.py`는 실제 운영 CLI Entry Point를 subprocess로 호출해
setup → doctor → start → status → 중복 start 차단 → GUI → stop → GUI 재연결을 수행한다.
GUI는 실제 CLI main과 Tk Desktop/Backend를 사용하며, 테스트 instrumentation은 자신이 연
창의 화면 이동·종료만 담당한다. 모델·Collector 데이터나 Backend를 Mock하지 않는다.

- 원본 저장 PCAP SHA: `80dcc2602519479ddcde889fa902fee19a76696630811452f8df38888af894f2`.
- 원본의 첫 128개 레코드 바이트·시각을 그대로 사용한 prefix SHA:
  `b76b8bf99528f764854d33915b6c52e277353eafcca12c9cdd8fafeaf030cc0b`.
- 수신 레코드 128 / Packet 70 / 파서 제외 58 / Flow 36.
- ELIGIBLE 34 / INCOMPLETE 2 / 실제 RF·LR Prediction 6 / Incident·Audit 3.
- Drop 0 / 모델 오류 0 / 외부 API 0 / Native 수집 0.
- 최종 Queue DONE 3 / PENDING 33, `queue_drain=PENDING_RETAINED`.
- Collector·Worker STOPPED / 소유 Cleanup VERIFIED.
- Dashboard·Continuous·AI Analysis·Investigation·System의 RUNNING 및 STOPPED 표시 확인.
- 첫 GUI 종료 후 Backend RUNNING 유지. Stop 후 GUI 재연결은 Runtime 상태·Audit를 변경하지 않음.
- 결과는 OFFLINE_PCAP이며 조사 SCRIPTED다. Native 성공으로 표시하지 않는다.

`cli-proof3/.../verification.json`과 `cli-gui-tests3.log`가 이 결과를 보존한다.
전체 원본 PCAP의 모든 Flow를 분석했다는 의미는 아니다.

## 실패와 제한 보존

- 첫 테스트의 "첫 Prediction 시점에 EOF" 가정이 잘못돼 실패했다. 수집과 모델 Worker는
  독립이므로 EOF와 Prediction을 각각 기다리는 검증으로 고쳤다.
- 큰 원본 PCAP 전체를 기다린 시험은 Window 보관 상한 512개에서 차단됐다.
  당시 Drop 366 / 모델 40 / Incident 20 / Queue PENDING 126을 보존했다.
  최초 오류는 `CONTINUOUS_WINDOW_RETENTION_REQUIRES_ARCHIVAL`, Cleanup UNVERIFIED다.
  부차 오류의 원문은 보존 자료에서 확인되지 않으므로 그 원인을 단정하지 않는다.
  그 실패를 성공으로 바꾸거나 해당 Runtime을 재시작하지 않았다.
- 일반 회귀의 Unix socket 4건은 긴 `--basetemp` 경로가 AF_UNIX 한도를 넘겨 실패했다.
  짧은 `/tmp` 경로에서 같은 검증을 재실행해 통과했다. 기존 assertion은 유지했다.

현재 기본 자원·보관 상한을 지키는 CLI다. 대규모 입력 전체 무손실 처리·자동 보관/재개와
실제 Native 장시간 운영 완료는 별도로 남는다. stop은 미승인 Native 모델 작업을 자동 승인하지 않는다.

## 다음 사용

[실제 명령어와 운영 범위](one-command-runtime.md)를 따른다.
보존 Native 조회는 [Native GUI 명령](native-gui-test-commands.md)의 profile을 사용한다.
이번에는 Root·Native·DNS Live·Host 로그 수집·API·실행 예약·승인 소비·기존 Ledger 변경이 없다.
기존 Ledger 81행과 SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`를 보존한다.

실제 Native start는 새 유효 Artifact/Session/Release/Namespace/최신 Ledger Binding,
필요한 R1/R2·Root·모델 Action 승인, Namespace 내부 check, 사용자 Scope 확인·sudo가 필요하다.
이 문서는 그 승인이나 실행 권한이 아니다.

## 검증 기록

- 최종 Workspace 관련 회귀: 153 PASS. 이미 통과한 5,000-event 내구성 1건은 반복하지 않았다.
- 실제 PCAP → 운영 CLI → RF/LR → Incident·Audit → 실제 Tk GUI: 1 PASS, 32.16초.
- Cleanup/의존성 선행 차단·Unix transport 집중 회귀: 17 PASS.
- 포화 Pipe 및 CLI 집중 회귀: 14 PASS.
- 독립 Git Export: 동일 관련153 PASS, 실제 PCAP/CLI/Tk 통합1 PASS(32.79초).
  Workspace와 같은 Packet70 / RF·LR6 / Incident3 / Drop0 / Cleanup VERIFIED를 확인했다.
- 실제 `.venv/bin/soc-agent` 실행 파일로 setup/doctor/start/status/stop/gui/status를
  별도 확인했다(`console-smoke.json`). 이 보조 검증은 UUID가 유효한 명시적 JSONL Fixture이며
  실제 모델 경로 검증은 앞의 실제 PCAP 시험이다. 첫 보조 입력의 잘못된 UUID 실패도 보존했다.
  기존 lifecycle 단위 테스트도 유효 UUID를 사용하고 실제 처리1·invalid0을 확인하도록 보강했다
  (보강 후13 PASS). 운영 입력 validator를 완화하지 않았다.
- Ruff check·format·diff check 통과. Native userspace 빌드6개 및 Wheel 이중 빌드 일치.

빌드 동결 Commit `3565293cfa3ae9fb20a6612c13fd8f645fb8d5f1`, Tree
`3c2786961677fcff8129c4135f9804f3d65c613b`.
Source archive SHA `80e17d7461a145573b8fd713dedd7a792d11797c91bb23491e182546769acfde`.
Runtime source660개 파일 map SHA
`4d7127167618c25024c97e470352a3123b9797e77f20f6e05b581e379750c46a`.
Workspace/Export Wheel SHA
`63759d8263dd0d5d0fcd2a19277f1c3bbc27de786253076edf527e2e05b73855`.
후속 보고·단위 테스트 Fixture 보강은 Runtime source나 Wheel을 변경하지 않는다.
빌드와 검증 로그는 증거 디렉터리의 `build-identity.json`, `source-files.json`,
`workspace-final-tests.log`, `export-tests.log`, `export-cli-gui-tests.log`에 보존했다.
