# 단일 CLI 운영 경로 검증 · 2026-10-29

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
- Ruff check·format·diff check 통과. 최종 Source 동결 후 독립 Export 결과와 Commit은
  Operations Verification 보고서의 이번 CLI 검증 항목에 기록한다.
