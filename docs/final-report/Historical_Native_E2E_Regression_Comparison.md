# 과거 성공 Native E2E와 현재 Root Exit 2 실패본 비교

2026-11-03. 실제 실행은 재시도하지 않았다. 분석 대상 실패 Session은 `81660de4-5cb8-418a-ae46-520ba4b168c0`, 실행 frozen 코드는 `74cbcb2`다. 현재 수정 코드 `30df74e`와도 비교했다. 대상 저장소의 문서 HEAD `dfb6abd` 및 기존 사용자 변경은 실행된 frozen 코드와 구분한다.

**결론: 성공 증거는 유효하지만, 특정 Git 변경이 현재 송신 공백을 유발했다는 회귀 인과관계는 아직 UNKNOWN이다.** 현재 증거는 정상 Control 송신 시도 중단(`PRODUCER_NOT_SENDING`)까지 좁힌다. 최초 오류 보존과 늦은 DNS 트래픽 시작 차단은 수정·검증했다. TCX 송신 정지의 근본 원인이 해결됐다고 선언하거나 기존 보안·Cleanup 개선을 되돌리지 않았다. 다음 Live 실행 준비 판정은 **BLOCKED / 원인 복구 PARTIALLY_VERIFIED**다.

## 1. 성공 기록의 실제 범위와 구현 Identity

|사용자가 지정한 기준|실제 실행 코드 / 경로|확인한 원본 결과|이 시험이 증명하지 않는 것|
|---|---|---|---|
|`71377c7` Native 성공|실행 코드는 `c542398`; `71377c7`은 이후 Worker 상태 표시 4줄 및 회귀 테스트 수정|404.593137초 전체 / 396.136964초 봉인 수집; Packet54, DNS3, Window3 VERIFIED, ELIGIBLE5, RF/LR8, Incident2, Task5, 소유 범위 Cleanup VERIFIED|실제 LLM 호출0; SCRIPTED 조사. `71377c7` 수정이 당시 실행됐다고 소급하지 않음|
|`82b1dc1` 실제 LLM 성공|문서 Commit. `analyze-offline` → 기존 OfflineWorkflow, 저장 PCAP 입력과 API 당시 Source pin 사용|실제 API2, Plan17.166340초 / Assessment13.392354초; Read-only Tool 완료, Incident `a79cecb6-9b8e-4c21-a55a-5caf7b150400`, Audit13행 검증|Native Collector·TCX IPC·Continuous 수신 안정성 시험이 아님|
|`e3412e8` 제한 Native 성공|실제 Capture 코드 `608c03e`; 정지 후 같은 Native 입력을 `analyze-offline`에서 별도 승인 분석|Native20, Window2, ELIGIBLE1/INCOMPLETE1, RF/LR2, Incident1, GUI·소유 Cleanup 검증|DNS/실제 LLM0; 당시 전체 프로그램의 동시 Continuous 모델·LLM 검증이 아님|
|현재 실패|`74cbcb2`의 같은 실행 Session|전체41.595616초, Native Packet0, DNS Transaction0, Runtime Window0, 모델/API0; Root Exit2|이전 46.87초 실패의 Packet12/DNS2와 다른 시험. 합산하지 않음|

각 성공 결과를 합쳐 하나의 Native+실제 LLM 동일 Session 성공으로 표현하지 않는다. 정상 시험용 TCP의 모델 이상 분류는 실제 공격 확정이 아니다.

원본 위치:

- Native54/DNS3: `.git/native-orchestration-final-fixes-20261030T085013Z/review-ready/execution/`, 독립 검증 `.git/native-orchestration-approved-attempt-20261030T093317Z/native-result-verified.json`.
- 실제 API: `.git/ai-pipeline-integration-20261027-1/actual-api-e2e/`.
- Native20: `.git/continuous-scalar-recovery-20261029T012308Z/execution/execution-result.json`, `retained-native-model-analysis/result.json`.
- 현재 실패: `.git/full-e2e-operations-readiness-20261103T035500Z/candidate-final/native/execution/`.

## 2. 성공 증거를 다시 읽은 결과

[Historical pins](evidence/historical-native-comparison-20261103/historical-pins.json): Native54 성공의 보존 파일 **178/178 SHA 일치**, Native20 실행 핀 **17/17 일치**. Native54 frozen Collector Source의 비교 가능한 9개 파일은 실제 실행 Commit `c542398`와 모두 일치했다. 실제 성공 Session·별도 작업 승인·GUI 결과·종료 증거를 유지한다.

[실제 API 증거 검증](evidence/historical-native-comparison-20261103/api-evidence-verification.json): SQLite를 `mode=ro&immutable=1`로 열고 기존 `validate_audit`로 13행 체인, 완료 결과 digest, 기존 `verify_api_receipts`로 두 요청/응답/Usage/Audit Binding을 검증했다. 새 API·모델 호출0, 원본 파일 SHA 모두 불변. 입력2764 / 출력3605토큰, 당시 단가 추정 합계 $0.00790100이다. 현재 요금이나 실제 결제 금액으로 해석하지 않는다.

API 당시 Source pin과 나중의 `source-export`는 1241개 중1237개 일치, 4개 불일치다(`api_investigation.py`, `offline_workflow.py`, `workflow_models.py`, `test_api_investigation.py`). 당시 보고서는 API 호출 후 Raw DNS/Receipt 검증 등을 추가했다고 명시한다. 최종 Export를 API 호출 시점의 완전한 원본으로 주장하지 않는다. 이 4개 파일의 호출 당시 전체 바이트 재구성은 **EVIDENCE_REQUIRED**이고, 이 불일치만으로 API 응답 위조나 Native 회귀를 단정하지 않는다. 원본 두 응답과 Audit의 Binding 검증은 별도로 통과했다.

## 3. 실제 호출 경로 비교

### Native20 (`608c03e`, `e3412e8` 보고)

고정 Root Launcher → 설치된 Collector `run` → `Provider` Kernel poll → `soc-continuous-tcx:v1` → `TCXProducer.events`의 직접 `sock_recv` → Runtime Queue/집계 → Seal/Attestation → Stop. 정지 후 보존된 Native Job → 기존 `analyze-offline`/OfflineWorkflow → exact RF/LR Action → SCRIPTED 조사·평가 → Audit/GUI였다. 당시 TCX 수신5초, STOP 송신2초/ACK5초였다.

### Native54 (`c542398`, 이후 `71377c7`)

Root Launcher → 같은 Kernel Provider → Collector 주 loop의 약1초 DATA envelope(빈 frames도 전송) → `TCXProducer.messages` background receiver → bounded queue → `events`/records → `ContinuousRuntime.collect` → Queue/Window Seal → `run_native_job`의 실제 봉인 Job 승인 → AnalysisService/OfflineWorkflow → Incident → ApplicationService/SOCRuntime → SCRIPTED Plan/Tool/Assessment → Audit/GUI. DNS Helper의 별도 metadata/transaction 경로도 Runtime에 연결됐다. 조사 Worker는 수집 loop와 별도다.

`71377c7`의 변경은 `start_retained_tcx`가 승인 검증 후 Worker를 시작하면 `worker_state="ANALYZING"` 및 관측 시각을 갱신하는 것이다. Collector, IPC, Heartbeat, Root 설정 변경은 이 Commit에 없다. 해당 상태 표시 수정을 송신 공백의 원인으로 볼 근거가 없다.

### 현재 실패 (`74cbcb2`) 및 수정본 (`30df74e`)

Root Launcher → 동일 Provider ABI → `ControlTransport` thread(accept/SO_PEERCRED, nonblocking Control·STOP) + 기존 Data Worker → 같은 SOCK_SEQPACKET → `TCXProducer.receive_message`/`messages` → Control은 별도 검증, Data는 bounded queue/저장 projection → Runtime. 봉인·모델 승인을 통과한 경우 이후 기존 SOCRuntime 및 실제 API 경로가 실행되도록 연결돼 있다. **이번 실패는 첫 Packet·Window·Prediction·Incident 이전**이므로 실제 모델/LLM 계산이 Collector 수신을 막았다는 증거는 없다.

현재 수정본은 `74cbcb2` 대비 운영 Source에서 `continuous/service.py`의 최초 오류·trace 보존8줄만 다르다. Native service/Producer/Root bytes는 해당 수정으로 바뀌지 않았다. 설치 Root Source와 개발 중인 수정본을 혼동하지 않는다.

## 4. 설정·프로토콜의 구체적 차이

|항목|과거 Native 성공|현재 실패|판단|
|---|---|---|---|
|Namespace / interface|전용 `net:[4026532232]`, lo/Ingress|동일|Scope 변경 회귀 증거 없음|
|Collector|CPU25%, RAM128MiB, TasksMax4|동일|성공/실패의 고정 설정은 동일. 실제 CPU contention은 별도|
|Runtime|CPU50%, RAM512MiB, TasksMax32|동일|설정 차이로 최초 오류를 설명할 수 없음|
|서비스|Restart=no, KillMode=control-group, RuntimeMax7min, Collector Stop10초/Runtime35초|동일|상태/PID/이전 실행 CPUUsage 등의 가변 관측값은 설정 Diff에서 제외|
|Kernel BPF / provider / build / policy.py|성공 `71377c7` 기준|`74cbcb2`와 바이트 동일|Kernel 프로그램 변경으로 단정할 근거 없음|
|Control|주 Worker의 DATA envelope가 무트래픽 생존 신호도 담당|독립 `soc-continuous-tcx-control:v1` 추가; Data/Stop v1 유지|구체적 구조 변화. 그 자체가 장애 원인임을 증명하지 않음|
|Receive|background receive + bounded queue|독립 Control 검증, queue와 durable 처리 분리, 수신 계측|현재 프로토콜 양단이 일치하고 Control1~9가 실제 수신됨|
|수신/STOP|receive5초, send2초, ACK5초|동일; transport-only ACK 대기 분기 추가|Timeout 확대/완화 없음|
|정책·무결성|주 loop에서 `validate(root_file(POLICY))`, `installed()`|동일 검사 유지, stage 게시 추가|마지막 stage=INSTALLED_INTEGRITY가 해당 함수의 결함을 증명하지 않음|
|LLM|저장 PCAP API 시험은120초/최대2회; 실제17.17·13.39초|현재 검토 Scope20초/최대2회/$0.05|별개의 설정 차이. 이번 실패는 API 호출 전이므로 TCX 원인 아님|

[서비스 설정 비교](evidence/historical-native-comparison-20261103/service-contract-comparison.json), [파일별 SHA/AST 위치](evidence/historical-native-comparison-20261103/source-comparison.json), [프로토콜/Deadline](evidence/historical-native-comparison-20261103/protocol-comparison.json), [실제 Launcher 함수·호출 위치](evidence/historical-native-comparison-20261103/launcher-comparison.json)를 첨부했다. 서비스 계약 JSON은 시작 전 저장된 고정 설정 관측이며 이전 Result/ExitStatus를 이번 실행 결과로 쓰지 않았다.

관련 변경 이력: `568e759` Control/조사 분리 → `c6405d7` 저장 독립 Control Heartbeat → `2cfcf7e` Data 검증 후 송신 → `183070f` 초기 accept·STOP ACK 전달 → `62567c1` 송수신/Lock/CPU 계측. [History](evidence/historical-native-comparison-20261103/transport-change-history.txt). 과거 성공 이후 변경됐다는 사실만으로 어느 Commit도 범인으로 지정하지 않았다.

## 5. 최근 Root Exit 2의 최초 오류

상세 타임라인·PID·시각은 [Root Exit2 복원 보고](Full_Live_E2E_Root_Exit2_Recovery.md)와 그 원본 증거를 참조한다.

1. 13:49:38.497810 Root Socket READY → 13:49:41.921910 첫 Control 수신 → 13:49:43.013744 인증 READY.
2. 마지막 Control9 송신완료 13:49:52.008563 → Runtime 수신 13:49:53.102300. 전달 관측 지연 **1093.736908ms**.
3. **13:49:59.413934 최초 오류 `CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT`**. Runtime PID2079255, frozen `tcx_producer.py:357`의 `wait_for(sock_recv,5)` → **395행** domain ValueError. 실제 wait6.311554초는 타이머/스케줄링 복귀를 포함한 관측값이며 설정6초가 아니다.
4. Root `root-trial.py:519` → `observe_service_health:375`가 같은 오류를 `RUNTIME_FIRST_ERROR`로 전달했다. Root coordinator PID 기록은 없고 Collector PID2079245와 구분한다.
5. DNS stale는 13:50:02.416862로 **후속 오류**다. 실제 DNS Helper는 그때 PID/Start Identity 일치, state R이었다. 최초 TCX 오류를 DNS 오류로 치환하지 않는다.
6. Root 실제 wait Exit2, `deadline_exit=false`. Collector 서비스 자체 Exit0, Runtime 서비스 Exit2. systemd의 `2/INVALIDARGUMENT`는 범용 exit명이고 인자 Parsing 오류 증거가 아니다. 공유 Launcher41.595616초이며 전체600초 만료가 아니다.

### 증거로 확인된 송신 공백

Root durable trace: **Control9+Data8=17, SENT17, BACKPRESSURE0, PARTIAL0, ERROR0, truncated0**. 마지막 정상 Control 송신부터 Root의 VALIDATED_STOP 처리까지 **13.599345초** 동안 다음 정상 Control 송신 시도가 없다. Data frames는 비어 있다. 최대 기록 send0.627016ms / Lock대기0.016099ms, Timeout 시 Runtime FIONREAD0 / app Queue0 / drop0이다.

따라서 분류는 **PRODUCER_NOT_SENDING**이다. Protocol 불일치였다면 나오는 Identity/Control validation 거부가 없고, 실제 Control1~9의 수신·인증을 확인했으므로 **IDLE_PROTOCOL_MISMATCH를 이번 직접 원인으로 지목할 근거가 없다**. 기록된 send/socket/Lock이5초 막혔다고도 주장하지 않는다. 단, 마지막 send 이후 Root thread가 왜 실행되지 않았는지는 UNKNOWN이다. 별도 finally-path의 Seal/ACK 시도까지 없었다는 뜻은 아니다.

Root CPU 표본14.493957초 구간에 usage1.746551초, periods145, throttled137, throttled_usec25.394701초 증가가 있다. **Throttling은 실제 관측됐지만**, 누적 CPU counter가 wall-clock 공백 또는 GIL 원인을 직접 증명하지 않는다. 당시 Host scheduling/GIL/native syscall의 세부 구간, 성공 시험과 같은 방식의 CPU trace 비교값은 부족하다. 성공 당시 같은 CPUQuota로 통과한 사실도 이번 scheduling 문제가 없었다는 증명은 아니다.

## 6. 확정 결함과 최소 수정

- `30df74e`: Root에 이미 게시된 Source 최초 오류를 Runtime `snapshot()`에서 latch한다. 이후 DNS/cleanup 실패가 primary를 바꾸지 않는다. 이미 다른 primary가 있으면 보존한다. 전역 모든 예외의 발생순서 판별기를 새로 만들지 않았다.
- 같은 Commit: primary 유무와 무관하게 collector traceback을 별도 보존한다. 3개 신규 회귀 테스트를 추가했고 기존 assertion은 변경하지 않았다.
- **Root Launcher 확인 결함:** blocking dnsmasq READY 대기 후 최신 Runtime health 재검증 없이 DNS probe를 시작했다. 이번 증거에서 시작 요청은 최초 TCX 오류보다3.672681초 늦었다. 전체 시작 차단 오류는 아니지만 실패 후 불필요한 트래픽 시도를 막아야 한다.
- 원본 소비된 `root-trial.py`를 수정하지 않고 **미승인 복구 copy**에 `observe_service_health` 및 현재 authenticated ready 검증을 `dns_probe.start()` 직전에 추가했다. 실제 health 함수를 이용한 AST guard 검증에서 실패/미인증은 spy조차 시작하지 않고 정상 상태만 통과했다. Root 전체 script/서비스/실제 DNS를 실행한 테스트가 아니다. [복구 patch](evidence/root-exit2-20261103/root-trial-dns-readiness.patch).

이 수정은 최초 오류 은폐와 실패 이후 DNS 시작을 해결한다. **13.60초 Control 송신 공백 자체를 해결한 것으로 판정하지 않는다.** 현재 보안·Model Admission·API 상한·정책 검사·Namespace·Cleanup을 유지한다. 추가로 확정된 회귀 원인이 없어 추정 성능 튜닝이나 과거 전체 코드 복원은 하지 않았다.

## 7. 종료 증거와 미검증 유지

TCX STOP 송신완료 후 Root가 VALIDATED_STOP을 관측하기까지약6.192초였다. Runtime의 기존5초 ACK bound 뒤 Root 로컬 Seal/최종 전송 실패가 이어졌다. TCX STOP ACK와 Runtime Cleanup은 **UNVERIFIED**다. Root Audit의 한정된 소유 자원 정리와 DNS Helper CLOSED·최종 Counter·STOP ACK는 별도 범위 결과이며 전체/전역 Cleanup으로 확대하지 않는다.

현재 일반권한 Snapshot의 과거 PID/Unix socket 부재는 과거 종료 시점의 Cleanup 증명을 대신하지 않는다. 새 privileged BPF/Socket/backup 검사는 실행하지 않았다. 과거 UNKNOWN/UNVERIFIED/FAILED, Legacy Ledger81행, 설치8경로 SHA/inode/mtime, 기존 Rollback 및 성공178파일은 보존한다.

## 8. 비권한 회귀·재현 빌드

이번 Root Exit2 수정 코드 `30df74e`에 대해 Workspace **883 PASS**, 독립 Export **883 PASS**, no-live guard 위반0, Source 불변을 확인했다. 초기 Workspace는882 PASS/1 FAIL(기존 DNS 실경과6초 wait 초과)이었고 동일 코드의 단독 재검증 및 전체 재검증이 통과했다. 그 간헐 원인은UNKNOWN이며 결과를 삭제하거나 대기값을 변경하지 않았다.

이번 성공본 비교 이후 ControlTransport·TCX failure cleanup·receive diagnostics·primary latch를 다시 실행: **34 PASS /32.07초**, no-live guard 위반0. 빈 DATA/Control 생존, bounded Queue, 잘못된 Peer/Clock/Replay 거부, Worker 저장 지연, STOP ACK 누락/지연, 오류 보존을 검증했다. **실제 cgroup 환경의13초 송신 정지 재현 성공을 뜻하지 않는다.** GUI·SOCRuntime·Mock API·Queue·복구는883/883 회귀에 포함됐다.

Native6개/legacy/Supervisor/Wheel의 Workspace A/B 및 독립 Export **3방향 byte-identical**을 확인했다. Wheel SHA `2c4dc1675c8f93a7baaa19ad1769ac6ab51ce42a5965506c56b0e0b4e06b9896`. Native는 compile/BTF 파싱만 수행했고 Kernel BPF load는 없다. Ruff Check/Format 및 Diff Check 통과. 비교 후 운영 Source 변경이 없어 같은 전체 회귀/빌드를 불필요하게 반복하지 않았다.

근거: [전체 검증](evidence/root-exit2-20261103/validation-final.json), [재현 빌드](evidence/root-exit2-20261103/reproducible-builds.json), [이번 guard](evidence/historical-native-comparison-20261103/guard.json), [프로토콜 회귀](evidence/historical-native-comparison-20261103/protocol-regression.log).

## 9. 현재 복구 판정과 남은 조건

- 과거 제한 Native E2E 및 별도 PCAP+실제 API 성공 증거: **재확인됨**.
- 최초 오류·소스·함수·오류 전달 경로: **복원됨**.
- 메시지 공백: **PRODUCER_NOT_SENDING**; Commit 수준의 회귀 인과관계 및 scheduling 근본 원인: **UNKNOWN**.
- 최소 오류 보존·후속 DNS 시작 guard: **VERIFIED_OFFLINE**, 설치/새 Root Binding 적용 **NOT_EXECUTED**.
- 현재 실패의 전체 Cleanup 및 동일 Session 전체 Live E2E: **UNVERIFIED**.
- 다음 전체 Live 시험을 안전하게 재개할 수 있다는 판정: **BLOCKED 유지**. 예상 원인을 고쳤다고 가정해 자동 재실행하지 않는다.

향후 권한이 필요한 현재 소유 자원 검사와 정확한 Source/Artifact/Session 재검증이 필요하다. 필요한 실제 실행은 별도의 유효한 Root·Native·DNS·R1 승인, 사용자 Scope 확인/sudo, 봉인된 ELIGIBLE 작업별 모델 승인, 별도 API 호출·비용 승인 범위 안에서만 가능하다. 이번에는 새 승인 패키지/영수증/예약을 생성하지 않았다. 기존 2초·5초 계약, 자원 상한과 Audit 보존은 그대로다.
