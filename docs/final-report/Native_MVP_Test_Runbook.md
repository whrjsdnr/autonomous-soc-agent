> 2026-11-02 야간 복구 갱신: 이 문서의 시험 수치와 경로는 해당 시점의 기록이다. 현재 실행 안내와 미완료 항목은 [One Command Guide](One_Command_Operation_Guide.md), [Full E2E RCA](Full_E2E_Blocker_RCA.md), [Readiness](Full_E2E_Integration_Readiness.md)를 우선한다. 과거 패키지는 재실행하지 않는다.

# 대상 저장소에서 실행하는 명령과 600초 제한 시험

이전 bbaeccd 시험은ReceiveTimeout으로실패했고소비된Session은재실행금지다. 수정코드2cfcf7e의새검토패키지/profile을준비중이다. 아래새경로는최종검증/준비완료확인후사용한다. [실제실패와수정](Final_MVP_Native_Result.md)을먼저확인한다.

현재 배치: 기존 루트 사용자 소스는 보존하고, 검증된 운영 코드는 `releases/research-mvp` Worktree에 있다. 루트의 오래된 `.venv`를 사용하지 않는다. 아래 명령은 모두 대상 루트에서 시작한다.

## 1. 터미널 준비

```bash
cd ~/kdt-linux/autonomous-soc-agent
source releases/research-mvp/.venv/bin/activate
export SOC_AGENT_HOME='/home/geonug/kdt-linux/autonomous-soc-agent/.git/research-mvp-control-validation-retest-20261102T100229Z/native-cli-profile'
command -v soc-agent
soc-agent --help
```

첫 출력은 대상 경로의 `releases/research-mvp/.venv/bin/soc-agent`여야 한다. 여섯 명령 setup/start/status/stop/gui/doctor가 지원된다. 매번 새 터미널에서는 이 준비를 다시 한다.

## 2. 승인 없이 가능한 점검

프로젝트 담당자가 아래 새 Native profile을 준비한 뒤 실행한다. `setup`을 반복하거나 기존 Session을 교체하지 않는다.

```bash
soc-agent doctor
soc-agent start --preview
soc-agent status
```

Preview는 Root 설치·Capture·트래픽·영수증 소비를 하지 않는다. Namespace 내부 권한 검사는 승인 전 BLOCKED일 수 있다. doctor의 WARN/BLOCKED는 그 이유를 확인한다. Preview 통과는 실제 실행 승인이 아니다.

## 3. 정확한 새 승인 이후에만 실제 시험

검토 패키지: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/research-mvp-control-validation-retest-20261102T100229Z/native/approval-package-final.md`.
최신 Git/Source/Artifact/Manifest/Session/Namespace/Ledger 일치와 유효한 정책·R1·Root·Native·트래픽 승인 후 사용자의 실제 전경 터미널에서 실행한다.

```bash
soc-agent start --gui
```

기존 Launcher가 Scope를 보여주면 사용자가 직접 확인하고 sudo 비밀번호를 직접 입력한다. 비밀번호는 채팅이나 파일에 쓰지 않는다. 임의로 sudo soc-agent를 실행하지 않는다. 자동 재실행은 금지하며 소비한 Session을 다시 시작하지 않는다.

전체 실행은 설치·시작·STOP·정리 포함 최대600초다. 기존 검증된 시간 계약을 재사용하여 순수 수집 목표360초, owner STOP400초, Drain460초, Root TERM530초/KILL560초, ordinary worker TERM590초/KILL595초를 유지한다. 순수600초 수집을 주장하지 않는다. 사용자 인증 대기 시간은 Native 실행 입장 전이며, 입장 때 최소75분 승인 유효기간을 확인한다.

별도 터미널에서 같은 준비를 한 뒤:

```bash
soc-agent status
soc-agent gui
```

GUI 종료는 Backend 중지가 아니다. GUI를 닫고 같은 `soc-agent gui`로 재연결한 뒤 Collector/Session Identity가 유지되는지 본다. 조기 중지가 필요하면:

```bash
soc-agent stop
soc-agent status
```

최신 사용자 요청은 RF/LR과 실제 LLM Plan·Assessment까지 확인하는 통합 시험이다. RF/LR은 봉인된 ELIGIBLE 작업별 별도 승인 후 기존 Worker가 실행한다. 기존 SOCRuntime의 SCRIPTED 경로와 실제 API 경로를 구분한다. 실제 API는 기존 RetainedAPIClient를 통해 이번 Session에서 생성된 Network Incident의 Evidence Revision을 고정하고 독립 승인 후 최대2회/총$0.05/요청20초/출력4096토큰/재시도0으로 실행하는 승인안을 준비한다. 실제 LLM을 자동으로 호출하는 start 옵션은 현재 없으며, 이 단계를 단일 start만으로 모두 실행한다고 주장하지 않는다. 새 API 승인·입력 Binding 확정 전에는 호출하지 않는다. Host Authentication Live와 DNS9는 검증 계약 미완료로 차단/미검증 상태를 표시한다. 값이 없다는 이유로 Mock 결과를 채우지 않는다.

## 4. 종료 후 보존 결과 확인

```bash
soc-agent status
soc-agent gui
```

동일 profile로 저장된 현재 Session의 Packet/DNS/Window/Eligibility/Queue/오류/STOP·Cleanup을 확인한다. 과거 Session의 Prediction·Incident와 섞지 않는다. 재시험은 새 Binding과 새 승인이 필요하며 start를 반복하지 않는다. 실제 측정 결과는 검토 디렉터리의 execution 증거에서 확인한다. 아직 실행되지 않은 시험의 결과는 생성하지 않는다.

## 5. 고정 Scope와 실패 기준

기존 Namespace `net:[4026532232]`, lo/Ingress. TCP 127.0.0.1:18080/source18081·18082, 최대2 Helper 시작/총4연결, 기존 고정 요청·응답 및35초 연결 간격; 두 Helper 시작 간격 최소180초. READY 전 트래픽 금지. DNS는 로컬 dnsmasq127.0.0.53:53, 기존 고정 UDP2/TCP1, 임의 포트·외부 연결 금지.

Collector128MiB/CPU25%, Runtime512MiB/CPU50%, DNS Helper512MiB/CPU10%, TCP64MiB/CPU10%, dnsmasq64MiB/CPU10%, Queue32. Runtime256MiB/Root Audit64MiB는 저장량 점검 상한이며 하드 디스크 Quota가 아니다.

성공에는 READY, 실제 이벤트, Window Seal/Attestation, DNS Transaction, 기존2초 Helper·5초 Control 계약, Queue/Drop/SourceGap, GUI 재연결, TCX STOP ACK, Helper CLOSED/최종Counter/ACK, Root 소유 Cleanup, Runtime Cleanup 증거가 각각 필요하다. Exit0만으로 성공 처리하지 않는다. 최초 오류와 후속 Cleanup 오류를 분리하고 실패 시 자동 재실행하지 않는다.

과거 Program1145/Heartbeat 송신 공백 원인은 UNKNOWN, 과거 Runtime/Global Cleanup UNVERIFIED와 FAILED/false는 보존한다. 현재 시험이 성공해도 소급 변경하지 않는다. 실제20분·1시간 Native 연속 운영, 실제LLM Assessment, Host Authentication IF 전체E2E, DNS9 원본학습 계약과 상용 무인운영 안정성은 미완료다.

## 통합 조사 API의 독립 계약

기존 OpenAI gpt-5-mini, https://api.openai.com/v1/chat/completions를 유지한다. 공식 문서를2026-11-02에 조회했으며 입력$0.25/출력$2.00 per1M tokens, deprecated/2026-12-11 shutdown 예정이다. 계정 가용성은 미확인이고 자동 모델 변경은 금지한다. 최대2호출(Plan1/Assessment1), 출력4096토큰/호출,20초/호출,자동재시도0,총비용$0.05. 입력 예약 상한은 각요청60000토큰(기존Adapter의 최소화된UTF-8본문+schema+4096 overestimate)으로 제한하면 총예약 최대$0.046384다. 실제 요청 직전 계산값이 이를 넘으면 호출하지 않는다. Usage누락/Timeout은 결과·비용UNKNOWN으로 보존하며 재계획은 이번2호출 범위에서 제외한다. 비밀번호/API Key를 출력하지 않는다.

가격 근거: [OpenAI 모델 문서](https://developers.openai.com/api/docs/models/gpt-5-mini). 수명 근거: [OpenAI Deprecations](https://developers.openai.com/api/docs/deprecations).
