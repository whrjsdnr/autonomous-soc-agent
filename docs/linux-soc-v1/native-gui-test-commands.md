# Native·RF/LR·기존 대시보드 테스트 명령

## 현재 사용 명령 · 2026-10-29 최종 갱신

아래쪽의 `next-native-gui-trial`은 이미 소비된 과거 시험이다.
그 `run-terminal.sh`를 재실행하지 않는다. 새 실제 Native 시험은 새 검토·인증이 필요하다.
최신 실제 시험은 Native360 / ELIGIBLE17 / RF·LR22 / Incident11을 확보했지만
53분대 Timeout으로 종료되어 1시간 운영 통과가 아니다.

현재 보존 결과를 새 CLI로 확인한다. 새 Capture·모델·API 호출 없이 읽는다.

```bash
cd /home/geonug/kdt-linux/soc-one-command-runtime
SOC_GUI_PROFILE=/home/geonug/kdt-linux/autonomous-soc-agent/.git/final-gui-operations-verification-20261029T061104Z/identity-recovery/onecommand-native-view
.venv/bin/soc-agent status --home "$SOC_GUI_PROFILE"
.venv/bin/soc-agent doctor --home "$SOC_GUI_PROFILE"
.venv/bin/soc-agent gui --home "$SOC_GUI_PROFILE"
```

Dashboard / Investigation에서 실측 latency·research assessment·완료된 읽기 전용 조사
단계를 확인한다. AI Analysis는 최신 검증 보고서를 자동 표시한다. Scripted 조사는
실제 API 조사로 표시하지 않는다. Authentication은 별도로 승인된 Host journald의
읽기 전용 Runtime이며, 이번 연결에서 실제 인증 이벤트1건을 확인했다. 해당 Runtime도
현재 정상 Stop했고 보존 이벤트를 표시한다. Native 시험의 인증 IF 추론은 0회다.

System의 Capture Quality는 마지막 봉인 Window의 own-hook 증거다. Root Audit의
Cleanup VERIFIED와 Runtime STOP ACK UNKNOWN은 독립적으로 남아 있다.
DNS는 이번 TCP 전용 시험에서 수집하지 않았다. DNS9 계약은 계속 INCOMPLETE다.

새 Offline profile 시작·중지는 [단일 CLI 사용법](one-command-runtime.md)을 따른다.
GUI 종료로 외부 Runtime을 중지하지 않는다.

## 과거 시험 기록 · 아래 실행 패키지는 재사용하지 않음

작업 브랜치는 `feat/continuous-runtime`, 작업 경로는
`/home/geonug/kdt-linux/continuous-soc-runtime`이다. 사용자 main 작업 경로
`/home/geonug/kdt-linux/autonomous-soc-agent`의 미커밋 변경은 보존했다.
아래 GUI는 일반 사용자로 실행한다. GUI 실행은 Root 서비스 시작이나 모델 실행이 아니다.

## 지금 확인 가능한 실제 보존 결과

WSLg 사용자 터미널에서 다음 명령을 실행한다. 새 패킷·모델·API 호출 없이 기존
대시보드에서 Native 40건과 별도로 승인·분석한 RF/LR 2건을 확인할 수 있다.

```bash
bash /home/geonug/kdt-linux/autonomous-soc-agent/.git/operations-final-stabilization-20261029T052719Z/open-preserved-gui.sh
```

Dashboard에서 source `REAL_NATIVE`, Collector `STOPPED`, 수집 metadata 40건을 확인한다.
Security Events에서 RF/LR 행을 선택하면 AI Analysis의 원본 Incident·조사·Audit를 연다.
Continuous 화면에는 Queue POISON 1/PENDING 1과 Collector Cleanup이 독립적으로 표시된다.
System Health와 Continuous 화면의 Controller 오류는 이전 시험의 `database is locked`다.
수집 후 분석한 결과를 선택했으므로 실시간 Prediction 수는 0이며, 선택된 보존 결과는 2건이다.
조사는 SCRIPTED, 이 Incident의 실제 API 호출은 0회다. 정상 TCP를 확인된 공격으로 표시하지 않는다.

이미 같은 데이터 디렉터리의 GUI가 열려 있다면 그 창을 종료하고 다시 실행한다.
과거 버전으로 열어 둔 창은 자동으로 새 코드로 바뀌지 않는다.
GUI를 닫아도 Backend 서비스의 Stop을 요청하지 않는다.

## 다음 실제 Native·모델·GUI 시험

다음 패키지는 **준비본**이다. 기존 소비된 승인을 재사용하지 않는다.
새 고정 Scope/R1 검토와 직접 사용자 확인·sudo 인증이 먼저 필요하다.
상위 유효기간이 지나거나 Source/설치/Lease/Ledger가 바뀌면 시작하지 않는다.

```bash
cat /home/geonug/kdt-linux/autonomous-soc-agent/.git/operations-final-stabilization-20261029T052719Z/next-native-gui-trial/approval-package-final.md
```

Scope: `net:[4026532232]`, `lo / Ingress`, Collector 최대 3,600초(시작·종료 포함),
고정 설정 파일 4개, Collector/일반 Runtime 각각 한 번 시작, 자동 재실행 없음.
Collector 128MiB/CPU25%/tasks4, 일반 Runtime 512MiB/CPU50%/tasks32,
Queue32/저장량256MiB 관측 상한이다. 기존 Helper 최대19번/총 TCP38연결,
고정 포트 18080/18081/18082, 내부35초 간격, DNS·외부망·API는 0이다.
마지막 Window에는 새 시험 TCP를 넣지 않고 종료 전 승인된 분석을 drain한다.
3,600초 전체가 Kernel attach 시간이라는 보장은 없으므로 실제 수집 시간을 별도로 기록한다.

승인된 Scope를 검토한 뒤 **실제 사용자 터미널 A**에서 실행한다.

```bash
bash /home/geonug/kdt-linux/autonomous-soc-agent/.git/operations-final-stabilization-20261029T052719Z/next-native-gui-trial/execution/run-terminal.sh
```

터미널에 표시되는 목적·권한·Namespace·자원·미해결 위험을 확인하고 해당 Scope/R1에
동의할 때만 `yes`를 입력한다. 이어 sudo가 터미널에서 직접 인증한다.
SHA나 비밀번호를 채팅에 입력하지 않는다. 인증 전 상태를 STOPPED로 반복 출력하지 않는다.
Namespace 내부 check와 자동 무결성 검증에 실패하면 후속 Capture를 시작하지 않는다.

`RUNNING_AUTHENTICATED_PRODUCER` 표시 이후 **사용자 터미널 B**에서 기존 GUI를 연결한다.

```bash
bash /home/geonug/kdt-linux/autonomous-soc-agent/.git/operations-final-stabilization-20261029T052719Z/next-native-gui-trial/execution/open-gui.sh
```

GUI Dashboard/Continuous에서 RUNNING, source REAL_NATIVE, Packet metadata, Window,
Queue/Drop/Heartbeat를 확인한다. Native 시작은 터미널의 승인된 서비스 경로에서만 한다.
GUI Start로 별도 Native 프로세스를 띄우지 않는다. GUI를 종료·재연결해도 Collector는 유지된다.

### 모델을 포함하는 검증

Capture 승인이 RF/LR Action 승인을 대신하지 않는다. 봉인된 job이 생긴 뒤
**사용자 터미널 C**에서 아래 명령을 실행한다.

```bash
bash /home/geonug/kdt-linux/autonomous-soc-agent/.git/operations-final-stabilization-20261029T052719Z/next-native-gui-trial/execution/approve-sealed-models.sh
```

현재 존재하는 불변 job/Session/Window/Flow/적격성/RF·LR 호출 수를 표시한다.
그 목록에 동의할 때만 `yes`를 입력하면 기존 Action-specific ApprovalManager가
해당 입력·출력·구현에 대한 영수증을 발급한다. 이후 Window는 자동 승인하지 않는다.
대략 30분과 57분에 이미 봉인된 입력을 묶어 확인할 수 있지만, 아직 준비되지 않은
job은 승인하지 않는다. 명령이 "No new sealed ELIGIBLE jobs"라면 승인·추론 없이 종료한다.
전체 상한은 적격 job19개/RF·LR38회이며 부적격 입력은 계속 제외한다.
기존 grant/출력/실패 시도는 재사용·재실행하지 않는다.

RUNNING 중 승인은 기존 AI Worker가 소비한다. STOPPED 및 Cleanup VERIFIED 후 명시적으로
승인한 경우에는 보존 입력 분석으로 구분하며 과거 Queue 상태를 수정하지 않는다.
GUI에서는 Prediction·Incident·SCRIPTED 조사·읽기 전용 도구·Audit를 확인한다.
실제 외부 LLM 호출이나 DNS9 실행은 이 시험에 포함하지 않는다.

### 상태 확인·사용자 Stop

실행 중 화면/health 조회는 SQLite writer와 경합하지 않는 관측 명령을 사용한다.

```bash
SOC_TRIAL=/home/geonug/kdt-linux/autonomous-soc-agent/.git/operations-final-stabilization-20261029T052719Z/next-native-gui-trial
SOC_PY=/home/geonug/kdt-linux/autonomous-soc-agent/.venv/bin/python
PYTHONPATH="$SOC_TRIAL/export/src" "$SOC_PY" -m soc_agent.cli continuous observe "$SOC_TRIAL/future-runtime"
```

필요 시 사용자 Stop은 다음과 같다. Stop은 owner STOP/ACK와 drain을 요청하는 것이며,
명령 반환만으로 Cleanup 성공을 판정하지 않는다.

```bash
SOC_TRIAL=/home/geonug/kdt-linux/autonomous-soc-agent/.git/operations-final-stabilization-20261029T052719Z/next-native-gui-trial
SOC_PY=/home/geonug/kdt-linux/autonomous-soc-agent/.venv/bin/python
PYTHONPATH="$SOC_TRIAL/export/src" "$SOC_PY" -m soc_agent.cli continuous stop "$SOC_TRIAL/future-runtime"
```

종료 후 터미널 A가 끝나고 Collector/Worker 정지·ACK·Queue 상태·Audit·소유 Map/Link/Socket
Cleanup을 확인한다. `execution/first-error.json`, `root-finished.json`, `runtime-final.json`,
`root-terminal-exit.json`이 최종 증거다. Cleanup VERIFIED와 Queue 완전 처리는 별개다.
오류·POISON·승인 대기는 삭제하거나 성공으로 바꾸지 않는다.
실패한 실행 스크립트는 다시 실행하지 말고 새 증거와 Binding으로 원인을 확인한다.

## 이번 점검 결과와 남은 범위

READY 세대 누락, SIGTERM owner STOP/ACK, DB health 경합, 모델 승인 대기의 과다 쓰기,
대시보드의 legacy STOPPED/모델 미연결, 원본 Incident 선택, 상태 보고서 크기 한도를 수정했다.
Controller 오류를 별도 증거 경로로 표시하고 live/보존/Replay 결과를 구분한다.
정확한 테스트·빌드·Git·Artifact 값은 같은 증거 폴더의 `final-verification.json`과
`next-native-gui-trial/final-artifact-identity.json`에서 확인한다.

현재 실제 시험은 약348.55초 수집·40 Native 이벤트·봉인2·ELIGIBLE2까지 확인했다.
첫 적격 입력의 RF/LR2·Incident1·Audit·SCRIPTED 조사는 수집 종료 후 분석했다.
따라서 **1시간 운영/실시간 모델 전체 성공은 아직 미검증**, 판정은 PARTIALLY_VERIFIED다.
과거 Program1145 UNKNOWN/전역Cleanup UNVERIFIED/FAILED·false 기록은 보존한다.
