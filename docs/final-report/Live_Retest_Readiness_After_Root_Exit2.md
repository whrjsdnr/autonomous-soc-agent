# Root Exit2 수정 후 전체 Live E2E 재시험 준비

2026-11-03. 사용자의 후속 실제 재시험 요청에 따라 기존 draft/verify_review/CLI를 재사용해 **새 미승인 Session**을 준비했다. 앞선 RCA 비교 단계에서는 새 패키지를 만들지 않았고, 이번 문서는 그 이후 준비를 구분한다. Root·Native·DNS·모델·API 실제 실행은 아직0이다.

## 고정 후보

- 코드 수정30df74e, 검토 Frozen Git3046260(문서 포함). 기존 사용자 변경127개는 별도 보존.
- 새 Runtime Session121cba1a-757a-4c0c-8d0e-db9c1b6317be. 이전 실행 Store/Queue를 재사용하지 않는다.
- 검토서: `.git/root-exit2-retest-preparation-20261103T053700Z/native/approval-package-final.md`.
- [검증 결과](evidence/root-exit2-retest-preparation-20261103/readiness.json). Source/Artifact/Root Manifest/Session/Ledger/Execution pins 내부 검증 통과.
- 실제 CLI setup 및 `start --preview --gui` 통과. 결과 `PREVIEW_ONLY_REQUIRES_DIRECT_SCOPE_R1_AND_SUDO`, Namespace entered=false. 이는 실행 승인이나 실제 수집 성공이 아니다.
- 후보 만료2026-11-04 10:21:57 KST. 승인 기록/입장 시 상위 정책과 최소잔여시간을 다시 검증한다.

## 한 문서에서 검토할 독립 결정

|구분|정확한 한도|아직 필요한 조건|
|---|---|---|
|현재 자원 읽기전용 검사|기존 검사계획의 PID/Start Identity·전용NS Socket/TCX/BPF·Root백업 읽기만|명시적 검사Scope/사용자 인증; 잔류/검사실패 시 Native 시작금지|
|A Native·DNS·R1|1회/전체600초/수집360초 목표, net:[4026532232] lo/Ingress; TCP4연결, DNS UDP2/TCP1|새 정확한 Binding·R1 조건부위험결정·정책·Scope 확인·sudo|
|Root 설치|고정8경로 백업/검증, 정책·Runtime unit·DNS unit3개만 변경; 나머지5개 검증|새 Root 설치승인, 기존설치/Rollback보존|
|B RF/LR|최대2개 실제 봉인Job/총16회, VERIFIED Attestation/Network14 ELIGIBLE|실제 생성된 입력을 기존GUI에서 작업별 독립 결정; 미래자동grant0|
|C 실제 LLM|Plan1+Assessment1, 총2회/$0.05/요청20초/출력4096/재시도0|같은 Native Session Incident/Revision 고정, Provider/가격/예약검증 후 기존GUI 독립결정|

Collector128MiB/CPU25%/Tasks4, Runtime512MiB/CPU50%/Tasks32, DNS512MiB/CPU10%/Tasks4, TCP64MiB/CPU10%/Tasks4, dnsmasq64MiB/CPU10%/Tasks8, Queue32, 저장점검256MiB/64MiB를 유지한다. 기존 주소/포트/페이로드/간격은 검토서에 고정됐다. 외부Namespace 연결/Host인증로그/DNS9/자동재실행은 제외한다. 실행권한은 A/B/C 간에 공유되지 않는다.

## 확인된 수정과 남은 위험

- 게시된 TCX 최초오류 latch와 collector trace 보존: 수정/회귀 검증. Runtime 8줄 및 신규3테스트.
- dnsmasq READY 대기 후 현재 Runtime health/인증 READY 재확인: **이 새 Launcher copy에 반영**. 원본 소비Artifact는 불변.
- 직전13.60초 송신 시도중단의 근본 원인은UNKNOWN이다. 새 코드가 이를 해결했다고 주장하지 않는다.
- 직전 TCX STOP ACK 및 Runtime Cleanup은UNVERIFIED다. 과거상태를소급변경하지 않는다. 현재 privileged 잔류검사도아직미실행이며 이 조건을 건너뛴 start는 안내하지 않는다.
- 지금 판정: **BINDING_VERIFIED_EXECUTION_BLOCKED**. 실제 전체 E2E 성공판정은없다.

## 준비된 사용자 Entry Point (실제 실행 전 승인·검사·인증 필수)

```bash
cd ~/kdt-linux/autonomous-soc-agent
export SOC_AGENT_HOME=/home/geonug/kdt-linux/autonomous-soc-agent/.git/root-exit2-retest-preparation-20261103T053700Z/operator-home
releases/research-mvp/.venv/bin/soc-agent start --preview --gui
```

위 preview는 실제로 검증했고 실행권한을 생성하지 않는다. 이후 정확한 승인과 현재 자원검사가 통과한 경우에만 같은 terminal/profile에서 실제 Entry Point는 다음과 같다.

```bash
releases/research-mvp/.venv/bin/soc-agent start --gui
```

사용자는 직접 Scope/R1을 확인하고 터미널에서 sudo 비밀번호를 입력한다. 채팅/로그에 비밀번호를 입력하지 않는다. 모델과 API는 실제 입력이 생성된 후 같은 GUI의 기존 독립 검토 경로를 유지한다. `status`/`stop`도 같은 SOC_AGENT_HOME과 고정CLI를 사용한다. 승인 전 start/예약/정책활성화/영수증 발급·소비를 수행하지 않았다.

관련 분석: [과거 성공본 비교](Historical_Native_E2E_Regression_Comparison.md), [Root Exit2 최초오류](Full_Live_E2E_Root_Exit2_Recovery.md).
