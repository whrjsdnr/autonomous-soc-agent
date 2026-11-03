# 사용자 직접 실행 안내 — Installed Research MVP

## 현재 장비에서 실행

```bash
cd ~/kdt-linux/autonomous-soc-agent
export PATH="$HOME/.local/bin:$PATH"
hash -r
soc-agent setup
soc-agent doctor
soc-agent start --preview
soc-agent start --gui
```

`setup`은 이미 설정된 profile을 다시 만들거나 실행하지 않는다. `doctor`와 `--preview`도 Root·Capture·DNS·모델·API를 시작하지 않는다. 옛 가상환경이 PATH 앞에 있으면 `~/.local/bin/soc-agent`를 직접 사용한다. 주 저장소의 옛 `.venv/bin/soc-agent`는 변경하지 않았다.

`start --gui`가 단일 실행 진입점이다. SHA와 Session UUID를 입력하지 않는다. 등록된 고정 Release를 확인하고, 준비된 미소비 Session이 있으면 사용한다. 정상 종료·소유 자원 Cleanup이 검증된 이전 실행이면 새 UUID·Queue·Incident·Audit·실행 초안을 자동 준비한다. 미사용 초안의 정책 제안이 만료되면 새 초안을 준비하지만 **정책 활성화와 위험 수용은 여전히 사람의 결정**이다.

A의 정확한 Scope/R1·정책 갱신 내용을 전경 터미널에서 확인하고 sudo 비밀번호를 OS 프롬프트에 직접 입력한다. 비밀번호를 채팅이나 GUI에 입력하지 않는다. 이 문서와 profile 준비는 실제 실행 승인이 아니다.

## 모델과 API 승인

Collector READY 이후 GUI의 Continuous 화면에서:

1. `Review sealed RF/LR jobs`: 이미 봉인된 ELIGIBLE 작업을 한 화면에서 검토한다. 작업마다 기존 ApprovalManager의 독립 Action 기록을 만든다. 미래 입력 자동 승인은 없다.
2. 실제 승인된 Prediction으로 Incident·고정 Evidence Revision이 생기면 `Review LLM Plan / Assessment`: Provider·모델·횟수·비용·Timeout을 확인한다.

현재 초안은 RF/LR 최대16회/최대2개 봉인 작업, API Plan·Assessment 합계 최대2회, 요청당20초·출력4096토큰·자동 재시도0회다. API 실제 승인 상한은 요청/GUI에 표시되는 값이며 현재 새 초안은 $0.05다. 과거 사용자 $1/20회 상한은 이 어댑터의 두 요청 계약을 확대하지 않는다. Usage 미수신 비용은 UNKNOWN이다. Provider 가용성과 가격 확인 전 실제 호출하지 않는다.

입력이 아직 없으면 승인 대기는 정상 상태다. 승인되지 않은 모델 작업은 실행하지 않으며 PENDING/POISON을 전체 처리 완료로 표현하지 않는다.

## 상태·조회·종료

별도 터미널에서:

```bash
soc-agent status
soc-agent status --sessions
soc-agent gui
soc-agent gui --session 1
soc-agent stop
soc-agent status
```

Session 0은 현재 실행, 양수는 보존한 이전 profile의 목록 인덱스다. GUI Continuous → `Sessions`에서도 경로·UUID 입력 없이 선택한다. 과거 Session 조회가 수집이나 모델/API를 재실행하지 않는다. GUI 종료·재연결은 Backend 종료가 아니다. `stop`은 기존 STOP·Drain·Cleanup 경로를 호출하고 미처리 작업을 공개한다.

## 다른 장비/profile의 최초 등록

이미 검증·동결된 기존 Native review를 한 번 등록한다.

```bash
soc-agent setup --installed-release /absolute/path/to/frozen-review --home /private/profile
```

실행 초안은 저장소의 기존 `.git` 증거 영역에 자동 준비한다. 설치된 Source/Artifact·실행 스크립트·모델·Dependency·Root Manifest·Namespace Lease·Ledger는 기존 검사로 검증한다. Root 설치는 최초 setup이 아닌, 승인·sudo 이후 기존 Launcher가 수행한다. 개발용 일회성 `--native-review`와 Replay 설정 경로도 유지한다.

## 명시적 갱신·Rollback

```bash
soc-agent setup --installed-release /absolute/path/to/new-verified-review --update
```

새 Release 후보를 검증하고 새 미승인 Session을 준비한 후 profile과 Release 참조를 교체한다. 이전 참조/profile은 `release-history/`, 기존 Session profile은 `sessions/`에 보관한다. 이전 Root 설치본·Rollback·Audit·Queue는 수정하지 않는다. 되돌릴 때도 보존한 이전 검증 review를 명시적으로 `--update`하여 **새 Session**을 만든다. 이전 승인 영수증이나 소비된 Session으로 돌아가지 않는다.

관리 CLI도 재현 Wheel을 사용자 전용 경로에 설치한다. `scripts/install_research_manager.py --build-evidence <검증결과경로>`는 Workspace/Export 결과와 재현 빌드 증거를 확인하고 기존 Controller Python 준비 경로를 사용한다. 네트워크 없는 `uv pip install --offline --no-deps`만 사용하며 Root 권한은 없다. 갱신에는 별도 `--update`가 필요하다. 이전 관리 Release는 삭제하지 않는다.

## 실패 대응

실제 실행 실패·Cleanup 미검증·종료 코드 미확보 후에는 새 Session 자동 재시도를 차단한다. 기존 first error, STOP ACK, Helper CLOSED·최종 Counter, Root/Runtime Cleanup 증거를 확인하고 새 정확한 검토를 준비한다. Timeout 증가, SHA 해제, Root 우회, 미승인 추론으로 해결하지 않는다. Native20분/1시간, 실제 LLM Assessment와 최근 서비스 모델 실패의 해결 여부는 별도 Live 시험 대상이다.

## 이번 준비 검증

관리 코드1825442, Wheel `2d3b2d6076b423af01048e857ab009797ba67b7609ca57de9b742724ea2f0b97`. Native backend는 별도 고정 Release2064af1이다. Workspace1545 PASS/1 SKIP, 독립 Export 변경 경로296 PASS, 집중71 PASS, Native·Supervisor·Wheel 3-way 재현 빌드 일치. 실제 설치 CLI의 Replay Start→Status→Stop/Cleanup과 실제 GUI Entry Point 두 번의 재연결을 검사했다. 이 준비 결과는 신규 Native/API 성공이 아니다.

최종 실제 시험 검토서: `.git/operator-ux-validation-20261103/live-approval-package.md`. A/B/C는 독립 결정이며 실제 승인·인증 이전에는 실행하지 않는다.
