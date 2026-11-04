# Authentication 복구 진행 및 시연 예비 경로 — 2026-11-04

## 현재 판정

**PARTIALLY_READY. 실제 Host 진단 미실행, Full Live E2E BLOCKED.**
운영 코드 `a5441a9` / 보고서 `47a31f7` 이후 운영 Source는 변경하지 않았다.
18:00 KST Live 목표를 유지한다. 현재 사용자 지시는 유효한 별도 승인 확인을 요구하며,
그 자체로 Host·Root·모델·API 실행을 승인하지 않는다. Host 읽기 1회 승인 질문을 제시했다.
답변 전에는 실제 Journal을 조회하지 않는다.

18:00 이후 새 Live 시험은 시작하지 않는다. 이미 진행 중인 승인 실행은 원래 STOP·Cleanup
계약을 지킨다. 시간 목표를 정책 유효기간, 실행 예약 또는 성공 보증으로 해석하지 않는다.

## Host 진단 검토서와 누락 항목

기존 `evidence/authentication-source-rca-20261104/host-read-review.json`을 직접 재검증했다.
Source 682개와 Manifest SHA, 재현 Wheel 3개의 SHA가 일치한다. Wheel 내 Python 633개도
검증 Source와 일치한다. 코드 `a5441a9`, 당시 문서 HEAD `47a31f7`, Worktree clean을 확인했다.

고정 명령은 다음과 같다. 이번 작업에서는 실행하지 않았다.

```bash
/usr/bin/journalctl --no-pager --quiet --output=json \
  --output-fields=__CURSOR,__REALTIME_TIMESTAMP,_MACHINE_ID,_COMM,_EXE,_UID,SYSLOG_IDENTIFIER,PRIORITY,MESSAGE \
  --lines=+16 SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 + _COMM=sshd
```

기존 Collector의 `poll(cursor=None, limit=16)`, PAM failure 설정 true가 정확히 이 명령 하나를
생성하는 것을 Mock으로 확인했다. Unit·날짜 필터는 없다. 15초는 기존 명령 Timeout이며,
연속 수집 15초 또는 해당 15초에 발생한 이벤트만 조회한다는 의미가 아니다.
출력 수용 상한 4MiB는 명령 완료 후 검사이며 디스크 Quota가 아니다.

검토서는 `PENDING_HUMAN_APPROVAL_NOT_AN_EXECUTION_RECEIPT`다.
**실행 승인자·결정·유효기간 및 Native Session/설치 Release 실행 권한은 없다.**
Source·Wheel이 고정된 독립 진단 후보이며 과거 Live 권한을 승계하는 문서가 아니다.
오늘 18:00까지의 Host 진단 1회만 승인받도록 제안했으며 답변 없이 활성화하지 않았다.
승인 후 고유한 진단 증거에 인간 결정, 검토서 Digest, 코드·Wheel, 실제 시각을 연결해야 한다.
원본 stderr를 출력·영구 보존하지 않는 기존 계약을 유지하고 errno·returncode·고정 분류를 기록한다.

## RCA와 Cleanup

기존 `Native_Startup_Recovery_Report.md`의 정정된 시간축을 유지한다.
최초 예외는 실행 당시 `AuthenticationLifecycle._start_owned`의 257행 READY_TIMEOUT이다.
SOURCE_UNAVAILABLE은 STOP·Timeout 뒤에 기록됐다. 내부 Source 실패 시각과 명령 Exit Code가
없어 접근 실패가 원인인지, STOP에 따른 명령 종료가 후속 결과인지는 **UNKNOWN**이다.
READY는 SQLite RuntimeStore observation으로 전달되며 별도 READY IPC Socket 경로가 아니다.
초기 2.325초 저장 지연은 자식 생성·READY 대기 이전이므로 5초 자식 예산 소모와 동일시하지 않는다.

현재 기록된 PID 3개는 부재다. Collector·DNS는 inactive, Runtime은 failed이며 MainPID는 모두 0이다.
이는 Root TCX·BPF·소유 FD·Socket 잔류 부재의 전체 검증이 아니다.
과거 Authentication Child Cleanup VERIFIED, Runtime Cleanup UNVERIFIED, Global Kernel UNKNOWN을 유지한다.
권한이 필요한 잔류 읽기 검사는 별도 Scope 승인 후 수행한다.
Root 8경로 SHA·inode·mtime, Ledger 81행 및 실패 증거를 보존했다.

## 비권한 추가 검증

| 조합 | PASS | 실제 Driver 경과 |
|---|---:|---:|
| Workspace, 일반 디스크 임시 저장 | 112 | 85.95초 |
| Workspace, tmpfs 임시 저장 | 112 | 55.80초 |
| 독립 Export, 일반 디스크 임시 저장 | 112 | 82.93초 |
| 독립 Export, tmpfs 임시 저장 | 112 | 55.83초 |

같은 112개를 네 환경에서 검사했으므로 448개 독립 테스트라고 합산하지 않는다.
READY·Heartbeat·Source 실패, Parser·Queue·Host Window, IF 작업별 Admission·Mock Prediction,
Incident·SOCRuntime, GUI 승인·재연결, STOP ACK·Cleanup, Replay 종료 경로를 포함한다.
Guard 위반은 0건이다. tmpfs는 테스트 DB·임시파일 영역이며 Source는 기존 Workspace·Export 경로다.

동일 Source의 기존 전체 Workspace·Export 각각 1,066 PASS와 Native·Supervisor·Wheel 재현 빌드
결과를 재사용했다. 불필요한 재빌드로 Binding을 바꾸지 않았다.
Ruff check, format 1,627개 파일, Diff 검사를 통과했다.

## 시연 예비 경로의 실패와 해결

과거 실제 API 성공 결과를 다른 경로로 복사해 GUI로 열자 `API_RECEIPT_SCOPE_MISMATCH`가 발생했다.
`security_ai/api_investigation.py:449`는 승인 당시 output_directory와 조회 경로를 비교한다.
이는 Authentication 장애가 아니며 무결성 검사를 완화할 근거가 아니다.
복사본의 실패 결과를 보존하고, 원본 경로를 기존 `verify_result`·`verify_api_receipts`로 조회했다.
그 결과 GUI 표시·종료·재연결 2회가 통과했다. 원본 파일 SHA 불변도 확인했다.

검증 범위는 실제 Tk GUI Entry Point의 저장 보고서 attach, Prediction 2행, Incident,
Audit VERIFIED, 창 종료·재열기다. 화면은 `IMPORTED_VERIFIED_REPORT`, `OFFLINE_PCAP`,
`REAL_API`, `not live capture`를 표시한다. REAL_API 2회는 2026-10-27 보존 실험의 수치다.
**이번 신규 API·모델·Host·Native 실행은 모두 0회다.**
이 검증을 새로운 Replay 통합시험 2회 또는 Live E2E 성공으로 해석하지 않는다.

## 검증된 예비 화면 명령

```bash
cd /home/geonug/kdt-linux/soc-auth-startup-recovery-20261104
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/src" \
  /home/geonug/kdt-linux/autonomous-soc-agent/releases/research-mvp/.venv/bin/python \
  -m soc_agent.gui \
  --analysis-result /home/geonug/kdt-linux/autonomous-soc-agent/.git/ai-pipeline-integration-20261027-1/actual-api-e2e \
  --data-directory /home/geonug/kdt-linux/autonomous-soc-agent/.git/authentication-demo-recovery-20261104T064236Z/operator-view
```

종료는 GUI 창 닫기 또는 실행 터미널 Ctrl+C다. 기존 실패 Native Runtime을 start/stop하지 않는다.
이 명령은 저장 결과 조회이며 `soc-agent start --gui` 전체 Live의 대체 성공이 아니다.
승인 대기 중에는 AI Analysis의 Run Offline Job 버튼을 사용하지 않는다.

## 5분 예비 발표 대본

1. 0:00–0:40: Human-governed SOC 목표. 탐지와 조사를 연결하되 모델·LLM 판단은 Root 실행 권한이 아님을 설명한다.
2. 0:40–1:30: OFFLINE_PCAP 라벨과 보존 Incident를 보여준다. 현재 Live 수집 화면이 아님을 먼저 밝힌다.
3. 1:30–2:20: RF/LR 두 결과와 Feature·Artifact 증거를 설명한다. 연구 모델 score를 공격 확률이나 공격 확정으로 표현하지 않는다.
4. 2:20–3:20: Investigation 탭에서 당시 실제 LLM Plan·Read-only Tool·Assessment를 설명한다. 지금 API 호출은 없다.
5. 3:20–4:10: Evidence/Audit 탭에서 원본 경로 Binding, 기록 검증과 독립 승인의 필요성을 설명한다.
6. 4:10–5:00: 창 종료·재연결로 증거 보존을 보여준다. Authentication READY 장애와 Runtime Cleanup 미검증을 공개한다.

## 남은 작업과 시간 경계

18:00 전에는 Host 진단 승인 후 1회 실행, 직접 원인 분류, 필요한 최소 수정·회귀,
새 Live Binding·잔류 검사·독립 권한 확인 순서로 진행해야 한다.
Root·Native·DNS·R1/R2, Host 읽기, RF/LR·IF 봉인 작업, LLM Incident·Revision·비용 결정이
각각 유효해야 한다. 인증·승인 없는 Live 명령을 실행 가능하다고 보고하지 않는다.

18:00까지 Live 미성공이면 새 Live 시작을 중단하고 21:00까지 Replay·GUI 시연을 정리한다.
확인된 후보는 과거 20분 Replay 성공 저장소(PCAP·RF/LR·SCRIPTED, Prediction 406건·Incident 203건,
Host·DNS 미포함)와 별도의 실제 API 성공 저장소다. 서로 다른 실험을 같은 Session으로 합치지 않는다.
Authentication은 현재 Fixture·Mock 검증이며 실제 Host·IF 시연이라고 표시할 수 없다.
새 Replay→모델 통합 시연 2회와 21:00 Release 고정은 아직 미완료다.
이 문서는 시간 예약, 무인 후속 실행 또는 최종 시연 완료를 뜻하지 않는다.

증거: `.git/authentication-demo-recovery-20261104T064236Z/` 및 인접 evidence 요약·실제 화면.
