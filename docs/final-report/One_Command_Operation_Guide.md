# 사용자 직접 실행 안내

## 사용할 CLI

```bash
cd ~/kdt-linux/autonomous-soc-agent
export PATH="$PWD/bin:$PATH"
soc-agent --help
soc-agent setup --help
soc-agent start --help
```

이 PATH 설정은 현재 터미널에만 적용한다. 기존 `.venv`나 사용자 shell 설정은 덮어쓰지 않는다. `soc-agent`는 검증 대상 운영 Worktree의 CLI로 전달된다. SHA나 Session UUID 입력 옵션은 필요하지 않다.

## 현재 장비의 최초 설정 상태

사용자 전용 `~/.local/bin/soc-agent` 링크와 기본 profile `~/.local/state/soc-agent`는 비권한으로 준비했다. 기존 주 저장소의 `.venv/bin/soc-agent`는 변경하지 않았다. 옛 venv를 활성화한 터미널에서는 다음을 한 번 적용한다.

```bash
export PATH="$HOME/.local/bin:$PATH"
hash -r
soc-agent doctor
soc-agent start --preview
```

PATH와 무관하게 `~/kdt-linux/autonomous-soc-agent/bin/soc-agent` 또는 `~/.local/bin/soc-agent`를 직접 사용할 수 있다. 현재 profile에 다시 setup을 실행하지 않는다. 새 준비 패키지에 대한 직접 Scope/R1 및 정책 유효기간 갱신 결정은 아직 필요하다.

현재 미승인 검토서:

`.git/full-e2e-exact-operator-review-20261102T120000Z-v3/native/approval-package-final.md`

현재 기본 Session은 미소비 상태다. `doctor`의 Namespace 내부 검사는 승인 전 `BLOCKED`로 남는 것이 정상이며, Lease Host 검증과 진입 권한을 혼동하지 않는다.

다른 profile을 최초 등록하는 기존 명령은 `soc-agent setup --native-review NEW_REVIEW_DIRECTORY --home NEW_PROFILE_DIRECTORY`다. 이 설정은 실행 권한을 만들지 않으며 기존 profile을 덮어쓰지 않는다. 새 Session UUID나 SHA는 사용자가 입력하지 않는다. 현재 Native Session 자동 회전은 미완료이므로 소비 후에는 새 패키지/profile 준비가 필요하다.

## 승인된 실제 시험

유효한 새 Binding과 인간 A Scope/R1 승인 후, 사용자가 있는 전경 터미널에서만:

```bash
soc-agent start --gui
```

Root Scope 확인과 sudo 비밀번호 입력은 기존 전경 Launcher가 담당한다. Codex나 GUI가 비밀번호를 받지 않는다. Packet/DNS READY 이후 GUI에서 `Review sealed RF/LR jobs`로 실제 봉인된 작업을 검토한다. Incident가 준비되면 `Review LLM Plan / Assessment`에서 정확한 입력과 비용을 검토한다. 아직 준비되지 않은 작업은 정상 대기다.

별도 터미널:

```bash
soc-agent status
soc-agent gui
soc-agent stop
soc-agent status
```

GUI 닫기는 Runtime 중지가 아니다. `stop`은 STOP/Drain/Cleanup을 확인하며 미처리 작업이 있으면 보존 상태로 보고한다. Exit 0만으로 TCX 또는 Helper Cleanup을 판단하지 않는다.

## 현재 사용 가능 범위와 제한

명령 등록, Replay 생명주기, Native 미승인 차단, GUI 검토와 결과 projection은 비권한 검증 대상이다. **지금 명령 하나로 모든 새 Native Session의 준비·독립 승인·모델·실제 API 실행까지 무조건 완료된다고 주장하지 않는다.** 등록된 Native Session은 일회성이며, 고정 Release 기반 fresh Session 생성과 새 Launcher의 exact API 승인 대기 연결이 남아 있다.

옛 `.venv/bin/soc-agent start`나 과거 `.git/.../run-terminal.sh`를 직접 실행해 새 검증을 대신하지 않는다. 실패 후 자동 재실행하지 말고 최초 오류·STOP ACK·Helper CLOSED·Cleanup을 보존한다.
