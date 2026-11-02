# Research MVP Release 무결성

## 현재 배치

주 저장소와 `releases/research-mvp`는 동일 Git의 다른 Worktree다. 주 저장소의 기존 사용자 변경 164개는 보존하며, 운영 코드 수정은 `release/research-demo-mvp`에서 수행한다. 주 저장소의 옛 `.venv/bin/soc-agent`와 운영 Worktree의 CLI는 버전이 다르다.

주 저장소 `bin/soc-agent`는 고정된 `releases/research-mvp/.venv/bin/soc-agent`로만 전달한다. 다른 설치로 fallback하지 않으며 sudo를 호출하지 않는다. 이것은 편의 진입점이지 승인 또는 무결성 검증의 대체물이 아니다.

## 기존 검증 재사용

- `AgentProfile`: Runtime configuration, backend code identity, Native review 및 entry SHA.
- `verify_review`: 요청·Source 파일 목록·실행 pins 자동 비교, 만료 검사.
- `validate_plan`: Git/Source/Namespace/Lease/Ledger/실행 흔적/정확한 Scope 검사.
- `installation_plan`: 고정 Root 8경로·후보 SHA·현재 설치 SHA·Launcher의 정확한 변경 집합 검사.
- 모델 Worker: Feature Schema, Fingerprint, Attestation, Action 승인 검증.
- API: 정확한 retained input과 Revision, Provider/모델, 호출/비용/Timeout 상한.

문서 Commit이 새 코드의 성공을 증명하지 않는다. 코드 Commit, Source identity, 재현 Wheel 및 Native Artifact의 실제 SHA를 별도로 기록한다.

## 고정 Release와 실행별 설정의 구분

운영 Worktree는 주 저장소의 개발 Source로 자동 대체되지 않는다. 그러나 현재 venv는 editable 설치이므로 **완성된 불변 설치 Release 제품으로 판정하지 않는다**. 운영 Worktree를 바꾸면 다음 실행의 기존 Manifest 검증이 실패해야 한다.

Root 설정에는 Session 경로가 포함되므로 매 실행 Root Manifest가 달라질 수 있다. 이 사실을 숨기거나 과거 Root 승인을 재사용할 수 없다. 고정된 코드 Artifact와 실행별 설정은 서로 다른 무결성 대상이다.

## Update / Rollback

명시적 Update에서만 검증된 코드·의존성·모델을 교체한다. 새 Source/Wheel/Root 후보의 pins와 새 승인 패키지를 준비하고, 변경 경로를 대조한다. 변경 없는 파일은 inode/mtime/SHA를 유지한다. 기존 백업과 Rollback은 삭제하지 않는다.

고정 Release에서 새 Native Session을 안전하게 생성하고 새 독립 승인 조건에 결합하는 등록된 factory는 아직 미완료다. 따라서 새 Session UUID를 CLI 사용자가 직접 입력할 필요는 없지만, 현재는 검토 패키지 준비 단계가 필요하다. 소비된 Session을 새 것으로 가장하지 않는다.

운영 코드 Commit: `ed24479`(설치/GUI/진단), `9cd24ee`(Replay 복구 부모 권한). ed24479에서 준비만 한 미승인 draft는 Source 변경으로 폐기 대상으로 표시하고 보존했다. 새 실행 Session을 별도로 준비하며 이전 draft의 승인·Artifact를 승계하지 않는다.

최종 코드2064af1은 제한된 초기 Planner Schema를 보존해 API에 전달하는 수정을 포함한다. 최종 Wheel SHA는 `61393470e58e3298a510540f7141243b8733bf02ee391a1b9507f321d3e93461`이다. Source675개, 새v3 Session/Root Manifest를 자동 대조했고 초기/변경 이전 profile은 미실행 상태로 보존 후 재결합했다. 이는 실행 승인 발급이나 Root 설치가 아니다.
