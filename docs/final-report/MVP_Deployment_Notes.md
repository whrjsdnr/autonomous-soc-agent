# 연구·시연용 MVP 배치와 보존 경계

두 경로는 같은 Git 저장소의 Worktree다. 개발 검증본4633e52/코드1fcbff2를 대상 저장소의 `releases/research-mvp` Worktree에 배치했다. 별도 로컬 `.venv`는 기존 uv.lock을 `uv sync --offline --frozen`으로 사용했다. Host 패키지·서비스·Root 설치를 변경하지 않았다.

기존 대상 루트는40개 tracked 사용자 수정과124개 untracked 파일을 가진 오래된main9a12fe9였고,8개 tracked 파일 및1개 untracked 문서가 incoming과충돌했다. 21개 tracked수정은incoming과동일하지만나머지는달랐다. 사용자파일을덮어쓰거나stash/pop/reset하지않고그대로두었다. `git stash create`는tracked차이를Git객체에복제만했고worktree/index/stash목록을바꾸지않았다. 병합사전검사는별도Git객체에서수행했다.

대상 루트의보고서만검증Commit에서추출하고,코드·테스트·지원문서링크는검증MVP Worktree를가리키도록교정했다. 대상루트의기존 `.venv/bin/soc-agent`는start만지원하므로최종CLI라고안내하지않는다. 정확한MVP CLI는 `releases/research-mvp/.venv/bin/soc-agent`다. shell에서해당venv를활성화하면 `soc-agent` 한명령으로기존6개기능을사용할수있다.

이 배치는 사용자 변경을 실제파일 그대로 보존하기 위한 기본값이다. 충돌하는8파일의최종루트병합은미수행이며,검증본이대상루트의모든기존src를대체했다고보고하지않는다. 충돌원본·binarypatch·SHA인벤토리는공통Git `mvp-final-transfer-20261102T090250Z/`에보존했다.

검증 범위는 제한Native Packet/DNS/RF-LR/Incident/SOCRuntime/SCRIPTED조사/GUI/Audit/소유Cleanup과별도실제LLMPlan/Read-onlyTool이다. 20분·1시간Native연속운영,Helper송신공백원인,실제LLMAssessment,HostAuthIF전체E2E,DNS9학습Feature계약,GlobalKernelCleanup,상용무인운영은미검증또는UNKNOWN/Timeout을유지한다.

Native 실행 승인이 이 문서나 배치로 생성되지 않는다. 기존 소비 영수증·Session을 재사용하지 않고, 새 검토 패키지·정책/R1/Root/Native/DNS/트래픽 승인과 사용자 Scope·sudo 인증 뒤 최대1회만 실행한다. 모델Action·외부API·HostAuth·DNS9는 별도 계약 없이 실행하지 않는다.
