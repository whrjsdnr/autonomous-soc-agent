# 최종 MVP 배치·검증 및 통합시험 상태

작성일2026-11-02. 대상저장소 `/home/geonug/kdt-linux/autonomous-soc-agent`.

## 배치 결과

개발본4633e52/운영코드1fcbff2를대상아래 `releases/research-mvp` Worktree로배치했다.
같은Git저장소이며검증MVP브랜치는 `release/research-demo-mvp`,동결HEAD `bbaeccdd6e6ac1ba8fc35862dba1cb8078833a96`.
루트는기존main9a12fe9와다른사용자변경을보존하는문서브랜치 `docs/research-mvp-finalization`.
40개tracked수정/124개untracked파일을덮어쓰지않았고164개원래변경파일SHA가그대로다.
tracked8파일의병합충돌과untracked1파일상이함을확인하여무조건병합하지않았다.
기존mainref와개발Worktree는변경하지않았다. 최종운영소스가루트기존src전체를대체한것은아니다.

기술보고서필수9개,10Mermaid,29장발표구성/49QA,보존실제GUI자료와모델지표자산을반영했다.
루트보고서의코드/테스트링크는검증MVP를참조한다. 두배치각280개로컬링크검사누락0.
새MVP의독립venv는잠금파일로 `uv sync --offline --frozen`;24개캐시의존성을사용했다.
루트의기존 .venv는변경하지않았고start만지원하므로사용하지않는다.

## 현재 확인된 검증

- 대상MVP Workspace 관련회귀1453PASS/1SKIP,pytest542.92초/전체wrapper548.23초.
- 독립Export 관련회귀1453PASS/1SKIP,pytest538.95초/전체wrapper544.75초.
- 실제보존Native결과Tk GUI2회연결/종료/재연결PASS;Prediction8/소유CleanupVERIFIED표시.
  원본SHA변경0. 이는새Native시험이아니다.
- GUI특화실제Tk Workspace5PASS/독립Export5PASS(29.58/27.85초). Replay/NATIVE표시분리,종료/재연결,적격성/조사표시검증.
- CLI setup/doctor/preview/status PASS. doctor의Namespace내부검사BLOCKED는승인전정상경계다.
- 실제Root verify_contract비권한실행PASS,권한/서비스조회만Mock,문서SHA/만료/Session/Git4negative차단.
- 새후보Launcher비권한3PASS:실제축소GNUtimeout,격리임시파일설치모드와백업/동일파일보존,
  봉인작업만모델승인화면연결/중복프롬프트차단. Root·모델실행없음.
- Native6/legacy Native/Supervisor/Wheel:Workspace2회+독립Export재현SHA일치.
  Wheel `6bd6b787a04ec69dedca968b337ac70b1cc5949fcce25973fea3d54f8392e209`;기존검증본과동일.
- Ruff Check PASS,Format1564파일PASS,DiffPASS. 운영코드추가수정없음.
- 원래사용자파일164/Source672/설치8경로SHA·inode·mtime/기존증거2554/ Ledger81행보존확인.

## 실행 준비의 최소 수정

기존600초Launcher와기존모델검토hook을새Worktree/Session에다시결합했다.
오래된600초템플릿에최신Installer의0644 fchmod/검증이없음을확인하여기존최신구현을재사용했다.
원래Root경로8개중변경4개/검증만4개,백업8개. 원래권한검증을완화하지않았다.
생성중private검증스크립트의메타데이터/ASTfixture오류는수정하여최종검증을통과했다.
새Framework/승인시스템/수집기/모델/Timeout상향은없다. 준비과정초안도별도보관했다.

## 정확한 새 시험

검토서: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/research-mvp-short-native-review-20261102T091500Z/native/approval-package-final.md`.
Request SHA `abc605213ae9cc96b8b75f0a9257e9fc2dc78bbd71c8206fbf82b0af4d0b061d`.
RootManifestSHA `29f7a608433a6c30b8f2f84330491d0ed8fd7f30842f90911e93e0085e786f4e`.
RuntimeSession `b3edc588-aec1-47ae-940a-3ba10d7e0060`,DNS `5cbf2a22-aeec-4d08-8f01-79c34653e01e`.
Namespace net:[4026532232]/lo/Ingress,Release0.6.3;Ledger81 `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`.
전체600초/순수목표360초. TCP최대4연결/DNS UDP2TCP1. Queue32.
Collector128MiB/CPU25%,Runtime512MiB/CPU50%,DNS512MiB/CPU10%,TCP64MiB/CPU10%,dnsmasq64MiB/CPU10%.
Runtime256MiB/RootAudit64MiB점검상한은하드Quota가아니다.
ownerSTOP400/Drain460,RootTERM530/KILL560,workerTERM590/KILL595;
기존2초Helper/5초Control계약유지. 상위제안만료 `2026-11-03T00:13:20.439461+00:00`와입장최소75분을확인한다.
현재Session은미실행이고정식새Binding승인/정책활성화/직접Scope/sudo가필요하다.
기존소비영수증을재사용하지않았고영수증발급/예약/Root/Native/DNS/API실행0회.

## 사용자 추가 요청: 실제 RF/LR·LLM까지

Native→Window/Attestation→ELIGIBLE→작업별승인→RF/LR→Incident→기존SOCRuntime→
계획/Tool/Assessment→Audit/GUI를검증한다. RF/LR독립상한은2작업/전체16호출이며
INCOMPLETE/UNKNOWN은차단한다. 실제입력부족/Incident미발생은성공을조작하지않는다.

실제LLM은기존RetainedAPIClient경로로이번Session의실제NetworkIncident하나를고정한뒤
별도API입력Binding/승인으로Plan1+Assessment1을진행하는안이다.
기존OpenAI gpt-5-mini/Provider/Key,최대2요청/총$0.05/20초/출력4096토큰/재시도0/재계획0.
각입력예약60000토큰이하일때총최대예약$0.046384. Usage없음/Timeout이면비용·결과UNKNOWN.
공식모델문서와Deprecations를2026-11-02조회했다. Deprecated/2026-12-11종료예정,
계정가용성UNKNOWN/자동모델변경금지. API Key는읽거나출력하지않았다.

**단일start에서실제LLM자동호출까지연결된상태는아니다.** 기존start는SCRIPTED조사Worker를
실행하고,실제API는독립승인의기존Retained API후속경로다. 이차이를숨기지않는다.
미래Incident의Task/EvidenceRevision/입력SHA는아직없으므로API승인안의정확한데이터Binding은
그결과생성후확정해야한다. 새승인시스템개발없이기존계약을유지한다.

## 최종 한계

실제20분·1시간Native연속운영은미완료. Helper송신공백근본원인UNKNOWN,
실제LLMAssessmentTimeout,HostAuthenticationIF전체Live,DNS9원본학습계약,
GlobalKernelCleanup/상용무인운영은미검증이다. 과거FAILED/false/UNKNOWN/UNVERIFIED와
PENDING2/POISON1은보존하고이번결과로소급수정하지않는다.

명령어: [Native MVP 시험 Runbook](Native_MVP_Test_Runbook.md).
구성: [배치 경계](MVP_Deployment_Notes.md).
공식API근거: [모델/가격](https://developers.openai.com/api/docs/models/gpt-5-mini),
[폐기 일정](https://developers.openai.com/api/docs/deprecations).
