# Full E2E 통합 준비 현황

최종 판정: **PARTIALLY_READY**. 1회용 Native 재시험 패키지와 기본 profile은 준비됐으나, 반복 실행용 자동 Session 준비와 완전한 불변 설치 제품 모드는 미완료다. 실제 Native/API 성공은 별도다.

판정은 검증 완료 시점의 결과 파일을 기준으로 갱신한다. `FULL_E2E_READY`는 실제 Native/API 성공을 뜻하지 않으며, 현재 알려진 미완료 사항이 있으면 부여하지 않는다.

## 반영한 변경

- 새 Launcher의 설치 Scope를 정확한 고정/변경 경로 집합으로 결합하고 CLI에서 설치 전 확인.
- 모델 Worker 실패 단계의 안전한 Durable 진단, ToolError 결과 보존.
- 원 Native Session/Incident/Task/Revision에 결합된 API 조사 결과를 동일 GUI에 표시.
- 현재 봉인된 RF/LR 작업의 GUI 일괄 검토와 기존 Action별 승인 기록.
- 정확한 Native Incident에 대한 API 검토 화면과 기존 APIRunAuthorization 재사용.
- 옛 주 저장소 CLI 대신 고정 운영 Worktree로 전달하는 `bin/soc-agent`.

## 구현/검증과 실환경을 구분

GUI 검토는 인간 결정 없이 권한을 만들지 않는다. API 결과 projection은 원 저장소를 수정하지 않는다. 테스트의 Native 권한 경계·HTTP 응답은 명시적으로 Mock이며 실제 API나 TCX가 아니다. RF/LR fixture/offline 실행은 Native Action 승인과 무관하다.

## 남은 완료 조건

1. 고정된 설치 Release에서 fresh Native Session·review를 안전하게 준비하는 등록된 제품 경로.
2. 새 v2 Launcher는 GUI exact API authorization을 기다리도록 연결했다. 과거 자동 발급 helper는 사용하지 않으며, 실제 C 호출과 결과 표시의 실환경 재검증은 별도다.
3. 새 Binding의 최종 미승인 v2 패키지와 Preview/Root 계약 검사는 통과했다. 정책 활성화와 R1/Root/Native 인간 결정은 미실행이다.
4. 서비스 안 RF/LR Worker의 실제 성공, 전체 GUI 값, LLM Assessment와 해당 Cleanup 재검증.

따라서 사용자 UX 전체 완료 및 실제 통합 라이브 성공은 아직 부여할 수 없다. 최신 테스트·빌드·Git 정보는 아래 검증 절에 기록한다.

## 검증

작업 증거: `.git/full-e2e-overnight-recovery-20261102T111600Z/`. 최초 집중 회귀181 PASS, 별도 실제 Tk/승인검토11 PASS, 원본 설치 함수 파일 작업 회귀5 PASS. 코드 ed24479에서 Workspace/독립 Export 각각1506 PASS·1 SKIP, Native6종/legacy/Supervisor/Wheel의 Workspace2회+Export SHA 일치를 확인했다. 이후 실제 CLI 복구에서 발견된 디렉터리 권한 결함을9cd24ee로 수정했고, 관련38 PASS와 실제 CLI 격리 복구·GUI 재연결을 확인했다. 최종9cd24ee의 전체 회귀·재현 빌드를 다시 수행 중이다.

## 이전9cd24ee 단계 검증 결과

| 항목 | 실제 결과 |
|---|---|
| Workspace | 1507 PASS,1 SKIP,511.18초 |
| 독립 Export | 1507 PASS,1 SKIP,484.65초 |
| Source 변경 | 두 회귀 중 없음 |
| Ruff | check PASS, format1573파일 PASS |
| Native6종 / legacy / Supervisor | Workspace2회와 Export1회의 SHA 일치; 로드/활성화 아님 |
| Wheel | 3회 동일 `0a7f6d2915ed64232a725fe54dfff07e186f0658bebb2d7c529f7d87cdbed459` |
| 실제 CLI 저장 PCAP |128레코드/70Packet,120초 시험 상한에서 정상 Stop,Prediction46/Incident23/PENDING13 보존 |
| 격리 복구 |75.809초,DONE36/새Prediction22/새Incident13,Drop/SourceGap/모델 오류0,Cleanup VERIFIED |
| 실제 GUI | Desktop2회와 실제CLIgui2회,PCAP_REPLAY/NativeLiveFalse/Task/Prediction/정상종료·재연결,Backend불변 |
| 보존 | 사용자164파일,기존2554증거,Ledger81행,Root8경로 유지 |
| 새 Native/API |0회 |

추가 집중 회귀:181 PASS, GUI/승인11 PASS, 원본 설치 fragment5 PASS, 복구38 PASS. 같은 테스트의 반복 실행을 서로 다른 운영 시험으로 합산하지 않는다. 전체 회귀의1 SKIP은 별도 retained-session opt-in을 요구하는 검사다.

## 이전9cd24ee 미승인 Binding — SOURCE 변경으로 미사용

- Code: `9cd24ee626ba17130c015a73237a60c409e5db8d`
- Controller identity: `71c6d28ce4d87a27358a2150d2bd746007dae9e5b49be963c26d283c8740573f`
- Source675개 digest: `79e3a109a807794d7bb071fc4268527fece4221ceb1ff5438e54647c2de0059d`
- Runtime Session: `ce7bab9f-2a5f-49d0-bea4-c2228b7562f1`
- DNS Session: `a43b5c96-628a-4aea-956b-98d6477a2f00`
- Namespace: `net:[4026532232]`,lo/Ingress,기존 Lease
- 제안 만료: 2026-11-03 21:58:11 KST. **활성화된 승인 만료가 아니라 새 인간 결정이 필요한 제안**이다. 입장 시75분 이상 유효기간 필요.
- Manifest: 고정8경로 중3개 후보 변경,5개 검증. 설치 전·후 SHA/백업은 실제 승인된 실행에서 확인한다.
- 기본 profile의 Preview: `PREVIEW_ONLY_REQUIRES_DIRECT_SCOPE_R1_AND_SUDO`; 실행·예약·영수증0.

검토서: `.git/full-e2e-exact-operator-review-20261102T120000Z-v2/native/approval-package-final.md`. 이 v2 Binding은2064af1 수정으로 미사용 보존했다. 코드 ed24479로 준비만 했던 draft는 Source 변경으로 `SUPERSEDED_BEFORE_APPROVAL` 표시 후 보존했다.

현재 장비에서 초기 1회 실행 진입점은 준비됐지만, 소비 후 새 Native Session을 자동 회전하는 반복 운영 UX는 아직 완료되지 않았다. `FULL_E2E_READY`나 실제 `OPERATIONS_VERIFIED`를 부여하지 않는다.

## 최신 추가 통합 결함 수정 —2064af1

실제 보존 PCAP 결과를 사용하는 초기 Planner의 제한 파생 Schema가 API 경계에서 거부되는 결함을 추가로 확인해 수정했다. 단계2 상한을 유지한 파생 Schema 수용과 무관 Schema 거부를201건 집중 회귀로 확인했다. 이 Code에서는 Workspace1509 PASS·1 SKIP이며 독립 Export1509 PASS·1 SKIP, Native/legacy/Supervisor/Wheel 재현 빌드까지 확인했다. 위9cd24ee 수치·Binding은 이전 단계 기록이고, 기본 profile은 실제 실행 없이 최종 새 Binding으로 갱신했다. 과거 미승인 패키지의 영수증이나 Session은 승계하지 않는다.

추가 보존 Evidence 조사 시험: 실제 PCAP의 저장 모델 결과와 실제 과거 Native DNS 메타데이터를 재사용했다. Network는 FAKE_HTTP Plan/Tool/Assessment2회, DNS는 SCRIPTED 조사이며, 실제 API0·신규 Native0·신규 모델 추론0이다. Source 역할과 시계를 유지했고 관련 없는 사건을 합치지 않았다. 별도 실제 GUI2회에서 FAKE_HTTP와 이 결과를 표시했다. 최초128레코드 PCAP 실행에서 DNS transaction이 나온 것으로 주장하지 않는다.

## 최종 실행 준비 Binding —2064af1, 실행 미승인

- Code: `2064af137905764d360fb002bab8b5672807d187`
- Controller identity: `5bfef1cac2c11de66a3eb0d8dae922262ba05fc3b87474cafbc2e07269b9465f`
- Source675 digest: `1b552d1db8b6e177d596d595d4838e98cc38dc3362c084a2d48028e453aa69a0`
- Wheel SHA: `61393470e58e3298a510540f7141243b8733bf02ee391a1b9507f321d3e93461`
- Runtime Session: `13a84145-3210-470b-87d1-fc07673ad832`
- DNS Session: `3561553a-17cd-414f-b0e6-89f3da690baa`
- Root manifest SHA: `f6d22d6de4adec991de266d6b37a25515c7b3066789e4155b15fc75da5c7acc6`
- 제안 만료 KST: `2026-11-03T23:06:23.432868+09:00`

검토서: `.git/full-e2e-exact-operator-review-20261102T120000Z-v3/native/approval-package-final.md`. 이전v1/v2는 실행 전 Source 변경으로 미사용 보존했고 기본 profile의 이전 설정도 private backup으로 보존했다. 새 Source·Session에 과거 영수증을 승계하지 않았다.

최종 회귀: Workspace1509 PASS·1 SKIP/489.19초, Export1509 PASS·1 SKIP/494.50초. 두 회귀의 Source 불변 확인. Native6종·legacy·Supervisor·Wheel은 Workspace2회+Export1회 일치. 최종 Ruff/check/format/diff PASS. 정상 Root 계약과 document/expiry/Session/Git 변조4개 음성 경로를 Root 권한 경계만 모사해 통과했다. 실제 Root 함수의 install/namespace/system은 실행하지 않았다. 설치 파일 부분은 별도 격리 경로 시험으로3교체/5불변/8백업을 검증했다.

현재 실행 허용·정책 활성화·R1·Root·Native·트래픽 인간 결정은 없다. 설정은 `PROFILE_PREPARED_NO_AUTHORITY`다. B는 봉인된 적격 작업별, C는 정확한 Incident/Revision의 GUI 결정이 필요하다. Native/API 실제 성공과 반복 Session 자동 준비는 미검증/미완료로 유지한다.

운영 Source2064af1의 알려진 비권한 차단 오류는 수정하고 회귀했다. 다만 반복 운영 제품의 Session factory와 완전한 불변 설치 UX가 아직 없으므로 전체 사용자 UX 판정은 **PARTIALLY_READY**다. 현재 준비된 1회 시험은 아래 Guide의 명령으로 Scope 확인 단계에 진입할 수 있다.


## 최종 검토 확인

실행 제안 만료는 2026-11-03T23:06:23.432868+09:00이다. 이는 인간 승인 없이 활성화된 정책이 아니다. 최종v3에 대한 자동 Preview/Root contract 검증이 통과했고 기본 profile은 이 v3를 가리킨다. GUI 초기 모델/API 대기 상태가 오류가 아닌 정상 대기로 반환됨도 확인했다.

코드2064af1, 문서는 별도 Commit. 설치 Root8경로·Ledger81행·기존 사용자164파일·역사 증거2554개 SHA를 마지막으로 재검증해 유지됨을 확인했다. Unit Test의 격리 TEST_ONLY 승인은 실제 R1/Root/Native/API 실행 영수증 발급으로 계산하지 않는다. Native 모델 Worker 원인은 실환경 재검증 전까지 UNKNOWN이며 Source/API 전체 Live 성공을 주장하지 않는다.


## 2026-11-03 — Installed operator UX 후속 준비

이 절은 이전 일회성 profile의 PARTIAL 판정을 덮어쓰지 않는 후속 개발 결과다. 코드1825442에서 기존 frozen Native Release의 Session 초안 자동 준비·소비/실패 차단·명시적 Update·GUI Session 조회를 연결했다. 관리 Wheel SHA는 `2d3b2d6076b423af01048e857ab009797ba67b7609ca57de9b742724ea2f0b97`이며 실제 Native backend의 frozen Code2064af1과 분리했다. API request 비용의 오래된 $1 literal은 새 제안 $0.05에 맞게 축소 결합했다.

최종 Workspace1545 PASS/1 SKIP, Export296 PASS(변경 CLI/GUI/승인/Session 및 보존 E2E), 집중71 PASS. 두 Source tree identity 일치, Native·legacy·Supervisor·Wheel 3-way 빌드 일치. Root verify_contract의 실제 새 draft/파일 검사는 통과했으며 인간 결정·서비스 조회만 fixture였다. 실제 설치 관리 CLI의 Read-only doctor/status/preview, 격리 Replay Start→Status→Stop/Cleanup, GUI 재연결도 검사했다. Native/API 실행은 별도다.

관리 설치 추가 결함: Controller-only 의존성에는 NumPy/scikit-learn/XGBoost·패키지 리소스가 없었고, copied CPython에는 Tcl/Tk shared libraries가 빠졌다. 실제 import/GUI 검사로 발견하여 기존 설치본에서 가져왔다. uv .lock0666은0600으로 강화했다. 기존 Root Controller의 파일/크기/권한 검사는 완화하지 않았다. 실패한 미게시 설치와 로그를 보존했다.

실제 시험 제안: `.git/operator-ux-validation-20261103/live-approval-package.md`. 전체600초/순수목표360초, 기존 lo/Ingress·TCP4·DNS UDP2/TCP1, Root8 중3변경, 기존 자원 상한. B는 실제 봉인 작업별, C는 실제 Incident/Revision별 독립 GUI 승인이다. 실제 운영 판정과 현재 관리 준비 판정은 구분한다.
