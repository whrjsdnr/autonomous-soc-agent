# Security AI Final Integration — 실행 검증 보고서

최종 판정: **INCONCLUSIVE (운영 환경 전체 범위)**.
오프라인 합성/사전 계산 입력, 실제 공식 Predictor, scripted LLM, 격리 Handler의
**공유 Backend/Runtime 통합 범위는 PASS**다. 별도 Linux Desktop/Server 운영 호스트,
Windows 최신 전체 회귀 및 신규 외부 모델의 전체 교차 플랫폼 수치/판단 비교는
실행하지 않았다. 운영 배포 준비 완료나 프로덕션 탐지 품질을 주장하지 않는다.

## 구현한 실제 경로

기존 공식 외부 패키지 → B-3.1 Adapter → Context v2 → Companion Store → 기존
`compose_application`/`SOCRuntime` → Planner/Investigation → ThreatAssessor →
IncidentDecisionEngine → 기존 정책/승인/실행 경계로 연결했다. 기존 offline 진단의
대체 Orchestrator가 아닌 실제 SOCRuntime을 사용한다. 외부 데이터는 별도 advisory
JSON section으로 전달되며 Model-Derived Observation/Hypothesis 승격은 거부된다.
기존 Fusion v1은 별도의 기존 callback을 유지한다.

`python -m soc_agent.external_runtime`가 Desktop/Headless의 실제 재생 진입점이다.
DESKTOP은 기존 `desktop.initialize`, SERVER는 같은 Application Composition을 쓴다.
HTTP listener, GUI, 실제 Collector는 필요하지 않다. 제공된 Top40/DNS 입력 파일의
출처를 source Evidence로 보존하되 모델 Prediction을 Evidence로 만들지 않는다.
Quality/Edge는 같은 관측을 공유하고 DNS는 별도 관측으로 남는다.

## 저장/복원 계약

기존 v15의 정확한 `ISOLATED_VALIDATION_ONLY` 계약은 유지했다. 실제 runtime
publication용 데이터는 목적이 명시된 **additive v16**에서 관리한다. v14 Core/v15
Companion 테이블과 기존 ID/Hash/Payload는 유지한다. 일반 v14/v15 Reader의 신규
schema 거부도 유지한다. 운영 DB 자동 Migration은 수행하지 않았다.

외부 단계의 실제 READ Evidence/CAS/Core Audit, Assessment/Decision Receipt,
Checkpoint/Trace, Publication 및 Security Audit은 단일 SQLite Transaction에서
게시된다. 사전 durable claim은 별도이며, 강제 종료/실패 시 남은 claim을 자동
탈취하거나 재시도하지 않는다. 명시적인 운영자 복구는 READ 진행을 UNCERTAIN으로
닫으며 Handler를 재실행하지 않는다. 정상 Legacy 사건은 기존 경로를 유지한다.

실제 요청 SHA, Context projection SHA, 실제 Assessor 입력 Anchor와 기존 Context
source Anchor를 구분해 보존했다. no-op Assessment 때문에 Incident revision이나
기존 assessment_appended 이벤트를 인위적으로 만들지 않는다. Decision의 원래
Payload/ID는 변경하지 않고 별도 Receipt로 연결한다.

## 실행 경계와 보안

Registry/Tool/GovernedExecutor의 요청·dispatch·원래 Handler 호출 직전에 검증한다.
전용 Guard가 실제 Backend의 승인 발급, 상태 변경, Promotion, Durable execution,
Self-improvement activation/rollback 및 실제 Runtime 진입점에 적용된다.
직접 ActionProposal, 유효한 별도 Legacy Approval, Alias/Wrapper, naked Handler,
Capability 복제/만료/사건 전이, private Runtime stage 우회가 권한이 되지 않는다.
모든 신규 WRITE Spy 호출은 0이다.

자세한 진입점 목록과 신뢰 범위는 `security-boundary.md`에 있다. 임의 Python/Raw
SQL/원래 외부 Adapter 코드의 실행은 trusted code 영역이다. frozen 객체나 Native
worker만으로 악성 코드 OS 격리를 주장하지 않는다. 기존 NTFS/POSIX/SQLite 정책,
TrustedInstaller, OWNER RIGHTS, reparse/TOCTOU 및 sidecar 보호는 변경하지 않았다.

## 실제 테스트 결과

| 실행 | 결과 | 검증 범위 |
|---|---|---|
| WSL 전체 회귀 | 3104 passed, 25 skipped, 0 failed | 최종 1018.98초; 전체 completed run 3회 |
| 초기 관련 집중 | 491 passed | 실행/승인/정책/Tool/Companion/기존 진단/신규 Runtime |
| 실제 프로세스 종료 포함 Runtime | 64 passed | shared SOCRuntime, 실제 SQLite, fault/kill/recovery, scripted LLM |
| 추가 보안/Legacy/ASGI | 16 passed | 필수 추론 실패, Legacy 증거 게시, 위조·만료, 인증된 API |
| 기존 Native 추가 실행 | 2 passed | 실제 Predictor/기존 Core diagnostic/Context |
| Windows 1차 집중 | 278 passed, 3 skipped | 실제 Native Python/NTFS/Adapter/Context/Guard |
| Windows 최신 통합 | 121 passed, 2 skipped | 공식 모델 4 parameter cases, Runtime, kill/recovery, NTFS, Gate A Decision |
| WSL 최종 READ Scope | 8 passed | 동일 사건 입력/위조/만료; 수정 전 READ 우회 4건 재현 |
| Windows 최종 private artifact/READ Scope | 12 passed | 실제 모델 재검증과 사건 입력 차단 |
| WSL / Windows 동시 Runtime CAS | 각각 4 passed | 단일 READ와 task-local Evidence/Checkpoint 복원 |
| Ruff / format / diff | PASS | 최종 검사 |

새 Runtime/Native 테스트는 전체 회귀에 포함됐다. Native parameter cases는 Quality,
Edge, DNS, Quality+Edge이다. 실제 추론과 synthetic normalized-output/scripted LLM
테스트를 동일한 의미로 보고하지 않는다. 새 테스트의 fake WRITE Handler는 호출되면
실패하도록 되어 있다.

1차 WSL 전체 회귀는 3094 passed/27 skipped였다. 최종 전체 회귀는 Windows 전용
23건과 explicit opt-in 외부 LLM 2건만 skip했다. 기존 Native 2건은 환경을 지정해
별도 실행 및 최종 전체 회귀에서 PASS했다. Windows 최신 skip
2건은 unprivileged symlink 생성 및 실제 FAT/exFAT/remote/removable fixture 부재다.
기존 Linux fork 기반 경쟁 테스트에서 DeprecationWarning 6건이 발생했다. 새 강제
종료 검증은 Windows에서도 실제 spawn 프로세스를 사용한다.

## 실제 CLI smoke

WSL Desktop 최초 실행/재시작, WSL SERVER profile CLI, Windows Desktop LOCALAPPDATA
최초 실행/재시작을 실행했다. 세 모델 실제 추론과 Model Context 보존, Assessment,
Decision Receipt, 사람 검토 대기, 실행 Intent 0건을 확인했다. WSL/Windows Desktop
증거 파일에 모델/Artifact SHA, Context Digest, Decision ID와 저장 개수가 있다.
OS/세션/시간/증거 UUID가 다른 신선한 실행의 Decision ID를 무작정 같다고 선언하지
않으며, 기존 고정 Fixture 기반 Gate A 동등성과 신규 실행 증거를 구분한다.

Windows에는 별도 Native venv를 만들어 LightGBM 4.7.0, Torch 2.14.1, LiteRT 2.3.0,
pandas 3.0.6 및 필요한 종속성을 설치했다. 기존 `soc-windows`는 변경하지 않았다.
초기 DNS 실패는 pandas 미설정이었다. 잘못 지정한 pandas 3.1.1은 설치되지 않았고,
실제 WSL 검증 환경의 3.0.6을 설치한 후 실제 DNS Runtime 테스트가 PASS했다.
C 루트 검증본의 저장 경로는 ancestor modification ACL 검사에서 거부됐고,
NTFS 검사를 완화하지 않은 LOCALAPPDATA 전용 private 저장소는 PASS했다.

## 발견·수정한 오류

- 재평가 시 이전 Decision/Review/Plan의 Assessment 연결을 해제했다.
- DecisionEngine의 기존 reference-set canonical order와 Assessor 보존 표현을
  맞춰 기존 Checkpoint의 정확한 equality 검증을 유지했다. 기존 Decision ID
  규칙을 바꾸거나 equality 검증을 완화하지 않았다.
- 오류 처리 시 미종료 security audit cursor로 인해 감사 저장이 잠기는 문제를
  bounded 단일-row 조회로 제거했다.
- 새 테스트의 WorkflowFailure enum/HTTP 422 기대값 및 실제 provenance 필드 이름을
  실제 코드 계약에 맞췄다. 기존 assertion이나 보안 검증은 삭제하지 않았다.
- Legacy 사건에 external Evidence staging을 적용하면 정상 Evidence가 게시되지
  않는 문제를 분리했고 실제 persisted revision/evidence 회귀 테스트를 추가했다.
- 외부 READ Action과 Tool 입력의 incident_id가 다른 우회를 실제 READ Spy로
  재현했다. Handler 직전 사건 입력 binding을 검사하여 차단했고, Legacy 경로는
  변경하지 않았다. 최종 WSL/Windows 검증에서 READ/WRITE Spy 호출은 0이다.
- 동일 Runtime 경쟁 호출의 staging 참조를 사건별 map에서 ContextVar로 통일했다.
  실제 SQLite claim/CAS 충돌에서 단일 READ 호출, Evidence revision 및 복원 가능한
  Checkpoint를 검증했다.
- Native worker가 숨긴 오류를 제한된 버전ed Result/정제된 오류 코드로 전달한다.
  Backend 실패를 다른 모델 성공이나 Fake Prediction으로 위장하지 않는다.

## 변경과 보존

이번 작업의 코드/테스트 변경은 `changed-files.json`의 33개 파일이다. 기존 working
 tree의 무관한 수정은 유지했다. `tests/fusion_support.py` SHA는
`e5f9d10f706f71b82e80261f7633a1504e27ba24499be948d04adb6eeb3a21c9`으로 동일하다.
기존 Fixture, Fusion v1, Reference 계산 및 모델/Selection 산출물은 변경하지 않았다.
`.env` 접근, 기존/운영 모델 재학습, 외부 Provider, 실제 보안 조치, 운영 DB 변경, commit/push,
모델 승격 및 운영 배포는 수행하지 않았다. 기존 회귀의 격리된 synthetic
fit/training 테스트는 실행했으며 기존 모델/학습 산출물을 덮어쓰지 않았다.

Windows 검증은 신규 격리 디렉터리 두 곳에서 수행했으며 기존
`C:\soc-agent-windows-test`는 보존했다. 검증된 최신 Windows 코드 33개는 WSL SHA와
일치한다. 공식 Artifact 복사본 10개도 원본/복사본 SHA를 확인했다. 원본은 변경하지
않았다. 이후 native secure-storage API로 LOCALAPPDATA에 보호된 모델 복사본
10개를 생성하고 동일 SHA와 실제 모델 Runtime을 다시 검증했다. 기존 검증본용 `windows-sync.json`은 23 EXPECTED_PREIMAGE와 10 NEW를 기록한다.
자동 덮어쓰지 않았으며 동기화 시 SHA 재확인/백업/충돌 중단을 적용해야 한다.

추가 요청인 Conda 26.7.1 업데이트는 WSL/Windows 두 base가 발견되어 대상 확인을
요청했다. 대상 답변 전에는 어느 base도 업데이트하지 않았다.

## 판정과 다음 조건

읽기 전용 External AI와 실제 SOC Runtime의 통합·저장·복구는 위 테스트 범위에서
PASS다. 별도 운영 호스트/전체 Windows 회귀/새 외부 모델의 정량 교차 플랫폼 비교가
남아 전체 운영 지원 판정은 INCONCLUSIVE다. 추가 개발이나 실제 배포/승격은 자동으로
진행하지 않는다. 남은 조건은 `remaining-risks.md`를 참조한다.
