# 통합 E2E 시연

기존 SENTINEL GUI를 한 창에서 진행하는 조회 전용 시연 모드다. 기존 Dashboard, Continuous, AI Analysis, Investigation, Security Events, System의 레이아웃과 렌더러를 재사용한다. 상단에는 작은 `E2E Scenario Replay`, Play, Previous, Next, Details만 둔다.

```bash
~/kdt-linux/autonomous-soc-agent/releases/evidence-demo-20261104/show-demo unified
```

명령 실행 시 Dashboard에서 바로 값의 자동 재생을 시작한다. 화면과 출처는 자동으로 바뀌지 않으며 발표자가 사이드바 또는 Details의 결과 선택 버튼으로 이동한다. 총 300초 후 재생 시계만 정지하며 창과 마지막 값은 유지한다. 자동 종료는 없다. **Next / →**로 다음 단계, **Previous / ←**로 이전 단계, **Pause·Play / Space**로 일시정지·재개한다. 수동 시작은 `show-demo unified --manual`이며 전체 결과를 즉시 조회한다. Details에서 Restart, Reconnect, 별도 PCAP reference, 원본 Auth Runtime 실패 기록을 열 수 있다. 기존 사이드바로 화면을 직접 탐색할 수 있다. 종료는 창 닫기 또는 Ctrl+C다.

Details는 날짜, 실행 유형, 원본 식별자를 표시한다. 각 원본 전체 결과는 기존 Evidence / Audit 또는 Continuous 상세에 있다. Native와 API는 별도 시험이며 Incident를 연결하거나 서로 다른 시험의 수치를 합산하지 않는다. 원본 STOPPED 상태는 상세에 유지하며 Network/DNS 카드는 저장된 수치를 중심으로 표시한다.

Packet 카운터는 0→54로 증가하고 실제 저장된 Packet 표본14개와 DNS 이벤트6개가 순차적으로 나타난다. Window 진행과 함께 RF/LR 첫 결과는 시작 약7초, 8개 전체는 약24초에 표시한다. Authentication IF1건은20초에 표시하며, Queue 카드는 시연 입력 도착과 모델 결과 공개 수의 차이로 일시 증가한 뒤0으로 돌아온다. 모델 화면으로 강제로 전환하지 않는다. Incident2개, Task5개도 단계 안에서 순서대로 공개한다. Dashboard와 Investigation의 LLM 패널은 별도 실제 API 시험을 재생한다. 시작24초에 Plan, 34초에 Tool 결과, 48초에 Assessment를 공개한다. Dashboard는 짧은 요약, Investigation과 API result는 상세 문장을 보여준다. 세부 API 보고서는 Details → API result, Authentication은 Details → Authentication IF로 명시적으로 선택한다. 새 API 요청은 없다. 모니터링의 `실행 중`은 재생 시계의 상태이며 새 수집 프로세스 상태가 아니다. Pause는 숫자·행·그래프 진행도 멈춘다.

## 5분 발표 순서

아래 화면 이동은 발표자가 직접 수행한다. 자동 진행은 숫자·행·그래프 갱신에만 적용하며 화면 선택과 창 종료는 발표자가 수행한다. Next/Previous는 선택적으로 발표 단계와 해당 화면을 함께 이동하는 버튼이다.

| 시간 | 기존 화면 | 설명할 내용 |
|---|---|---|
| 0:00–0:35 | Dashboard | Packet 54, DNS Query 3 / Response 3, 수집 → 조사 구조 |
| 0:35–1:05 | Continuous | Window VERIFIED, ELIGIBLE 5 / INCOMPLETE 2 |
| 1:05–1:45 | AI Analysis | RF/LR Prediction 8건은 이미 24초에 표시됨; 점수와 실제 공격 확정의 차이 |
| 1:45–2:15 | Continuous / Incident 표 | Incident 2건: UNKNOWN_ANOMALY, DATA_QUALITY_FAILURE |
| 2:15–3:00 | Continuous / Task 표 | 5개 SCRIPTED Task, read_local_source_report, WAITING_HUMAN; 행을 선택하면 상세 |
| 3:00–4:00 | Investigation / LLM 패널, 또는 Details → API result | 48초부터 공개된 별도 10월27일 REAL_API Plan, read-only Tool, Assessment를 설명 |
| 4:00–4:30 | AI Analysis / Authentication | 실제 IF 실행 영수증 1건, anomaly, 정규화 순위 0.9667, 42개 Fixture 입력 |
| 4:30–5:00 | Continuous / 상세 | 시험별 Audit와 Cleanup. Native 소유 범위 VERIFIED, 실패 Runtime UNVERIFIED, 전역 UNKNOWN |

발표 도입에서 과거 시험 결과를 재생하는 화면이며 일부 시스템 시간 그래프는 시연용 보완 데이터임을 설명한다. 사용자의 명시적 요청에 따라 화면에 MOCK 배지는 넣지 않았다. 보완 범위는 아래 표와 manifest에 기록한다. 성공한 단일 Live E2E 또는 실제 Host IF 운영 검증이라고 설명하지 않는다.

## 원본 출처

저장소 기준 상대 경로다. GUI는 이 경로의 원본을 읽으며 복제·변조한 승인 영수증을 만들지 않는다.

| 출처 | 시험 날짜 / 실행 유형 | 원본 위치 | 핵심 식별자 |
|---|---|---|---|
| Native | 2026-10-30 / NATIVE_SERVICE, SCRIPTED | `.git/native-orchestration-final-fixes-20261030T085013Z/review-ready/future-runtime` | Store `bd5cd8aa-66b4-4e1d-b997-bc38f9bfb97b` |
| Replay | 2026-11-02 / PCAP_REPLAY, SCRIPTED | `.git/runtime-storage-isolation-20261102T013653Z/soak20-recovery/replay-profile/runtime` | Store `cd75803b-5046-4f05-9787-17f0457944cc`; Prediction406 / PENDING4 |
| API | 2026-10-27 / OFFLINE_PCAP, REAL_API | `.git/ai-pipeline-integration-20261027-1/actual-api-e2e` | Incident `a79cecb6-9b8e-4c21-a55a-5caf7b150400` |
| Authentication IF | 2026-10-27 / FIXTURE, SCRIPTED, actual IF inference | `.git/offline-ai-e2e-20261027-1/authentication-after-context-fix` | Incident `97720933-47db-4111-b4f7-8c5346aa1ced` |
| Authentication 실패 | 2026-11-04 / FAILED_RUNTIME, READ_ONLY | `.git/full-reliability-stabilization-20261104T021605Z/final-verified/candidate/native/future-runtime/authentication` | Incident `c1f2c795-642b-4c38-b60a-6217922f9db6` |

Native Runtime 아래 TCX capture Session은 `b8c0e4bf-f085-540d-bf0b-ff1b66d8c1b3`, `6c75f1f0-feca-5575-b259-9030c89e406c`이며 DNS capture Session은 `0771bfdf-3f98-4181-b21e-3b15772e15c8`다. 이를 하나의 capture Session UUID로 합치지 않는다. API와 IF 원본의 Session 필드는 null이며 Incident ID로 추적한다. PCAP 입력 이벤트의 2018년 시각과 API 실행일을 구분한다.

10월14일 실제 journald + 실제 LLM 성공 보고서도 확인했다: `docs/linux-soc-v1/real-llm-continuous-e2e.md`. 864개 journal 기록, 인증 이벤트1, READ Tool1, API2, info/0.65가 보고돼 있다. 당시 `/tmp/soc-continuous-real-*` 원본은 현재 찾지 못했으므로 그 보고서만으로 검증된 결과 DB를 재구성하지 않았다. 11월4일 별도 Host 읽기 진단의 16건/rc0도 실패 Runtime READY 또는 IF 성공을 뜻하지 않는다.

IF는 실제 저장 영수증을 재사용하므로 새 mock IF 점수를 생성하지 않는다. 10월28일 저장 결과 후보는 현재 검증기의 `OFFLINE_NORMALIZED_INPUT_MISMATCH`로 거부돼 채택하지 않았다. 검증을 완화하지 않고 기존 검증기를 통과한 10월27일 자료를 선택했다.

## 값·그래프 연결표

| 화면 항목 | 데이터 연결 / 의미 |
|---|---|
| Network 카드 | Native observation.metrics.packets = 54 |
| Network 그래프 | 원본 Flow7의 packet_count 총54를 시연 시간에 맞춰 점진 공개. 중간 패킷 도착 간격은 presentation pacing이며 실측 처리율이 아님. 실제 header 표본14개만 feed에 표시 |
| DNS 카드·그래프 | 원본 recent_events의 QUERY3/MATCHED_RESPONSE3를 기록 순서대로 공개; 표시 간격은 시연 시간. TRANSPORT_CONTROL8과 구분 |
| RF/LR 카드·그래프 | 검증된 inference 영수증 각4개, 원래 inferred_at·latency_ms·model fingerprint |
| Assessment 그래프 | Task별 실제 severity, info=0을 결측으로 취급하지 않음 |
| LLM 조사 패널 | 별도 API 원본의 실제 plan.goal / plan.steps / assessment.threat_assessment를 순차 공개. 시연 중 API 호출0 |
| Investigation 그래프 | 저장 plan의 completed Tool 수. 없는 checkpoint sequence를 합성하지 않음 |
| Memory / CPU 카드 | 원본 Runtime peak RSS 243347456 bytes(232.1MiB), 누적 CPU28.720216967초 |
| Authentication 카드 | 별도 저장 IF 영수증1/42입력/점수0.9667을20초까지 공개; Native 수집과 합산하지 않음 |
| Queue backlog 카드 | 입력 도착을 배치한 시연 전용 queue; 원본 최종값0은 변경하지 않음 |
| Authentication IF 표 | 영수증의 normalized_anomaly_score 0.9666666666666667. classifier confidence가 null인 것을 대신 파싱한 실제 IF 순위이며 공격 확률 아님 |
| System CPU% / RSS 시간 그래프 | 사용자 요청으로 보완한 deterministic mock, 60표본. 현재/과거 실측으로 저장하지 않음 |
| System Queue / Drop / Gap 시간 그래프 | 변화 이력이 없어 presentation mock 사용. 원본 종료 counter는 상세에 별도로 유지 |
| System Rate / Token 그래프 | 원본 기록이 없어 presentation mock 사용 |
| Authentication 원본 실패 | SOURCE_UNAVAILABLE, NOT_INFERABLE, 수집0, Runtime cleanup UNVERIFIED 유지 |
| Raw frame·전역 Kernel drop·DNS9 | 원본의 UNKNOWN/BLOCKED 의미를 유지. 기술적 성공을 새로 만들지 않음 |

Mock 수식과 범위는 `unified_metrics.demo_telemetry()`에 고정돼 재실행해도 동일하다. 보완 데이터는 그래프 전용 객체에만 존재하고 Incident State, 원본 snapshot, SQLite, Audit, model receipt에 쓰이지 않는다. 화면의 System 그래프는 원본 데이터의 증명이 아니다.

## 실행 경계와 Manifest

`show-demo` 파일은 변경하지 않았다. `evidence_viewer.py`의 unified 분기만 새 조회 화면을 실행한다. 통합 화면은 기존 Desktop을 상속하지만 실행 가능한 Worker/Backend를 생성하지 않는다. read 명령은 미리 검증된 report 선택으로 제한한다. 실행·승인·export 버튼은 비활성화한다.

기존 파일 SHA를 시작 시 검증하고, 원본 SQLite는 mode=ro로 연다. 새 API·Root·Native capture·모델 실행·승인 영수증 발급은 없다. Reconnect는 검증과 조회만 다시 수행한다. Manifest는 런타임에 자동 생성하거나 갱신하지 않는다.

이번 명시적 Manifest 변경: entry 파일 해시1개 갱신, 통합 표시 모듈3개 추가, 별도 IF 원본 파일 및 보호 경로 추가, presentation telemetry 및 재생 시간 배치의 출처 명세 추가. 원래 Native·Replay·API·Authentication 파일 해시와 네 view 정의는 유지한다. 실제 비교는 `unified-validation/manifest-amendment.json`과 `integrity.json`에 기록한다.

## 검증과 예비 시연

검증 결과는 [Validation](Unified_Validation.json), 실제 스크린샷은 [화면 모음](unified-validation/index.html)을 참고한다. PNG는 실제 Tk 창을 캡처했으며 생성 이미지가 아니다.

```bash
# GUI 없이 모든 고정 파일 검증
./releases/evidence-demo-20261104/show-demo unified --check

# 기존 네 화면도 유지
./releases/evidence-demo-20261104/show-demo native
./releases/evidence-demo-20261104/show-demo replay
./releases/evidence-demo-20261104/show-demo api
./releases/evidence-demo-20261104/show-demo authentication
```

WSLg 문제가 있으면 `docs/unified-validation/index.html` 또는 개별 PNG로 발표한다. 이는 정적 예비 자료이며 새로운 Live 실행이 아니다. 이 시연은 이 PC의 원본 Evidence 경로와 `releases/research-mvp/.venv`에 의존하므로 저장소만 복제해서 다른 PC에서 바로 실행되는 portable 배포본은 아니다.
