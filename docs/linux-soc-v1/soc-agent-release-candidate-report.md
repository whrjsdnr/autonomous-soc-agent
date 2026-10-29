# Autonomous SOC Agent — Release Candidate 검증 보고

2026-10-29, `feat/continuous-runtime`. **판정: RELEASE_CANDIDATE_READY.**
**OPERATIONS_VERIFIED는 선언하지 않는다.** 이번 작업은 일반 사용자 개발·Replay·장애 주입·
GUI·빌드 검증이며 Root 설치, Namespace 진입/변경, Native Capture, DNS, Host 인증 로그 수집,
실제 외부 API 호출, 서비스 변경, 실제 실행 예약, 운영 정책/실행 영수증 발급·소비는 모두0이다.
회귀 테스트의 임시 합성 영수증·Ledger는 운영 승인/기존 증거와 구분한다.

운영 코드 Commit: `a3d1aaaa98515c6dd752a305a690af8b56c7bd0c`.
보존된 실제 Capture 코드는 `608c03e`; 이후 표시 집계 기준선은 `e3412e8`이다.
현재 RC로 새로운 Kernel 시험을 수행했다고 보고하지 않는다. 기존 설치된 BPF/Provider/Root
service/policy/unit은 성공 시험의 바이트와 동일하며 이번에 교체하지 않았다.

## 구현과 수정

기존 `ContinuousRuntime`, `TCXProducer`, Persistent Queue/Store, `AnalysisService`, 기존
Model Registry/Adapter, `OfflineWorkflow`, Policy/Approval/Executor, Planner/Tools/Assessor,
Audit/`verify_result`, Tkinter GUI를 재사용했다. 새로운 승인·예산 프레임워크는 추가하지 않았다.

```text
Collector Supervisor / TCX·DNS·저장 Authentication
→ Durable Event Queue / Cursor / Deduplication
→ Flow·Window / Capture Attestation / Eligibility
→ 별도 승인된 Native 모델 Action 또는 Replay 모델 분석
→ RF/LR·Authentication IF / Evidence Fusion / Incident
→ 읽기 전용 대응 / LLM 조사 계획·도구·평가
→ immutable 결과·Audit / GUI
```

| 확인된 문제/요구사항 | 운영 코드 수정과 검증 |
|---|---|
| 오래된 서비스 Heartbeat에 과거 LIVE 표시가 남음 | `continuous.cli.status`가 현재 LIVE를 취소하고 Collector/Worker를 UNKNOWN_STALE_HEARTBEAT로 표시. 마지막 관측은 별도 필드로 보존하며 원본 State를 덮어쓰지 않음 |
| Collector task의 Cleanup 예외가 gather에서 유실 | task 종료 예외를 정리 실패에 포함. 두 번째 close 성공으로 앞선 실패를 지우지 않고 UNVERIFIED·최초 오류·Audit 보존 |
| 미확인 Cleanup 후 새 ordinary Start 가능 | 기존 code/Scope/lock 검증에 더해 UNVERIFIED 또는 stale service loss 상태는 프로세스 생성 전 차단. 자동 복구 승인/Root 권한 부여가 아님 |
| Collector와 AI 건강 상태 구분 부족 | 인증 Root 메시지 시각, Collector 이벤트 시각, Worker supervisor 관측·자식 실행/종료 상태를 구분. 모델 실행 대기 중에도 관측 갱신; 모델 진행률/성공으로 가장하지 않음. 연결 재시작 시 과거 heartbeat 초기화 |
| Native Incident 조사 context의 명시적 연결 부족 | Incident/job/Session/Namespace/Window/Flow Identity와 모델 provenance를 조사 context에 연결. 로컬 `investigation-context.json`·Audit binding을 보존하고 변조 시 verify_result 거부. 기존 보고서의 이전 형식은 재작성 없이 검증 지원 |
| Dashboard/System에서 Continuous 상태 확인 어려움 | 독립 Continuous Collector/Native·Replay/Packet/Window/Eligibility/AI/Queue·Drop/Incident/Cleanup 요약 추가. 기존 진단 그래프와 합쳐 가짜 packet rate를 만들지 않음 |
| 보존 Native 결과가 일반 Offline 분석과 혼동될 여지 | AI Analysis에서 REAL_NATIVE 입력은 RETAINED_NATIVE / not live capture로 표시. 실제 LIVE 결과로 승격하지 않음 |
| 오류 요약의 민감 문자열 | Continuous 요약의 오류에도 기존 display redaction 적용. GUI 테스트의 가짜 password 문자열이 화면에 노출되지 않음 |

Worker 장애는 기존 bounded circuit/POISON/명시적 reset 경로로 처리한다. 실제 자식 exit17 이후에도
Collector가 계속 수집하고, 실패 job을 재실행하지 않은 채 다음 독립 Auth job이 실제 IF 모델로
처리되는 회귀가 통과했다. 실제 Kernel Collector 자동 재시작은 활성화하지 않았다.

## 장시간·장애·복구 검증

| 검증 | 입력/실행 구분 | 결과 |
|---|---|---|
| 72분 상당의 봉인 Window | SYNTHETIC event time, 25개 독립 Window. 실제 Kernel/72분 벽시계 soak 아님 | Counter·Clock·epoch·seal·기존 Eligibility 재검증, 중간 transcript 재구성, 결정적 job identity·Replay 거부 PASS. Window 사이 미관측 구간의 연속 coverage는 주장하지 않음 |
| 5시간 상당 Packet Replay | SYNTHETIC event time, 기존 600-event 테스트 | 적격 Flow599개, capacity1 Queue의 명시적 Drop598개, Flow 메모리 경계·Native가 아님을 검증. 무손실 결과로 보고하지 않음 |
| 5,000-event 내구성 | SYNTHETIC 저장/중복/커서 처리, 실제 SQLite FULL 내구성 경로 | Workspace333.78초 / Export334.50초 벽시계, 각각 PASS. packet/AI 처리량 benchmark나 실제 장시간 운영으로 해석하지 않음 |
| Collector 실패 | 모의 Collector 경계, 실제 Runtime loop | bounded recovery·circuit·최초 오류 보존·정상 Stop |
| Worker 장애 | 실제 ordinary 자식 exit17, 정상 다음 작업은 실제 Auth IF | Collector 유지, Queue POISON 보존, 명시적 reset 후 다음 job 처리 |
| Queue·Cursor·Restart | 저장 이벤트/실제 Persistent Queue | Full/Backpressure/Drop, partial handoff/crash 재구성, dedup·idempotency·cursor resume PASS |
| 저장소 장애 | 격리된 DB/모의 ENOSPC·손상 입력 | 실패 전 cursor 게시 차단, checkpoint/segment/archive 변조 거부, 정리 예외 보존 |
| Clock·Model | Fixture/저장 데이터, 실제 검증 코드 | clock/epoch/counter/drop/partial Window/schema/model 오류에서 추론 차단 |
| API 장애·위험 plan | 기존 Provider Adapter + FAKE_HTTP transport, 실제 호출 없음 | timeout/전송 오류/RateLimit/Usage·비용 경계/잘못된 도구·사실 승격·재시도 차단 PASS |
| 정상 Stop/Cleanup | ordinary 실제 서비스·소유 자식/Unix transport 경계 테스트 | graceful stop, Queue 상태·입력 보존·Audit, cleanup 실패 시 UNVERIFIED/재시작 차단 |

첫 통합 테스트 실행은 장시간 케이스와 넓은 Controller 회귀가 합쳐져420초 runner 한도에
도달했다. 부분 로그를 보존했고 테스트 Assertion/내구성/품질 기준을 바꾸지 않았다.
동일 5,000-event 테스트를 별도900초 한도에서 완료하고 나머지 회귀를 별도600초 한도에서
완료했다. 무제한 재검증이나 실제 Kernel 재시작은 수행하지 않았다.

## Native Incident와 LLM·대응

기존 Native 성공 증거와 이번 Fixture/Replay를 분리한다.

- 기존 실제 Native: Event20, seal2(callback20/0), ELIGIBLE1/INCOMPLETE1,
  실제 RF/LR Prediction2, Incident1, SCRIPTED 조사·읽기 전용 도구·평가·Audit·GUI·Cleanup VERIFIED.
  Incident `c37a311d-436d-57eb-a698-3166f1b7dd6b`. 이번에는 결과·원본 inference receipt·Audit를
  읽기 전용으로 다시 검증했다. 마지막 INCOMPLETE Flow를 승격하지 않았다.
- 현재 코드의 context 연결: 봉인 Fixture + 실제 RF/LR + 기존 SCRIPTED Client로 계획·평가까지
  검증했다. 두 단계가 동일 Incident/Window/Flow/model digest를 받으며 context 파일 변조는 거부된다.
  이것은 현재 RC의 실제 Native Capture 또는 외부 생성형 API 실행 검증이 아니다.
- 기존 실제 API 성공은 별도 Offline PCAP Incident
  `a79cecb6-9b8e-4c21-a55a-5caf7b150400`, 원래 REAL_API2회·Prediction2개다.
  이번에는 읽기 전용으로 재검증했을 뿐이며 Native API 조사 성공으로 보고하지 않는다.
- 외부 Provider의 기존 allowlist 최소화 projection은 그대로다. 전체 Source·계정·도메인을
  전송하지 않으며 추가된 상세 provenance는 로컬 context와 digest로 결합한다.
- 알려진 `FEATURE_EXTRACTION_INTERRUPTED`는 저장 입력을 기존 read-only Policy에서1회
  재검증한다. 실패 시 중단, 중복 시도 거부. Collector/Host/방화벽을 복구했다고 주장하지 않는다.
- 모델 점수는 미보정 연구용 advisory이며 정상 TCP 시험의 UNKNOWN_ANOMALY가 공격임을
  입증하지 않는다. LLM 가설과 관측 사실을 분리하고 임의 Shell/위험 대응은 실행하지 않는다.

## GUI 결과

Workspace/Export 각각 실제 Tk 테스트 **4 PASS**:

1. ordinary Replay 서비스 Start/중복 Start 거부/GUI 종료·재연결/명시적 Stop·Cleanup.
2. 실제 모델을 사용한 Packet·DNS·Auth Fixture Incident/조사/평가·Audit 표시.
3. 합성 stale Native 상태의 LIVE 취소와 Worker circuit/Queue·Drop/Cleanup 실패 표시,
   Dashboard/System 갱신·오류 redaction.
4. 보존된 실제 Native Incident의 Prediction2·SCRIPTED 계획/도구/평가·Evidence/Audit 표시,
   종료·재연결. 가져온 보고서는 새 Worker를 시작하지 않으며 RETAINED_NATIVE로 표시.

GUI에서 Root 명령을 직접 실행하거나 API 키를 입력/출력하지 않았다. Source 정상·이상 분석,
모델 오류·API 장애·정리 실패는 각각 실제 Backend 회귀와 GUI 상태 투영으로 검증했으며,
합성 화면 상태를 실제 LIVE 장애 시험으로 보고하지 않는다.

## 테스트·빌드·Manifest

| 항목 | Workspace | 독립 Export |
|---|---:|---:|
| Continuous/Attestation/모델/조사/API 오류/Controller/Namespace/READY/Approval·Ledger/Supervisor 관련 회귀 | 315 PASS | 315 PASS |
| 별도 5,000-event 내구성 | 1 PASS | 1 PASS |
| 실제 Tk GUI | 4 PASS | 4 PASS |
| 추가 Provider/Network/Timeout 오류·민감 정보 차단 단위 검증 | 3 PASS | 3 PASS |
| Native 산출물 | 6개 SHA 일치 | 6개 SHA 일치 |
| Wheel | SHA 일치 | SHA 일치 |

각 환경 합계 **관련323 PASS**이며 저장소 전체 테스트 전부를 실행했다는 뜻은 아니다.
Controller 생성기는 합성 Namespace Scope의 실제 기존 builder를 동일 입력으로 두 번 호출해
2개 파일 재현성을 각 환경에서 검증했다. 이는 실행/정책 승인이 없는 compile-only 증거다.
검증용 임시 산출물 중 보존 가능한 실제 파일 쌍을 RC 증거에 복사했다.

Ruff/Format/Diff PASS. 실제 Wheel을 별도 디렉터리로 추출해 `-I` Python에서 모든 import가
추출된 package 내부임을 확인하고, 보존 Native 결과 재검증과 BTF/libbpf 파일 parse를 수행했다.
편집 checkout fallback·새 Kernel load·모델/API 호출은 없다. 최종 Wheel의 package 바이트는
Source manifest의653개 파일과 전부 일치한다.

공통 Git 디렉터리 `soc-agent-rc-20261029T015342Z/`에 다음을 보존한다.
`final-source-files.json`, `artifact-manifest.json`, 최종 `release-manifest.json`,
`model-manifest.json`, Workspace/Export 테스트 로그, 두 환경 Native/Wheel,
Controller builder 증거, 기존 성공 보존 해시 및 최종 검증 파일.
초기 빌드 기록은 유지하며 README 포함 최종 Wheel은 `wheel-final-*`에 별도로 생성했다.

| Identity | SHA256 |
|---|---|
| Source653개 canonical file-map | `3d6dcb836c07bc2bbdef1f90f89b3b04886072dc266ec45fd5d09c11bdb57ce5` |
| Source manifest 물리 파일 | `29cb5cd86c1b2a2774c17182c648dd2e37cb480ec2f62fdcd2fcab79767c4377` |
| 최종 Wheel | `ee5bd7624b26c0537fae83ebeb89eda7b6a96ce0a99900a5097bcb3dd1534ef8` |
| Model manifest 물리 파일 | `26df75bba7b071b7079c8cb994c9ea2bbde39a610aa787a480141744b39cdb80` |
| BPF | `da58d00289ce04a3c818f8ca5b776f1b2fccaaef9b96f324f60a24904bcde8f6` |
| Provider | `62e4610379f9dc3b8f2a5fb070009dfcdcdbf2c1a5a0f6d76c0c2a22b6296bff` |
| Root service | `9a259bf55d1d8f1d88b86860fdc9ac9986fefea0958cc1435d8788f28e372119` |
| Root policy code | `cb050423f29747e7b0ab96b89248ad5893eea1e8c9c8bb24edc1f0c5585b3d53` |
| Root unit | `df58418162abcc539103453345c889d6b133f153935d15ad6a3251020826a033` |
| Runtime dependency manifest | `431f2854bdd2c515f47ad60784263b1446305b1b515108ab5a898aef313ee7fb` |

모델 manifest에는 RF/LR 실제 model file SHA·canonical model manifest digest·물리 manifest SHA와
Authentication IF 패키지 파일 SHA를 각각 기록했다. 기존 모델 input fingerprint/schema 검증은
유지했다. Manifest canonical digest와 JSON 파일 SHA를 혼동하던 초기 검증 스크립트의 오류를
수정했으며 모델/Loader의 기존 검증 기준은 변경하지 않았다. 실패 로그도 보존했다.

## 보존·운영 위험·다음 승인

- 기존 Native/실제 Offline API 성공 파일·설치·Lease·Ledger81행·과거 FAILED/false/UNKNOWN은
  보존 해시와 최종 재대조한다. Rollback 생성 증거는 보존하며 Root 전용 백업 내용을 이번에
  권한 진입해 재조회하지 않는다. 새 정책/예산/실행 영수증을 발급하거나 Ledger를 변경하지 않는다.
- 실제 장시간 Kernel/고부하/운영 장애·복구 시험은 미수행이다. 5,000-event SQLite 테스트 시간은
  이 테스트 환경의 내구성 비용이며 목표 처리량·실환경 손실률 보장이 아니다.
- Native 서비스의 metadata는 payload를 보관하지 않지만 저장 PCAP/인증 자료는 개인정보를
  포함할 수 있다. private permissions/redaction은 암호화가 아니다. 보존·암호화·삭제 정책은
  운영 결정을 요구한다. 현재 archive는 원본을 삭제하지 않으므로 공간 부족을 자동 해결하지 않는다.
- DNS9 학습 추출 계약은 INCOMPLETE, 실제 Host Auth 수집은 미검증, 모델은 RESEARCH_ONLY다.
  매 Window의 exact 모델 Action, 임계값/정확도 및 무인 운영 정책을 임의로 승격하지 않는다.
- 과거 Program1145 UNKNOWN·전역 Cleanup UNVERIFIED를 이번 비권한 검증으로 해소했다고
  보고하지 않는다. 기존 trial의 systemd oneshot RuntimeMaxSec 경고는 TimeoutStartSec90초가
  실제 상한을 유지하는 비차단 설정 경고이며 이번 승인 범위 밖의 unit을 변경하지 않았다.
- 다음 실환경 시험에는 Continuous 전용 Namespace/Interface/파일·자원·시간·수집량 승인,
  최신 Artifact/Runtime/Ledger/Lease 및 필요 R1, 모델 Action, 트래픽 생성 시 구체 Scope,
  사용자 확인·터미널 인증·전후 Cleanup 비교가 필요하다. 실제 API는 별도 Provider/입력/호출 범위
  승인을 요구한다. 기존240초 승인을 장시간 권한으로 재사용하지 않는다.

실행·Stop·업데이트·Rollback·Quota/손상/Worker/Collector/API/Cleanup 복구 절차는
[RC Runbook](soc-agent-release-candidate-runbook.md)에 정리했다.
최종 Git Commit/Tree·Push·보고서 SHA는 같은 RC 증거의 `final-verification.json`에 고정한다.
