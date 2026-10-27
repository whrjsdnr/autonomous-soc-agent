# Autonomous SOC Agent — AI Pipeline & Investigation Integration

2026-10-27. Branch: `feat/ai-pipeline-integration`. Source baseline: `0ca627d36108b0739fafbb4c761e68870e04cacb`.

**실제 PCAP → Network14 → 실제 RF/LR → 실제 API 계획 → READ-only 도구 → 실제 API 평가 → Incident/Audit 경로를 검증했다.** 실제 API는 이번 요청 전체에서 정확히 2회, 재시도 0회다. Raw DNS는 저장된 실제 UDP 증거의 파싱·상관분석까지 연결했으며, DNS9 학습 추출법이 없어 모델 입력은 `INCOMPLETE`로 유지한다. Native·운영 승격 성공으로 해석하지 않는다.

## 실제 운영 경로와 기존 기능 재사용

```text
soc-agent analyze-offline --input <pinned job> --input-sha256 <SHA> --output <new directory>
  → JOB schema / retained input
  → existing ResearchAdapter or packaged model adapters
  → input quality + feature/model compatibility
  → immutable inference receipts / advisory classification / fusion
  → existing PolicyEngine + GovernedExecutor (read-only)
  → existing InvestigationPlanner
  → explicit OpenAICompatibleClient + scoped API budget
  → existing plan normalization / InvestigationOrchestrator
  → existing ThreatAssessor / evidence reference validation
  → Incident / audit chain / persisted result verification
```

새 Orchestrator, 모델, 승인 시스템, Shell 도구를 만들지 않았다. 기존 Model Registry·Package Loader·RF/LR 연구 Worker·Network/Auth Feature Extractor·Fusion·Policy·Approval·Tool Registry·GovernedExecutor·Planner·Assessor·RuntimeGovernanceStore를 재사용한다.

| 구성 | 실제 상태 / 검증 범위 |
|---|---|
| Network PCAP / Flow / Network14 | 기존 PCAP reader·producer·pinned replay 재사용. 실제 저장 PCAP 2개 Flow를 정상/이상 사례로 사용 |
| TCX / Capture·Clock·Flow Eligibility | 기존 구현 보존. Native checkpoint의 품질/정책 차단 유지; 새 Capture 없음 |
| DNS parser / correlation | 기존 `dns_message`를 재사용해 저장 wire transcript를 운영 CLI에 연결. UDP 실제 증거, TCP 완결 메시지 Fixture |
| DNS9 INT8 | 기존 9개 이름·순서·모델 SHA 재사용. 기존 Feature Fixture 추론은 성공; Raw DNS → DNS9 추론은 차단 |
| Network XGBoost / IsolationForest | 기존 5개 Feature 전용 모델. Synthetic 정상/공격/이상 입력에서 실제 추론. Network14를 5개 입력 모델에 넣지 않음 |
| Authentication IF | 기존 Authentication Feature/실제 모델/Fusion 경로 보존. Synthetic 인증 42개 이벤트 회귀; 실제 인증 AI/Native 검증으로 표시하지 않음 |
| Evidence Fusion | 기존 모델별·도메인별 계약 유지. 모델 점수를 공격 확률로 평균하지 않음 |
| 생성형 조사 | 실제 API Planner/Assessor 각각 1회. 기본 모드는 SCRIPTED 유지; 주입 Fake Transport 테스트와 구분 |
| Known-error recovery | 기존 `FEATURE_EXTRACTION_INTERRUPTED` 입력 재검증 1회. Collector 재시작·Host 복구·보안 차단 아님 |
| Response | READ-only Source continuity. 실제 방화벽·서비스·계정·네트워크 변경 없음 |

## 실제 API E2E

사용자가 기존 키 사용과 이번 요청의 **실제 호출 최대 2회, 비용 상한 없음**을 명시했다. 키는 기존 비추적 `.env`의 `SOC_LLM_API_KEY`를 사용했다. Endpoint는 `https://api.openai.com/v1`, 설정 모델 alias는 기존 검증 문서의 `gpt-5-mini`다. 별도 인증/연결 테스트 호출 없이 본 조사 2회에만 사용했다. 응답의 서버 모델 snapshot ID는 기존 Adapter가 보존하지 않아 특정 snapshot 실행을 주장하지 않는다.

원본 실제 PCAP SHA256:

`80dcc2602519479ddcde889fa902fee19a76696630811452f8df38888af894f2`

기존 pinned replay Flow index 3에서 Network14를 생성했다. `quality_rf`와 `edge_lr`가 모두 `CLASS_1`을 반환해 `UNKNOWN_ANOMALY`로 분류했다. 이는 연구 모델의 advisory이며 공격 확정이나 독립 성능 측정이 아니다.

| 모델 | 실제 Artifact SHA256 | 결과 |
|---|---|---|
| `linux-network14-research-v1-quality_rf` | `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` | CLASS_1 |
| `linux-network14-research-v1-edge_lr` | `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882` | CLASS_1 |

각 추론 Receipt에 Feature fingerprint·model manifest·원본 출처 참조·실제 latency를 보존했다. 14개 Feature의 실제 이름·값·단위는 기존 pinned producer 계약에서 취득하며 임의 Adapter로 모델 호환성을 선언하지 않는다.

| 단계 | 실제 결과 |
|---|---|
| 1차 API | 2026-10-27T19:25:59.826261+09:00 시작. 구조화된 가설 2개·검증 방법·필요 증거·예상 결과·미확인 사항·권고 반환 |
| 계획 검증 | 기존 최대 2 step, 도구 allowlist, Tool input schema, Incident/Evidence UUID Binding 통과 |
| 도구 | `read_local_source_report` 1회 completed. 실제 GovernedExecutor / READ-only Policy 경유 |
| 2차 API | 2026-10-27T19:26:17.034025+09:00 시작. 실제 도구 증거를 포함한 별도 평가 |
| 평가 | severity `info`, confidence `0.25`; 내용이 제한돼 위협 판단 불충분. 가설은 미검증 해석으로 유지 |
| Incident | `a79cecb6-9b8e-4c21-a55a-5caf7b150400`. 관측 사실로 승격한 모델 출력 0개 |
| 완료 | `COMPLETED_READ_ONLY`. Incident·평가·요청/응답·Audit 재열기 검증 성공 |

실제 도구는 보존 입력의 연속성을 확인한다. 프로세스/EDR/Host 로그를 새로 조사했다거나 두 가설을 독립적으로 입증했다고 주장하지 않는다. LLM의 추가 증거 요구는 계획으로 남고, 등록되지 않은 조사나 대응은 실행되지 않았다. 평가 confidence는 보정된 공격 확률이 아니다.

### Token / 비용 / 실패 계약

| 실제 호출 | Prompt tokens | Completion tokens | Latency |
|---|---:|---:|---:|
| Planner | 1,335 | 1,919 | 17,166ms |
| Assessor | 1,429 | 1,686 | 13,392ms |
| 합계 | 2,764 | 3,605 | API 2회 |

공식 단가는 1M token당 입력 $0.25 / 출력 $2.00이며, 두 응답의 Usage에 적용한 표준 단가 추정 합계는 **$0.00790100**이다. Cached input 할인·청구서 대조는 하지 않았으며 실제 결제 금액으로 확정하지 않는다. [공식 OpenAI 모델·단가·Structured Outputs 문서](https://developers.openai.com/api/docs/models/gpt-5-mini)를 확인했다. 모델 alias를 더 최신 모델로 자동 대체하지 않았다.

기존 Adapter의 HTTPS·redirect 거부·SecretStr·1MiB 응답 한도·Schema 검증·자동 Retry 0회를 유지한다. 이번 설정은 요청당 120초 / Completion 최대 4,096 token / 동시 요청 1개 / 최소 간격 1초 / 총 2회다. HTTP rate-limit, timeout, 인증/Schema/Usage 오류는 추가 요청 없이 중단한다. Timeout을 서버 측 취소나 무료 요청으로 해석하지 않는다.

일반 API 설정에서는 양의 USD 상한을 요구하며, `budget_usd: null`은 명시적으로 비용 상한 없음을 뜻한다. 필드 누락을 무제한 승인으로 해석하지 않는다. 금액 제한이 있으면 전송 전 UTF-8 요청/Schema 크기+overhead 및 최대 completion의 보수적 예약을 검사한다. 이는 로컬 제한이며 Provider 청구 강제 상한을 보장하지 않는다. Usage가 없거나 예약을 초과하면 후속 호출을 중단한다.

## API 운영 코드 변경

- `security_ai/api_investigation.py`: 기존 Provider를 감싸는 명시적 API composition. 입력 SHA·새 출력 디렉터리·승인 참조·시간 범위·모델/endpoint·호출/비용 한도 Binding; 구조화된 조사 계획·가설 Schema; 개인정보 최소화; 요청 전 Audit; Usage·응답·실패 Receipt; 재열기 검증.
- `planning/planner.py`: 기본 계약을 유지하는 선택적 확장 Draft. 모든 확장 필드를 검증한 뒤 `goal/steps`만 기존 실행계획 validator에 투영. `last_draft`는 검증 성공 후에만 보존.
- `security_ai/offline_workflow.py`: 실제 API와 기존 Planner/Executor/Assessor 연결. `REAL_API`와 SCRIPTED/주입 Client를 구분. 입력과 원본 모델 Receipt 보존, 응답/실패 Receipt의 Audit Binding 검증.
- `security_ai/offline_analysis_cli.py`: 기존 명령에 `--api-authorization`와 `--api-env-file`을 명시적으로 제공하는 경로 추가. 기본 API 자동 호출 없음. `--verify`는 키·API 호출 없이 동작.
- `security_ai/workflow_models.py`: REAL_API 결과와 Raw DNS 입력을 기존 Job/Outcome Schema에 연결.
- `security_ai/dns_transactions.py`: 기존 DNS parser 기반의 제한된 wire transaction 분석. DNS9 추측 벡터를 생성하지 않음.

정확한 API 승인 파일과 새로운 출력 경로가 없으면 실행되지 않는다. 같은 출력 디렉터리 재사용은 거부한다. 이번 승인 파일의 재사용·확장은 새 호출 승인으로 취급하지 않는다. Native/Root 승인 계약은 수정하지 않았다.

### 외부 전송과 안전

LLM에는 raw PCAP, DNS 이름, IP 주소, 계정, 원본 로그를 전송하지 않았다. Evidence UUID·local digest·허용된 도구 Schema·제한된 모델 결과·정해진 read-only 결과 코드만 투영했다. 원본 증거와 전체 모델 Receipt는 private 디렉터리에 남겼다.

모델 출력은 관측 사실이 아니며, API가 `observations`를 만들어내면 거부한다. 계획은 기존 Tool input·allowlist·Policy로 재검증한다. LLM의 임의 Shell 실행·위험 대응 권한은 없다. 가설/권고는 설명이며 Human approval을 대신하지 않는다. 정확한 키 값과 private JSON/SQLite/Worker 증거를 메모리에서 비교해 키 비노출을 확인했고, 테스트 출력·Git에도 키를 기록하지 않았다.

초기 로컬 모델 실험은 사용자 API 전환 지시 후 중단했다. 실험 파일·환경은 제거했고 운영 코드·Wheel에 로컬 LLM Module/Dependency가 없다. 로컬 모델 추론 성공을 주장하지 않는다.

## Raw DNS → DNS9

기존 parser는 DNS UDP와 **단일 완결 length-prefixed TCP 메시지**의 Question metadata를 처리한다. 이를 `raw_dns` Job으로 연결했다. Query/Response에는 protocol·양 endpoint·transaction ID·QTYPE/QCLASS·상관분석용 ASCII 소문자 이름·Capture source SHA·Clock epoch를 Binding한다. 원문 이름/이름 digest를 보존하며, 소문자 변환을 DNS9 학습 전처리로 선언하지 않는다. Query/Response timestamp·duration·RCODE·packet reference·영수증 digest를 남긴다.

분할 TCP/복수 메시지 stream은 `INCOMPLETE_TCP_REASSEMBLY_REQUIRED`로 거부한다. 완전한 TCP 재조립이나 Resource Record 검증은 구현했다고 주장하지 않는다. 이름 압축/경계 검증은 기존 parser 책임이고, 이 경로의 의미는 Question metadata correlation이다. 중복 source ID·Clock 역전·다른 QTYPE/TID·중복 Query/Response·불완전 메시지를 정상 거래로 꾸미지 않는다.

실제 저장 PCAP SHA:

`4d0a00c33a4bf11228158baddd47c38f702731ea8d75ef1201061fc8bbd878b9`

기존 ML PCAP reader로 50,156개 레코드를 읽고 기존 Packet parser로 추출한 UDP DNS 메시지 **1,162개**를 CLI에 입력했다. Non-IP 8,949개는 지원 밖으로 계수했다. 원본 PCAP·packet index·frame digest·wire transcript SHA를 별도 보존했다. Transcript의 원본 연계는 `DECLARED_UNATTESTED`이며 Native 암호학적 출처 증명은 아니다.

- strict metadata matched response: **331개**
- Query: 600개; ambiguity Query 재전송/ID 재사용: 205개; ambiguity 후속 관측: 26개
- unmatched pending Query: 64개
- 같은 key의 재사용은 보수적으로 모호성으로 남겼다. DNS 거래 전체의 재구성 정확도 수치가 아니다.
- 실제 이 PCAP의 DNS는 UDP다. TCP 실제 PCAP 검증으로 표시하지 않으며 TCP는 wire Fixture 회귀 범위다.

DNS9의 정확한 순서는 `FQDN_count, subdomain_length, numeric, entropy, special, labels, labels_max, labels_average, len`이다. 기존 모델 계약에는 **모든 항목의 학습 추출법/단위가 UNVERIFIED**이며, upstream raw-domain extractor가 없다. 따라서 7개 lexical feature를 9개로 늘리거나 임의의 count/window를 만들지 않았다. 모델 SHA `28e089af363dd565a4fb3d3f202de9e9f9804bd14a164de4fd7b61adb1201e33`의 기존 Feature Fixture 실제 INT8 추론은 CLASS_1이지만, 원시 DNS 1,162개에 대한 추론은 **0회**, 결과는 `INCOMPLETE`다.

Raw DNS → DNS9를 완결하려면 학습 당시 추출 코드와 단위/window 계약, 또는 원시 DNS와 정답 9개 벡터의 검증 가능한 golden pair가 필요하다. 이 누락은 모델 응답이나 합성 Fixture로 대체할 수 없다.

## E2E 사례와 실패 주입

모든 사례는 기존 운영 CLI 또는 그 실제 Workflow/Adapter 경로로 실행했다. 아래 실제 API 사례 외 추가 Provider 호출은 없다.

| 사례 | 입력·모델 | 결과 / 대응 |
|---|---|---|
| 정상 | 실제 PCAP Flow 0, 실제 RF/LR | CLASS_0 / NORMAL / continuity READ / API 0회 |
| 미분류 이상 | 실제 PCAP Flow 3, 실제 RF/LR + 실제 API | CLASS_1 / 생성형 계획 / READ / 실제 평가 / Audit / API 2회 |
| 알려진 위협 label | Synthetic Network5, 실제 XGBoost/IF | BruteForce + anomaly / KNOWN_THREAT advisory / READ-only. 실제 공격 ground truth 아님 |
| 알려진 수집 오류 | Synthetic caller-reported error | 입력 재검증 1회. Collector 수리나 Host 변경 없음 |
| 부족한 Feature | Synthetic missing field | INVALID / 모델 추론 0회 / API 0회 |
| Raw DNS | 실제 저장 UDP PCAP transcript | 331 strict match / DNS9 INCOMPLETE / 모델·API 0회 |
| DNS9 Feature Fixture | 기존 fixture, 실제 INT8 | CLASS_1 / SCRIPTED 조사 / API 0회 |

Fixture/Fake HTTP 실패 주입은 미등록 Shell 도구·위조 Evidence UUID·근거 없는 관측·필수 가설 누락·Schema 오류·인증/Network/Rate failure·Usage 누락/초과·금액 한도·만료·입력/출력 Binding·영수증 변조·Audit intent 저장 실패를 검증한다. API 장애 Mock을 실제 원격 장애 검증으로 보고하지 않는다. 정책·도구 권한·승인 조건을 약화하지 않았다.

최초 테스트 실패 6건은 매번 새로 생성한 Job UUID를 정확한 입력 Binding이 거부한 테스트 오류였다. 같은 입력 객체로 고쳤다. 이후 확장 Draft를 기존 base-only validator에 직접 전달해 거부된 결함 1건은, 전체 확장 Schema 검증 후 실행 필드만 투영하도록 수정했다. 원래 validator의 extra-field 거부를 약화하지 않았다. 모든 실패 로그를 보존했다.

## 검증 / Source / Artifact

| 검증 | 최종 결과 |
|---|---|
| Workspace 관련 회귀 | **1,044 PASS**, 88.96초 |
| 독립 Source Export 동일 회귀 | **1,044 PASS**, 100.50초 |
| 신규 집중 API/DNS 테스트 | **35 PASS**. Fake HTTP transport / Synthetic wire; 실제 API와 분리 |
| Ruff / Format / Diff | PASS / 1,415 files PASS / PASS |
| 재현 빌드 | 두 Wheel 바이트 동일, 676 entries |
| Wheel 재열기 | 실제 API 결과 --verify PASS; 새 API 호출 0회 |
| 보존 검증 | 보호 파일 112개·과거 Native 증거 55개·설치 9개·Rollback 9개 SHA 일치 |

소스 구현 Commit: `081f53e104edde61e263b4ec7c4b9c42ea1142ca`

구현 Tree: `c4f483165bef6791aa5b16d497aad982283aa3db`

Frozen Source SHA256 (1,758개 입력):

`379db891fed35e76995b1d324477910e90d05ec47bcdb49d215a69932ec8c3c0`

Wheel SHA256:

`745f38344a91160df306f274f96f3669c486d67509439a225d897e10bc9728c2`

실제 API 결과 SHA256:

`7b44630fbf54480dc911944b07260c9cfa6c629cdb1e6c88aaae5a7ad981b838`

실제 API 응답 semantic digest (순서대로):

- `cc7ebfca744741612bf4b2b38b0094e3f5d780d84a22f160ddf9222a5d705e5a`
- `eedb52847d72c6c6d867f4ee8eadf325ea99fa0fffb498ec2619dcb1a07f365c`

실제 API 호출 당시 source pin 파일 SHA는 `8ed02dea872789f672f8eab42dec1a8797925b3bb97c836962c3228d803da863`이다. 이후 Raw DNS 분기/영수증 검증·테스트 및 줄바꿈을 추가했다. 최종 Wheel은 Mock 회귀·독립 Export·기존 실제 결과 재검증 범위이며, 최종 SHA로 추가 유료 호출했다고 주장하지 않는다. 실제 호출 제한 2회를 지켰다.

Source map은 자체 참조하는 이 보고서와 기존 사용자 수정 Native 보고서 2개를 제외한다. 보고서는 별도 문서 Commit으로 기록하며 위 구현 Tree와 혼동하지 않는다. 기존 사용자 수정은 Stage/Commit하지 않는다. Native Manifest/Execution Image/Root Manifest를 새로 만들거나 승인 상태로 승격하지 않았다.

## 증거 / Git / Native 잔여 조건

Private 증거 위치: 원본 저장소 `.git/ai-pipeline-integration-20261027-1/`.

- `actual-api-e2e/`: 원본 입력·각 모델 Receipt·최소화 요청·전송 전 intent·API 응답/Usage·Incident 결과·Audit DB
- `actual-api-source-pins.json`, `actual-api-authorization.json`: 실행 시점 코드/사용자 승인 참조
- `actual-stored-dns/`, `actual-stored-dns-extraction.json`: 원시 transcript 연계·거래·모델 차단
- `source-snapshot.json`, `source-export/`, `build-verification.json`, `integrity-verification.json`
- `other-cli-results.json`: 추가 5개 CLI 사례, API 0회

Source·테스트 및 이 보고서만 `feat/ai-pipeline-integration`에 선별 Commit하고 origin에 Push한다. 실증거·API 설정/키·기존 Native 보고서 사용자 수정은 Git에 추가하지 않는다. 배포·Merge를 수행하지 않는다.

캠페인 Ledger는 **26행, SHA `7f61dbdcd8e589e40f8b11d405a435c4057223ab6738005984abbd5902b59c5f` 불변**이다. Campaign Native 4/10·Root 5/10, Batch 3 Native 1/2·Root 2/4를 유지했다. 예약/환급 0건. SOC Namespace `net:[4026532232]`, Host `net:[4026531833]` 불변. 기존 FAILED·false·Program 1145 UNKNOWN·과거 예약 UNKNOWN을 수정하지 않았다. 보호 파일 검증은 원본 공유 저장소 기준이며, 별도 Worktree의 기존 Native 보고서 사용자 변경도 그대로 보존했다.

남은 조건은 실제 Namespace DNS 검증·Native P02 Capture Integrity/P03 Flow Completeness/P04 적격 후보 확보와 정확한 새 Artifact·Scope·R1/R2·Root/Native 승인이다. Native ELIGIBLE 0개라는 과거 판정은 유지한다. Raw DNS9 추론에는 위 학습 계약이 먼저 필요하다. 실제 모델 성능 Ground Truth 평가·원격 장애/과금 정합성·장시간 운영은 미검증이다. API가 계획을 만들 수 있다는 사실과 자율 대응 권한은 별개다. Native AI·DNS9 운영 적격성·운영 승격은 계속 **BLOCKED**다.
