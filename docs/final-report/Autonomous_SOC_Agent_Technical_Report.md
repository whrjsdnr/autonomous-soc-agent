# Autonomous SOC Agent 종합 기술 연구 보고서

**Human-Governed Autonomous Investigation: 탐지 모델에서 감사 가능한 조사 시스템까지**

진단 보강 코드 Commit: `1fcbff2`. 최종 회귀 Workspace/Export 각각1453 PASS/1 SKIP.

작성 기준: 2026-11-02, `feat/one-command-runtime`, 조사 기준 HEAD `253dc0c`. 본문과 부속 문서는 하나의 기술 보고서 묶음이다. 고정 페이지의 PDF가 아니므로 “40~60페이지”를 실제 렌더링 완료 분량으로 주장하지 않는다. 모델 분석·10개 Mermaid·실험 원장·개발 타임라인·29장 발표 구성·기술 Q&A를 함께 읽도록 구성했다. 핵심 주장에는 [Evidence Index](Evidence_Index.md)의 원본을 연결했다.

## 초록

이 프로젝트의 연구 문제는 이상 탐지 모델 하나를 더 만드는 것이 아니라, 실제 보안 관측을 신뢰할 수 있는 모델 입력으로 변환하고, 그 결과를 제한된 자율 조사와 인간 통제에 연결하는 것이다. 패킷·DNS·인증 로그의 관측 단위, Window 완결성, 모델 Feature 의미, 사건 Identity, 조사 Task의 중복 실행, LLM의 불확실성, 종료 자원 증거는 모두 최종 판단의 정확성에 영향을 준다. 따라서 모델 정확도뿐 아니라 데이터 계약·상태·권한·감사·복구를 시스템의 일부로 설계했다.

현재 구현은 TCX Native Collector와 Continuous Runtime, 별도 DNS Helper, Persistent Queue, Window Attestation, Network14 RF/LR, 기존 SOCRuntime 조사와 GUI를 연결한다. 제한된 Native 시험은 실제 Packet54·DNS3·RF/LR8·Incident2·Task5와 소유 Cleanup을 검증했다. 실제 API에서는 Plan이 성공했으나 Assessment가 Timeout되어 전체 LLM 조사 성공은 아니다. 20분 실제 경과 PCAP Replay는 성공했지만, 최신 Native 전체 통합은91.81초에 Helper Heartbeat 계약 위반으로 중단됐다. 그러므로 본 보고서의 성과는 **제한 실환경 E2E와 비권한 복구 통합**이며, 20분/1시간 Native 운영 완료나 운영 환경 승격이 아니다. [E10–E14](Evidence_Index.md#e10)

## 1. 연구 방법과 신뢰 수준

### 1.1 무엇을 사실로 간주했는가

실제 코드·설정·Artifact를 우선하고 학습 결과, 실행 증거, 테스트, Git History, 설계 문서 순으로 대조했다. 문서의 사전 검토와 최종 실행 기록이 다르면 최종 실행을 우선한다. 보고 Commit을 실행 Code Commit으로 쓰지 않고 frozen source/Session을 추적한다. ML 작업 트리의 기존 사용자 변경은 보존하고, 변경된 작업 파일과 committed Export의 차이는 숨기지 않는다. [E01/E04/E12](Evidence_Index.md#e01)

`IMPLEMENTED`는 호출 가능한 코드 존재, `VERIFIED_OFFLINE`은 비권한 시험 증거, `VERIFIED_NATIVE`는 특정 승인된 Kernel 시험, `VERIFIED_API`는 실제 외부 응답 증거다. `PARTIALLY_VERIFIED`는 일부 경로만 확인됐다는 의미이며 `UNKNOWN`은 관측 부족이다. 설계 로드맵은 `PLANNED`다. 이 라벨은 모듈 전체에 영구 부여하지 않고 입력·버전·환경·기간·권한 Scope를 함께 기록한다.

### 1.2 이 보고서의 추론 한계

“왜 그렇게 만들었는가”의 답은 당시 기록이 있는 경우와 현재 구조에서 복원한 사후 분석으로 나눈다. 최초 Foundation의 Single Orchestrator·Tool·인간 통제는 AGENTS에 명시된 당시 방향이다. TCX/Queue/Control 분리가 현재 문제에 어떤 의미인지 설명하는 부분은 실패 기록과 현재 코드에 근거한 사후 기술 분석이다. 기록 없는 회의·벤치마크·경쟁 기술 실험을 지어내지 않는다.

Native Socket·BPF·Namespace·Root 설치는 이번 보고서 작업에서 실행하지 않았다. 기존 실제 실행 로그를 읽은 것과 새 실제 시험을 수행한 것을 구분한다. 테스트의 Mock 권한 경계·SCRIPTED Provider가 실제 Kernel/LLM을 검증한 것처럼 서술하지 않는다.

## 2. 기획 배경과 문제 정의

### 2.1 IDS에서 조사 시스템으로

Signature 기반 탐지는 알려진 패턴을 명시적으로 식별하기 좋지만 관측되지 않은 변형과 규칙 관리 비용의 한계가 있다. 통계/ML 이상 탐지는 다른 신호를 제공하지만 이상을 침해로 확정하지 못한다. SOC 관점에서는 “점수가 높다” 다음에 누가·언제·어떤 근거로 무엇을 조사했는지 설명해야 한다. 이 프로젝트는 탐지 결과와 조사 절차 사이의 단절을 줄이는 것을 목표로 한다. 이것은 프로젝트의 설계 문제 정의이며 실제 조직의 조사 시간 절감 효과를 측정했다는 주장은 아니다. [E01/E08](Evidence_Index.md#e01)

이벤트 증가와 다양한 데이터 소스는 동일 행위에 여러 경보를 만들 수 있다. 반대로 한 경보만 보면 정상 관리 작업과 공격 시도를 구별하지 못할 수 있다. 이때 모델을 추가하는 것만으로 사건 간 시간·대상·관측 범위의 차이를 해결할 수 없다. Source Provenance와 사건 상태를 중심으로 evidence를 연결하고, 부족하면 read-only 조사로 보완해야 한다는 것이 기술적 가설이다.

### 2.2 아홉 가지 핵심 문제

| 문제 | 기존 단순 접근의 한계 | 본 프로젝트 가설·구현 | 남은 한계 |
|---|---|---|---|
|실시간 수집|프로세스 종료만 보면 유실/중단 원인 불명|Kernel counter·sequence·epoch·READY|실제 장시간 안정성 미완료|
|불완전 Flow|STOP을 Flow완료로 간주|Window Seal·INCOMPLETE 유지|마지막 적격 입력 감소|
|모델 입력 신뢰|이름/개수만 맞추면 실행|의미·순서·dtype·fingerprint·attestation|학습 분포와 운영 분포 차이|
|이기종 통합|시간/대상만 같으면 병합|clock/scope/namespace/target·revision|근거 부족은 standalone|
|중복 조사|큐 재시작이 외부 호출 반복|claim/checkpoint/idempotency|불확실 claim은 사람 검토|
|LLM 불확실성|응답을 즉시 실행|typed proposal·policy·tool gate|실제 Assessment Timeout|
|역할 조율|모든 agent를 독립 실행|기존 SOCRuntime·고정 역할·우선순위|동적 agent 확장 불필요|
|안전 종료|Exit0만 성공|ACK·CLOSED·counter·owned cleanup|Global Kernel은 별도 UNKNOWN|
|재현성/감사|코드만 commit|source/artifact/session/approval binding|정확한 승인 운영 비용 증가|

문제 정의는 서로 의존한다. 완결성 없는 Feature로 모델을 호출하면 조사 단계가 성실해도 잘못된 근거를 확대할 수 있다. 반대로 모델을 과도하게 차단하면 사용자는 빈 GUI를 장애로 오해한다. 따라서 “관측됨/미승인/부적격/오류/미수집”을 분리한 상태 표현이 제품의 정확성에 포함된다.

## 3. 전체 아키텍처와 계층 경계

[전체 구성도와 9개 세부도](Architecture_Diagrams.md)에 Mermaid 원본을 보관했다. 수집 계층은 Native TCX와 별도 DNS, 선택된 읽기 전용 Authentication이다. Data Plane은 정규화·Queue·Window·Feature·추론을 처리한다. Control Plane은 identity·heartbeat·stop·진행 상태를 게시한다. 조사 계층은 ApplicationService/SOCRuntime/Planner/Tool/Assessor이며 집행은 Policy·인간 승인 경계 뒤에 있다. GUI와 CLI는 이 Backend 상태를 투영한다. [E02/E08/E15](Evidence_Index.md#e02)

### 3.1 실제 운영 연결

```text
soc_agent.cli:main
 → agent_cli.main
 → agent_runtime.start/status/stop/gui/doctor
 → Continuous service / existing Native supervisor entry
 → Producer / bounded Queue / analysis worker
 → AnalysisService / OfflineWorkflow
 → immutable InvestigationSource
 → InvestigationTasks / investigation queue
 → ApplicationService / SOCRuntime.advance
 → existing Planner → InvestigationOrchestrator → ThreatAssessor
 → checkpoint / trace / Audit → GUI projection
```

위 경로는 기능을 나열한 가상의 순서가 아니다. `continuous/investigation.py::from_analysis/application`, `investigation_store.py::submit/_schedule/claim/recover`, `api/service.py::ApplicationService`, `investigation/runtime/service.py::SOCRuntime.start/advance/restore`가 연결점이다. 분석과 조사 Queue를 분리하여 Collector가 LLM 응답을 기다리지 않게 한다. Source role의 EVIDENCE_RETAINED 상태는 해당 수집기가 지금 RUNNING이라는 뜻이 아니다. [E08](Evidence_Index.md#e08)

### 3.2 아키텍처 대안의 사후 비교

임의 shell을 가진 범용 LLM Agent는 데모 구현이 빠를 수 있으나 입력·권한·반복·복구를 검증하기 어렵다. 범용 Multi-Agent 프레임워크도 이 고정된 네 역할에 필수적이라는 증거가 없었다. 기존 core와 ToolRegistry를 재사용하면 누적된 CAS·정책·승인·감사 테스트를 유지할 수 있다. 이 비교는 별도 프레임워크 성능 대조 실험이 아니라 현재 요구사항에 대한 설계 분석이다. LangChain/LangGraph를 사용한 것처럼 기록하지 않는다. 선언된 Python/Pydantic/numpy/sklearn/xgboost와 기존 코드 계층이 근거다.

## 4. Native 수집과 Kernel/User 경계

### 4.1 TCX의 역할

TCX Ingress에서 수집되는 Packet metadata는 kernel hook 범위의 관측이다. Kernel 이벤트·Map/Ring Counter·설치 epoch와 User Space Producer의 sequence를 연결한다. Kernel 검증은 Object userspace parse와 다르다. BTF가 존재해도 verifier가 pointer 접근을 거부할 수 있고, load 성공해도 TCX attach/READY/Runtime 전달 성공이 자동 보장되지 않는다. [E11](Evidence_Index.md#e11), [Kernel 공식 문서](https://docs.kernel.org/bpf/index.html).

TCX를 선택한 의사결정을 현재 관점에서 해석하면, Kernel 관측 위치와 Counter/소유 Link를 고정하고 User 모델 처리와 분리할 수 있다는 장점이 있다. 그 대가는 Root·Kernel ABI·BTF/verifier·Namespace·Resource·Cleanup 검증 비용이다. libpcap과 비교한 운영 처리량 우위를 직접 벤치마크했다는 근거는 없으므로 “무조건 빠르다/손실 없다”라고 쓰지 않는다.

### 4.2 Namespace와 실제 수집 범위

반복 시험의 Target은 `net:[4026532232]`, interface `lo/Ingress`다. 최신 증거의 Host는 `net:[4026531833]`로 달랐다. 승인된 로컬 loopback 시험을 Host 전체 네트워크 탐지로 일반화하지 않는다. DNS 트래픽 공급원도 같은 전용 Namespace의 로컬 dnsmasq이며 외부 DNS resolver 호출이 아니다. 이 환경은 안전한 계층 연결 검증에 유리하지만 실제 인터넷 트래픽 다양성·고속 부하·장기 서비스 상호작용을 검증하지 못한다. [E12/E13](Evidence_Index.md#e12)

### 4.3 Producer/Consumer와 Persistent Queue

Producer는 User Runtime으로 정해진 IPC 메시지를 보낸다. Queue는 수집과 AI 처리의 속도 차이를 완충하고 재시작 후 미처리 작업을 보존한다. 그러나 bounded capacity32는 무한 저장이 아니며 Drop·Reject·high-water·source gap을 계측해야 한다. FIFO 하나로 모든 동작을 묶으면 저장·모델·조사 지연이 Control까지 막을 수 있어 worker와 observer의 책임을 나눴다. [E02/E14](Evidence_Index.md#e02)

Durable Queue의 “전달 보장”은 exactly-once 외부 호출을 자동 제공하지 않는다. 입력 identity, unique key, claim, checkpoint, receipt를 결합해 중복을 통제한다. Crash 시 PENDING과 in-flight uncertain work를 구별해야 한다. POISON은 문제 작업을 숨긴 성공 상태가 아니며 원인과 이전 증거를 보존하는 격리 상태다.

## 5. Window Seal·Attestation·Model Admission

### 5.1 세 종류의 완료

Capture Window 봉인은 수집 구간·counter·epoch 증거를 고정하는 행위다. Flow의 event-time timeout은 feature 표본의 경계를 정하는 행위다. 모델 승인 후 inference receipt는 계산 실행을 증명한다. 셋은 같은 완료가 아니다. 사용자가 “모델을 봉인하지 말라”고 요청한 맥락에서도 봉인되는 것은 모델이 아니라 실제 입력 Window다. 이 구분 없이 Future input 전체에 미리 모델 권한을 발급하면 기존 Action 계약을 확대한다. [E02/E03/E15](Evidence_Index.md#e02)

### 5.2 신뢰 가능한 입력의 조건

정확한14개 float32, 계산 정의·순서·schema, source hash·Session·Flow·Window, event-clock·generation, Counter 범위, capture quality와 종료 witness, Model/scaler fingerprint, 독립 Action grant를 모두 확인한다. 하나의 구조체에 값이 있다는 것만으로 admission을 통과시키지 않는다. UNKNOWN/INCOMPLETE를0으로 채워 추론하는 편의 기능은 없다.

### 5.3 feature와 성능의 관계

모델 평가가 높아도 실시간 extractor가 학습 의미와 다르면 그 점수를 적용할 근거가 없다. Zeek summary의 orig/resp와 first-seen packet 방향, conn lifetime과30/120초 packet window는 다르다. Top40을 Network14로 잘라 넣거나 DNS9 이름만 추정해 계산하면 input shape는 맞아도 통계적 의미는 깨진다. 이 프로젝트의 운영 기여는 높은 점수를 새로 주장한 것보다, 그런 잘못된 호출을 차단하는 경계를 만든 데 있다. [자세한 계산·평가](Model_Analysis.md).

## 6. DNS와 Authentication의 별도 경로

### 6.1 DNS Transaction

DNS는 쿼리ID 하나만으로 대응하지 않는다. transport·client/server endpoint·query type/class·정규화 질문·capture source·clock epoch를 결합한다. timeout·duplicate·missing response·ambiguous·invalid frame을 정상 응답과 분리한다. ASCII lower는 transaction correlation의 규칙이며 학습 canonicalization을 증명하지 않는다. Stored TCP 처리기는 완전한 length prefix를 요구하며 partial stream을 INCOMPLETE로 남긴다. [E06](Evidence_Index.md#e06)

Native DNS 경로는 승인된 Helper가 Raw frame을 읽고 metadata를 IPC로 전달한다. loopback outgoing/host clone 중복을 그대로 이중 계산하지 않는다. 실제 dnsmasq UDP2/TCP1 시험에서 transaction3을 확보했지만 임의 segmented TCP/DNS load까지 모두 검증했다는 뜻은 아니다. DNS9는 원본 추출 계약이 INCOMPLETE여서 차단한다.

### 6.2 Authentication

계정별300초 Window는 사건 시각으로 정렬하고 Cursor/Event Identity·중복·입력 완결성·읽기 전용 source binding을 검증한다. 5개 behavior feature를 정상 baseline IF로 연결하는 코드는 있다. 사용자 인증 이벤트를 임의 발생시키거나 Host 보안 설정을 바꾸지 않는다. 이벤트가 적거나 source 승인이 없으면 GUI에서 미수집/적격 입력 부족 상태를 나타내야 하며 synthetic 결과를 Live로 채우지 않는다. 실제 Host IF 성공은 EVIDENCE_REQUIRED다. [E07](Evidence_Index.md#e07)

## 7. ML/DL 연구 결과와 운영 모델의 분리

[Model Analysis](Model_Analysis.md)는 데이터셋·정확한14개 수식·RF/LR parameter/threshold·Top40 모델 비교·DNN layer/tensor·DNS INT8·Authentication IF를 상세히 기록한다. 핵심은 연구 protocol이 다른 결과를 합산하지 않는 것이다. CTU session 연구의 RF/LR과 CSE15-class DNN은 목적·입력·label·분포가 다르다.

선정된 RF의 Test FPR15.19%, LR의 FNR27.25%는 운영 경고다. 모델 score는 calibrated attack probability가 아니고 본 시스템의 Incident UNKNOWN_ANOMALY도 침해 확정이 아니다. TF/TorchAO/LiteRT 관련 Artifact나 notebook이 있다는 이유로 모두 Native runtime dependency인 것처럼 기술하지 않는다. 현재 Native RF/LR, 독립 Top40 package, DNS INT8 supplied artifact를 분리한다. [E04–E07](Evidence_Index.md#e04)

## 8. Pipeline에서 AI Agent로 확장한 이유

ML pipeline은 정해진 입력을 정해진 모델에 넣는 데 적합하다. 조사에서는 어떤 evidence가 부족한지, 다음 read-only Tool이 유용한지, 가설과 관측이 모순되는지 판단해야 한다. 이 제한된 계획·평가 영역에 LLM을 사용하고, 권한·위험·횟수·retry·stop·state transition은 결정론적 코드로 둔다. LLM의 존재만으로 수집·Queue·Supervisor를 AI Orchestrator라 부르지 않는다. [E01/E08/E09](Evidence_Index.md#e01)

Agent 상태는 chat history가 아니라 IncidentState·plan·step result·evidence·assessment·checkpoint·trace로 관리한다. Tool 입력/출력과 LLM structured response는 Pydantic schema로 검증한다. Observation은 로그/모델receipt 등 실제 획득 사실이고 Hypothesis는 해석이며 Decision은 정책과 권고다. “비정상 점수”를 “공격자가 침입했다”라는 observation으로 저장하면 이후 단계가 허위 확신을 증폭하므로 분리한다.

ToolRegistry는 명시적 read-only Tool과 검증된 argument를 노출한다. LLM shell string을 `shell=True`로 실행하는 통로를 제공하지 않는다. Tool 실행 성공도 가설 확인과 같지 않다. 결과가 불충분하면 추가 evidence 또는 인간 검토로 넘어가야 한다. 이러한 설계는 자동 조사와 인간 통제의 역할을 명확히 하고, 설명 가능한 포트폴리오라는 초기 목표에도 부합한다.

## 9. 기존 오케스트레이션의 재사용과 통합

### 9.1 왜 SOCRuntime인가

기존 SOCRuntime에는 deterministic step transition, durable claim, checkpoint revision, external interruption reconciliation, trace validation, policy/human boundary가 있었다. Continuous 분석의 결과를 새로운 별도 조사 engine에 넣으면 같은 사고 상태와 외부 호출 계약을 이중 구현하게 된다. 따라서 Continuous adapter가 immutable source를 제출하고 기존 ApplicationService/SOCRuntime을 호출하도록 통합했다. [E08](Evidence_Index.md#e08)

`InvestigationPlanner`는 최초 계획, `InvestigationOrchestrator`는 검증된 Tool 실행·evidence 수집, `ThreatAssessor`는 근거 평가, `AdaptiveInvestigationPlanner`는 제한 follow-up을 담당한다. `SecurityAISelector`와 `MultiModelFusionEngine`은 기존 SecurityAI 계층의 모델 선택·결합 코드다. **Continuous 후속 조사에서는 빈 AI registry를 사용해 별도 승인 없는 모델 추가 실행을 막는다.** 이 모듈의 이름만 보고 LLM이 모든 모델/Agent를 실시간 선택한다고 결론 내리지 않는다.

### 9.2 Correlation과 Evidence Revision

관련 사건 연결은 동일target·scope·namespace·origin·clock·1분 event bucket을 요구한다. 시간 또는 대상 하나만 같다고 합치지 않는다. clock domain이 불명확하면 standalone으로 둔다. 정렬된 source hash가 EvidenceRevision을 정의하고 새 증거가 들어오면 새 revision/task/checkpoint를 만든다. 기존 Incident owner ID는 유지하고 이전 Task는 superseded로 남긴다. 현재 조사 중 mutable evidence가 바뀌어 어떤 근거를 평가했는지 잃는 문제를 방지한다.

### 9.3 우선순위·충돌·중복

기존 bounded priority0~2에서 conflict/unknown/error 상태를 구분한다. AI의 priority는 advisory이고 deterministic 정책이 실행순서를 결정한다. 낮은 우선순위가 새 사건에 무한히 밀리지 않도록 연속 overtaking을 최대8개로 제한한다. Claim/Lock·source digest·canonical attempt input으로 같은 Incident/revision/Tool의 중복 실행을 차단한다. RF/LR 상충은 추가 조사 필요의 근거일 수 있지만 실제 Native에서 상충하지 않았다면 Fixture의 conflict 성공으로 대체하지 않는다. [E08/E11](Evidence_Index.md#e08)

### 9.4 복구와 불확실 외부 단계

claim 이전 crash는 retained source와 queue를 다시 연결할 수 있다. 외부 LLM/Tool claim 이후 crash는 결과가 없더라도 이미 실행됐을 수 있어 자동 반복하면 안 된다. 기존 checkpoint에서 uncertainty/human review로 남기는 것이 안전한 복구다. at-most-two rounds와 중복 attempt 차단은 무한 Agent loop를 방지한다. Retention은 active claim·미완료 cleanup이 없는 stopped 상태만 허용하며 immutable source/core DB를 함께 보존한다. Queue33건 등 과거 미처리 자료는 격리 사본으로만 복구 검증했다.

## 10. 실제 LLM과 SCRIPTED의 경계

기본 Continuous 조사 Provider는 SCRIPTED다. API Key가 환경에 있다고 자동 외부 호출로 전환하지 않는다. 실제 API trial A는 보존 Native Incident에 대한 별도 승인·호출·예산·Audit을 가졌다. OpenAI gpt-5-mini Plan은9.139초,2264input/689output으로 성공했고 Read-only Tool도 완료했다. 두 번째 Assessment는20초 Timeout, Usage 미수신이므로 결과와 총 billing은 UNKNOWN이다. 두 호출로 Replan까지 완료했다고 주장하지 않는다. [E10](Evidence_Index.md#e10)

11월2일에는 보존된 Plan/Tool을 재사용한 별도 Assessment1회도20.065초에 실패했다. 예약$0.011354/출력4096토큰/재시도0을 유지했으며 Usage가 없어 총비용UNKNOWN이다. timeout시HTTPworker alive를관측했으므로원격취소완료를주장하지않는다. 실제Tk2회에서Timeout/비용UNKNOWN/Audit를확인했다. 이는앞선시험과별도기록이다.

Timeout은 클라이언트가 정해진 시간에 응답을 못 받았다는 사실이지 원격 요청 미실행·무료·취소완료를 뜻하지 않는다. 따라서 사전 reserved cost와 실제 usage-confirmed cost를 분리하고, 불확실 요청을 자동 재시도하지 않는다. Checkpoint revision5 FAILED와 실제 Plan을 GUI/Audit에 함께 표시한다. 새 Assessment 검증에는 별도 요청 승인·가격/가용성·전송범위·토큰/횟수/비용 상한이 필요하며 다른 모델로 자동 교체하지 않는다.

## 11. Control/Data Plane과 반복 장애

### 11.1 Heartbeat가 증명하는 것

Heartbeat는 특정 process/control path의 생존 신호다. Data Progress는 Queue 소비·Window/저장 완료 등 실제 업무의 진척이다. Heartbeat만 분리하면 저장이 영원히 멈췄는데 RUNNING처럼 보일 수 있으므로 두 축을 모두 계측한다. 프로세스 PID 재사용을 막기 위해 start identity·boot/time namespace를 확인하고, Clock 비교는 동일 monotonic domain에서만 한다. [E02/E14/E16](Evidence_Index.md#e02)

### 11.2 저장과 상태 게시의 결합

기존 durable update가6~7초 걸릴 때 DNS snapshot refresh까지 같은 serialized storage 흐름에 놓이면 데이터는 아직 저장 중인데 외부 observer는 오래된 상태를 읽는다. 260e760은 무거운 snapshot을 Control loop 밖으로 옮겼지만 같은 storage 순서를 기다리는 한계가 남았다. db5e8dc에서 별도 DNS observer/read lock으로 분리하고 read 시작 시각을 freshness의 기준으로 삼았다. 완료시각만 쓰면 오래 기다린 읽기를 새 상태로 오인할 수 있기 때문이다. [E12/E14](Evidence_Index.md#e12)

### 11.3 최신 실패에서 확인된 것

91.808838초 시험에서 마지막 heartbeat seq408은 생성→수신1.302270ms였다. 그 뒤 CLOSEDseq409가 기록될 때 이전send완료와의 간격은4.181036875초였다. failure 당시 heartbeat age2.236042초, FIONREAD0, packet queue0/32, Reader 최대pollgap0.818836초였다. 따라서 이 사례를 단순히 “이미 도착한 heartbeat를 Reader가 못 읽었다”로 설명할 수 없다. 동일 Helper는 failure 당시 R(running/runnable), 이후 STOP/CLOSED를 보냈으므로 프로세스가 먼저 종료됐다고 단정할 수도 없다. [E12/E16](Evidence_Index.md#e12)

cgroup nr_throttled는51→71이나 throttled_usec는4,520,591→동일값이었다. 이 snapshot만으로 CPU10% quota가 직접 원인이라고 확정하거나 throttling이 전혀 없었다고 말하지 않는다. Control Root heartbeat최대1.536483초, durable update최대6.952602초, Control publication최대0.039924초도 서로 다른 계층 지표다. Helper의 interface_identity·select·packet processing·counter sample 중 어떤 구간이 지연됐는지는 기존 증거로 UNKNOWN이다.

### 11.4 이번 최소 보강과 남은 실환경 검증

Helper의 기존 diagnostic transport trace에 완료된 loop의 start/identity-check/select/packet-processing/counter-sample monotonic 경계를 추가했다. read-only 값이며 raw payload·key·새 권한이 없다. strict typed model이 역전된 시각을 거부하고, 현재 heartbeat 생성 전에 완료된 elapsed stage를 보존한다. 고의적인30ms identity 지연과 정상 lifecycle을 권한 경계 Mock으로 검증했다. 실제 CPU 사용시간과 descheduling을 합친 elapsed 구간이며 원인을 자동 단정하지 않는다. STOP이 loop 중간에 도착하면 마지막 완료 loop만 남는다.

이는 **원인 해소를 선언할 수정이 아니라 원인 구간을 좁히는 진단 결함 보강**이다. 2초 Helper/5초 Control 기준, socket timeout, Resource limits, counter/admission/namespace/replay 검증은 그대로다. 새 Source/Helper Artifact이므로 과거 승인과 실제 성공을 승계하지 않으며 새 Native 검증은 미실행이다.

## 12. STOP·Cleanup의 증거 모델

실패하면 최초 오류를 고정하고 새 입력을 막고 STOP을 요청한다. TCX ACK·DNS CLOSED/최종 Counter/ACK·가능한 Window Seal 또는 diagnostic seal을 수집한다. Queue·Audit flush와 소유 process/thread/socket/FD/link/map 종료를 확인한 뒤 각 영역을 독립 판정한다. Cleanup 후속 오류는 최초 Timeout을 덮어쓰지 않는다. [E10–E14](Evidence_Index.md#e10)

Queue Drain은 미승인 모델 작업을 몰래 실행하거나 삭제한다는 뜻이 아니다. 데이터 수신/저장·audit flush가 끝나도 PENDING/POISON이 보존될 수 있으며 “모든 처리 완료”라고 보고하면 안 된다. 동일 개수의 PENDING2/POISON1도 서로 다른 Session이면 별도 자료다.

현재 Snapshot에 잔류가 없다는 것과 과거 종료시점 Cleanup proof는 다르다. 소유 Root 자원이 정리됐다는 것과 Global Kernel 모든 프로그램의 원인을 안다는 것도 다르다. Program1145의 소멸 UNKNOWN과 과거 UNVERIFIED는 후속 시험 성공으로 소급 변경하지 않는다. 종료코드0 하나로 이런 차이를 압축하면 운영 안전의 중요한 정보가 사라진다.

## 13. CLI·GUI의 제품 설계

### 13.1 단일 CLI의 실제 지원 범위

| 명령 | 실제 책임 | 완료/권한 조건 |
|---|---|---|
|setup|private profile·Replay/config/native-review·기존 runtime 연결|Root무조건설치 아님|
|start|환경·artifact·scope검증 후 기존 service/backend 연결|Native 정확한 승인·Scope·sudo 필요|
|status|Backend snapshot·Queue·Window·Worker·cleanup 조회|상태조회 지연/죽은PID를 구분|
|stop|기존 STOP·drain·seal·audit·cleanup|미승인 모델 task 보존|
|gui|기존 Tk desktop·Backend 연결|GUI 종료는 Collector 종료 아님|
|doctor|Python/dependency/model/artifact/storage/host검사|권한 필요한 Target검사 별도 BLOCKED|

```bash
cd /home/geonug/kdt-linux/soc-one-command-runtime
.venv/bin/soc-agent setup --home /private/profile --native-review /exact/review
.venv/bin/soc-agent doctor --home /private/profile
.venv/bin/soc-agent start --home /private/profile --preview
# 실제 start는 새로운 정확한 인간 승인과 Scope·sudo 뒤에만 실행
.venv/bin/soc-agent status --home /private/profile
.venv/bin/soc-agent gui --home /private/profile
.venv/bin/soc-agent stop --home /private/profile
```

이 예시는 경로 placeholder이며 과거 Session/소비 영수증을 다시 실행하는 안내가 아니다. 단일 CLI 목표는 사용자가 여러 내부 SHA를 직접 입력하지 않게 하는 것이지 승인 검증을 삭제하는 것이 아니다. [E15](Evidence_Index.md#e15)

### 13.2 GUI에서 빈 값의 의미

Packet/DNS/Authentication, Capture Quality, Feature Eligibility, model receipt/latency, Incident, Investigation/Assessment, Task, Audit, STOP/Cleanup은 각각 실제 Backend에 대응해야 한다. 미수집 Auth, 미승인 모델, 새 적격 입력 없음, 실제 runtime 오류를 같은 N/A로 숨기면 사용자는 의도된 대기와 고장을 구별하기 어렵다. 최신 GUI correction은 DNS query/response 실제 counter를 history에 투영하고 반복 STOP이 CLOSED를 STOPPING으로 덮지 않게 했다. [E12/E14/E18](Evidence_Index.md#e12)

모든 패널에 반드시 숫자를 표시하라는 요구는 없는 모델 결과를 만들라는 뜻으로 구현할 수 없다. full acceptance에서 필수 항목이 미검증이면 시험 FAIL/PARTIAL로 기록하고 이유를 표시한다. Fixture·Replay·SCRIPTED·Native·API의 origin을 유지한다. [실제 실패 화면](assets/native-failure-dashboard.png)은 이 원칙대로 미실행 모델을 성공 수치로 채우지 않은 증거다.

## 14. 보안·승인·재현성

Source Manifest는 어떤 코드가 실행 대상인지, Artifact SHA는 빌드 결과가 무엇인지, Root Manifest는 허용된 고정 설치 경로/내용을, Namespace Lease는 Target identity를, Session/Release/Scope는 이번 시험 범위를, Ledger/receipt는 유효성·소비·Replay 방어를 연결한다. SHA는 스스로 신뢰를 만들어내지 않으며 검토된 identity/ownership/정책이 함께 있어야 한다. pickle/joblib을 hash했다고 외부 모델이 안전해지는 것은 아니다. [E04/E15/E17](Evidence_Index.md#e04)

R1은 과거 UNKNOWN/UNVERIFIED 등 잔여 위험 수용의 정확한 binding이며 R2 DNS scope를 무관한 새 트래픽으로 확대하지 않는다. Model Action은 수집 권한과 독립이다. LLM proposal은 Root·Native·서비스 변경 권한이 아니다. 인간 승인이 있었더라도 만료·소비·source mismatch라면 차단한다.

이 구조의 단점도 크다. 작은 Source/Root 파일 변경이 재검토·Artifact freeze·Session/정책 갱신을 요구하고 사용자는 반복 확인에 피로를 느낄 수 있다. 실제 Installer scope/time rebinder의 외부 준비 오류도 발생했다. 개선 방향은 검증 제거가 아니라 기존 CLI에서 exact scope diff/automaticSHA/독립권한 결과를 명확히 보여 주는 것이다. 새로운 승인 체계를 덧붙이는 것은 본 작업 범위가 아니다.

## 15. 개발 실패를 통한 설계 복원

[Development Timeline](Development_Timeline.md)은 Foundation부터 모델·조사·Kernel·Continuous·CLI·Native 안정화까지 Git 근거를 연결한다. BTF누락→userspace parse→Verifier 거부→pointer/errno수정→제한Native성공의 순서는 단일 “eBPF 완료”로 뭉칠 수 없다. DNS UID EPERM, Timeout, SQLite/상태 관측 결합도 서로 다른 결함이다.

실패 분석에서 관측된2초 공백은 직접 증상이고 CPU scheduling은 원인 후보다. 저장 지연6초를 확인했다고 모든 Helper 공백이 SQLite 때문이라고 결론 낼 수 없다. 수정 전 재현·수정 후 회귀·실제 재시험은 각각 따로 기록해야 한다. 이전에 회귀가 통과했는데 Native에서 다시 실패한 것은 테스트가 무의미해서가 아니라 당시 재현한 failure domain 밖에 미관측 지연이 있었음을 보여 준다. 이것을 숨기지 않고 다음 관측을 더 좁히는 것이 안정화의 핵심이다.

## 16. 실험 결과와 수락 기준

[Experiment Results](Experiment_Results.md)에 개별 trial별 Code/시간/카운터/GUI/Cleanup/최초오류를 기록했다. 제한 Native Orchestration은404.593초 전체/396.137초 봉인 수집으로 성공했지만, 이후1시간 시도는1080.335초 실제 구간만 확보했다. 20분 Replay는1200.132초 실제 경과로 통과했으나 Kernel은 실행하지 않았다. 최신 Native는85.896초 봉인 수집으로 실패했다. 이 수치를 합산해1시간 성공이라고 할 수 없다. [E10–E14](Evidence_Index.md#e10)

성공 조건은 목표 수집시간, 실제 events, multi-window attestation, 승인된 모델/조사/GUI, drop/accounting, stop/cleanup을 같은 Session·Scope에서 충족하는 것이다. QueueDrop0은 이벤트가 하나도 누락되지 않았다는 전역 보증이 아니라 관측한 counter/queue 범위 결과다. GUI close/reconnect도 backend survival과 화면 새로 읽기를 모두 확인해야 한다.

## 17. 검증 전략의 범위와 실패 기록

Unit은schema/timeorder/policy/retry, Integration은실제 component contract/Queue/Workflow/GUIprojection, Mock failure는control/write/stall/crash/STOP, Export는다른 source root의import/build 재현을 확인한다. 실제 Kernel scheduling/cgroup/raw socket의 장기 동작과 provider remote timeout은 별도 live계층이다. Offline 전체 test가 많아도 이를 대신하지 못한다.

이번 작업의 변경은 stage diagnostic과 해당 회귀로 제한했다. broad regression 도중 source를 바꾸는 초기 실행은 취소하고 고정 source snapshot으로 Workspace/Export를 다시 시작했다. 취소 실행을 PASS에 포함하지 않는다. Native/Supervisor/Wheel 빌드는 file compile·guarded preview이며 설치/attach가 아니다. 최종 결과·명령·SHA·보존 확인은 [Validation Results](Validation_Results.md)에 기록한다.

## 18. 기술적 성과·한계·후속 조건

성과는 Human-Governed Investigator를 실제 packet feature/모델 receipt와 연결하고 source/revision/claim/checkpoint/audit로 설명 가능하게 만든 것이다. Native와 DNS의 제한 E2E, 실제API Plan, 20분wall Replay, 반복 실패의 독립 Cleanup proof를 확보했다. 단일 CLI와 GUI가 서로 다른 성공·대기·오류를 표시하도록 통합한 것도 운영상 의미가 있다.

남은 제한은 20분/1시간 Native 운영, Helper 송신 공백의 정확한 작업·scheduling 원인, 실제LLM Assessment, HostAuth IF, DNS9 학습추출, GlobalKernel이다. RF/LR의 Test분포 이동과 오탐/미탐도 미해결 운영 위험이다. 이 상태는 연구·포트폴리오와 제한 RC의 근거는 되지만 자동 대응·운영 환경 승격 근거는 아니다.

차기 실제 시험에는 새 Git/Source/Artifact/Root/Session/Namespace/Ledger binding, 유효한 독립 Root·Native·R1·TCP/DNS scope, 사용자Scope/sudo, 단1회deadline·resource limits, 새Helper loop진단 및 독립STOP/cleanup을 요구한다. 별도모델Action은 실제봉인ELIGIBLE작업 뒤에만, APIAssessment는 별도횟수/비용/timeout/usage계약으로 수행한다. 본 작업에서는 어느 실행권한도 소비하지 않았다.

## 19. 읽기 순서와 발표 활용

기술 면접에는 본문3·5·9·11·12장과 Q&A, ML 검토에는 Model Analysis의 protocol/feature/selection/Test표, 운영 검토에는 Experiment Results/Timeline/Validation Results를 우선한다. 발표 구성은 [Presentation Outline](Presentation_Outline.md), 그림은 [Architecture Diagrams](Architecture_Diagrams.md), claim 검증은 [Evidence Index](Evidence_Index.md)·machine manifest를 사용한다.

각 그림과 성능표는 설계 의도와 실제 검증 범위를 함께 읽어야 한다. 실패를 제거한 성공 스토리보다 어떤 근거에서 어디까지 결론 내릴 수 있는지 설명하는 것이 이 프로젝트의 연구적·엔지니어링 성과를 정확하게 드러낸다.

## 20. 구성 요소별 구현·검증 상태표

| 구성 요소 | 실제 연결/함수 | 상태와 증거의 경계 |
|---|---|---|
|NativeTCX|continuous/native·Producer→ContinuousRuntime|VERIFIED_NATIVE(제한시험);장시간PARTIAL,E02/E11|
|DNSHelper|continuous/dns_helper.main→stream_helper.run(diagnosticsTrue)|VERIFIED_NATIVE(UDP2/TCP1);송신gapUNKNOWN,E06/E12|
|Authentication|project_journal/Journal poll→window/IF|IMPLEMENTED/VERIFIED_OFFLINE;HostIF미검증,E07|
|PersistentQueue|ContinuousStore·기존EventQueue·claim/recovery|VERIFIED_OFFLINE/제한Native;미승인pending보존,E02/E08|
|Window|NativeWindows.add/process/close·Window.finish|VERIFIED_NATIVE제한;SHUTDOWN완결성승격금지,E03/E11|
|Attestation/Admission|ebpf/input_eligibility.input_receipts 등 계층검사|VERIFIED_NATIVE제한;UNKNOWN차단,E03/E11|
|RF/LR|researchSPECS/modelworker·작업별Action|VERIFIED_NATIVE호출;운영탐지정확성미인증,E04/E11|
|Top40LGBM/DNN|ML독립predictors/contract|VERIFIED_OFFLINE저장실험;Native14와별개,E05|
|DNS9DNN|MLpackage/fixedfeaturecontract|Artifact분석/legacyparity;Raw추론BLOCKED,E06|
|Incident연결|from_analysis→InvestigationSource|VERIFIED_OFFLINE/제한Native,E08/E11|
|Task조율|InvestigationTasks.submit/_schedule/claim/recover|VERIFIED_OFFLINE;Native모든conflict시나리오미발생,E08|
|Plan/Investigation|ApplicationService→SOCRuntime.advance→Planner/Orchestrator|NativeSCRIPTED경로검증,실제PlanAPI별도성공,E08/E10|
|Assessment|ThreatAssessor→checkpoint/trace|SCRIPTEDVERIFIED;실제API2시험Timeout,E10|
|AdaptiveReplan|ContinuousInvestigationPlanner.create_followup/AdaptivePlanner|VERIFIED_OFFLINE;실제APIReplan미실행,E08|
|Selector/Fusion|SecurityAISelector/MultiModelFusionEngine|기존계층코드/회귀;Continuous추가AIregistry빈값,E09|
|Control/Data|service control loop/statusobserver/storageworker|VERIFIED_OFFLINE/제한Native;Sendergap미해결,E14/E16|
|STOP/Cleanup|STOPACK/CLOSED/Counter/durable/audit/ownedproof|최신소유범위VERIFIED;과거/GlobalUNKNOWN유지,E12|
|GUI|Backendprojection·Tk·CLIgui|현재offline회귀/과거Native실제화면;최신fullacceptanceFAIL,E15/E18|

위 표의 `VERIFIED_OFFLINE`은 해당 기능의 관련 시험 범위이며 운영 전체 인증이 아니다. 실제 AI가 계획·평가에 참여한 지점과 deterministic priority/claim/policy를 구분한 결과다. 정확한 코드 심볼은 E번호의 현재 파일을 우선하고, 단일 Admission 함수가 모든 검사를 대신한다고 해석하지 않는다.

## 21. Native Collector의 구현 세부와 안전성 비용

실제 [continuous.bpf.c](../../releases/research-mvp/src/soc_agent/continuous/native/continuous.bpf.c)는262,144바이트RingBuffer와1개config Array,per-CPUcounter Array를사용한다. `bpf_ktime_get_ns`와CPU별sequence/generation/ifindex/hook을metadata에기록한다. config가없거나disabled/잘못된generation/interface/time일때passive `TCX_NEXT`로반환한다. 커널은lease길이를10초이하로제한하고provider의renew는5초lease를게시한다. daemon이죽으면무기한새수집이활성화되는것을줄이지만,lease만료가Link/Map정리의증명은아니다.

CPU별분당admission4096개는진단의누적packetbudget과다른제한이다. ringreserve실패는ring_lost,quota초과는budget,미지원형식은unsupported,파싱실패는malformed로분리한다.관측된고속traffic처리량이나모든packetcapture성공을이상한값0으로채우지않는다.새Map으로재부착할때같은분의quota를다시부여하지않도록admissionstate만이월하고capturecounter자체는새Map의실제pre/post값으로검증한다.

[packet_parser.h](../../releases/research-mvp/src/soc_agent/continuous/native/packet_parser.h)는최대128바이트header범위에서scalaroffset과고정크기destination으로`bpf_skb_load_bytes`를사용한다. Ethernet/IPv4/일부IPv6/TCP/UDP를검사하며IPv4fragment나지원하지않는헤더/크기·VLAN/GSO조건은제외한다.일반IPv6extension/임의fragmentreassembly까지완료한범용DPI엔진이아니다.이것은Verifier가검증할수있는접근과정확한입력의교환관계다.

[provider.c](../../releases/research-mvp/src/soc_agent/continuous/native/provider.c)의open은euid/lo/Namespaceinode를검사하고libbpfObjectload·TCXexpected_revision·ringbuffer를설정한다.poll에서는현재Namespace와소유Link/Programidentity를재확인한다.finish는detach후ringconsume과최종counter시각범위를확보하고,close는config비활성화·link/ring/object/배열정리를수행하며실패를EUCLEAN으로보고한다.각단계가성공해도전역다른Program의소유권/소멸원인을설명하지는못한다.

[policy.py](../../releases/research-mvp/src/soc_agent/continuous/native/policy.py)는Root소유·비쓰기권한·비symlink파일,고정경로,설치4파일과python/libbpf/libelf/libz/libc의SHA를검증한다.설치정책의`native_model_inference=False`는Collector설치권한이모델Action권한을포함하지않는다는명시적계약이다.부모경로검사와별도Root설치는관리편의비용이있지만LLM/Event입력이실행파일경로를바꾸는위험을줄인다.이번분석은파일읽기/빌드만수행했고이함수들의RootLive실행을하지않았다.
