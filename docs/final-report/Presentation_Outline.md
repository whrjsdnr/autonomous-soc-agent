# 발표 구성안 — 29장, 약29~36분

본 내용은 발표자료 원본 설계이며 완성된 PPT 파일이나 새 Live 데모가 아니다. 그림 번호는 Architecture_Diagrams.md, E번호는 Evidence_Index.md다. 실제 Screenshot은 assets/native-failure-dashboard.png(최신실패), assets/native-success-investigation.png(제한Native성공·SCRIPTED), assets/api-assessment-timeout.png(별도실제API실패)이며 각 Scope 캡션을 유지한다. 성능차트는 저장된 평가 CSV만 사용한다. 각장60~75초를기본으로하며질의응답시간은별도다.

## 01. 프로젝트의 정체성

- 핵심 메시지: 탐지 결과를 인간 통제 하의 자율 조사로 연결한다.
- 화면 본문: Observe→Plan→Investigate→Assess→Govern; 대응 권한은 별도
- 그림·표: 전체 아키텍처 그림1
- 실제 근거: [Evidence Index E01/E08](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “모델·LLM·실행기를 같은 AI로 묶지 않고 책임을 먼저 정의한다. 탐지 결과를 인간 통제 하의 자율 조사로 연결한다.”
- 예상 시간: 60초.
- 예상 질문: SOC Agent가 자동으로 차단하는가?
- 답변: 이 보고서의 핵심은 read-only 조사이며 위험한 집행은 정책·인간 승인 뒤다.

## 02. 기획 배경

- 핵심 메시지: 경보 생성 이후의 조사 단절을 해결하는 것이 문제다.
- 화면 본문: Signature/이상점수만으로 사건 맥락·조사 이력·권한이 생기지 않는다.
- 그림·표: 탐지→조사 단절 개념도
- 실제 근거: [Evidence Index E01](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “조사 부담 감소는 가설이고 실제 운영 인력 절감 실험은 없음을 밝힌다. 경보 생성 이후의 조사 단절을 해결하는 것이 문제다.”
- 예상 시간: 60초.
- 예상 질문: 실제 SOC 업무 절감률은?
- 답변: 측정하지 않았다. 본 성과는 연결·감사·복구의 기술 검증이다.

## 03. 아홉 가지 핵심 문제

- 핵심 메시지: 입력 신뢰부터 Cleanup까지 모두 판단 품질에 영향을 준다.
- 화면 본문: 불완전Flow·이기종·중복·LLM불확실·안전종료
- 그림·표: 종합 보고서 문제표
- 실제 근거: [Evidence Index E02/E08/E16](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “높은 모델 F1만으로 실시간 시스템을 완성할 수 없음을 문제표로 설명한다. 입력 신뢰부터 Cleanup까지 모두 판단 품질에 영향을 준다.”
- 예상 시간: 60초.
- 예상 질문: 가장 먼저 실패하는 지점은?
- 답변: 시험마다 다르며 최신은 Helper Heartbeat 송신 공백이다.

## 04. 성과와 한계의 경계

- 핵심 메시지: 제한 E2E 성공과 장시간 운영 실패를 동시에 제시한다.
- 화면 본문: VERIFIED_OFFLINE/NATIVE/API; 20분·1시간 Native 미완료
- 그림·표: 실험 결과표
- 실제 근거: [Evidence Index E10–E14](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “성공한 범위를 먼저 한정하면 뒤의 모델·GUI 수치가 과장되지 않는다. 제한 E2E 성공과 장시간 운영 실패를 동시에 제시한다.”
- 예상 시간: 60초.
- 예상 질문: 운영 준비가 완료됐나?
- 답변: 운영 승격은 불가하며 제한 RC/연구 검증 범위다.

## 05. 전체 시스템

- 핵심 메시지: 기존 Core를 중심으로 수집·추론·조사를 결합했다.
- 화면 본문: Collector/Queue/Window/Model/Incident/SOCRuntime/GUI
- 그림·표: 그림1
- 실제 근거: [Evidence Index E02/E08](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “데이터와 제어의 책임을 구분하고 뒤 슬라이드의 위치를 지도처럼 안내한다. 기존 Core를 중심으로 수집·추론·조사를 결합했다.”
- 예상 시간: 60초.
- 예상 질문: 왜 새 framework를 안 썼나?
- 답변: 고정 역할과 기존 core 계약으로 요구를 충족하며 이중 구현을 피했다.

## 06. Native TCX

- 핵심 메시지: Kernel hook 성공과 Runtime 전달 성공은 별개다.
- 화면 본문: BTF→load→attach→READY→IPC→Window
- 그림·표: 그림2
- 실제 근거: [Evidence Index E11](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “BTF 문제와 verifier 문제를 독립 검증 단계로 설명한다. Kernel hook 성공과 Runtime 전달 성공은 별개다.”
- 예상 시간: 75초.
- 예상 질문: libbpf parse가 되면 실행 가능한가?
- 답변: 아니다. Kernel load/verifier/attach는 별도 실환경 검증이다.

## 07. DNS 수집·Transaction

- 핵심 메시지: 실제 DNS 수집은 성공했지만 DNS9 추론은 차단한다.
- 화면 본문: local dnsmasq UDP2/TCP1; client/server/queryID correlation
- 그림·표: 그림3
- 실제 근거: [Evidence Index E06/E12](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “Raw→Transaction은 프로토콜 문제, DNS9는 학습 계약 문제라는 구분을 강조한다. 실제 DNS 수집은 성공했지만 DNS9 추론은 차단한다.”
- 예상 시간: 60초.
- 예상 질문: DNS 모델이 있는데 왜 안 쓰나?
- 답변: 원본 extractor/scaler/export 동등성이 없어 임의 feature로 실행하지 않는다.

## 08. Authentication

- 핵심 메시지: 읽기 전용 Host 입력과 IF 모델 입력의 완결성을 따로 검증한다.
- 화면 본문: Journal cursor/event ID→계정300초→5개feature
- 그림·표: 그림4
- 실제 근거: [Evidence Index E07](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “이벤트 부족이나 승인 부재를 synthetic 성공으로 대체하지 않는다. 읽기 전용 Host 입력과 IF 모델 입력의 완결성을 따로 검증한다.”
- 예상 시간: 60초.
- 예상 질문: Live IF가 검증됐나?
- 답변: 이번 근거에서는 EVIDENCE_REQUIRED다.

## 09. 데이터셋과 분할

- 핵심 메시지: Network14 CTU와 Top40 CIC는 다른 연구다.
- 화면 본문: CTU session split, CIC V2/V3/V4; validation 시간 역전/host독립 한계
- 그림·표: Model Analysis 데이터표
- 실제 근거: [Evidence Index E04/E05](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “수치 비교 전 sample단위와 분할 protocol을 정의한다. Network14 CTU와 Top40 CIC는 다른 연구다.”
- 예상 시간: 60초.
- 예상 질문: Validation보다Test점수가 낮은 이유는?
- 답변: 분포 이동·선택편향이 관측되며 특정 원인을 하나로 확정할 수 없다.

## 10. Feature Engineering

- 핵심 메시지: 14개 숫자를 만들었다고 적격 Flow가 되지 않는다.
- 화면 본문: 첫관측방향/IPbytes/IAT/populationstd/flags
- 그림·표: Network14 계산표·그림2
- 실제 근거: [Evidence Index E03](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “mean과populationstd를 증분sum/squares로 계산하고 eventclock을 유지함을 설명한다. 14개 숫자를 만들었다고 적격 Flow가 되지 않는다.”
- 예상 시간: 75초.
- 예상 질문: Zeek conn.log로 대체할 수 있나?
- 답변: lifetime/방향/window 의미가 달라 자동 대체하지 않는다.

## 11. Model Admission

- 핵심 메시지: 성능과 입력·권한 적격성은 독립 조건이다.
- 화면 본문: schema→provenance→attestation→fingerprint→Action
- 그림·표: 그림6
- 실제 근거: [Evidence Index E03/E04/E15](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “이 경계 때문에 비어 있는 Prediction이 정상 대기일 수 있음을 연결한다. 성능과 입력·권한 적격성은 독립 조건이다.”
- 예상 시간: 60초.
- 예상 질문: 승인으로 UNKNOWN도 추론 가능한가?
- 답변: 아니다. 인간 승인은 입력 검증을 우회하지 않는다.

## 12. RF/LR 선정

- 핵심 메시지: Quality는 validation 품질, Edge는 제한 조건을 만족하는 latency로 선택했다.
- 화면 본문: RF128/depth12, LRscaledC1; threshold0.35/0.8
- 그림·표: Model Analysis 후보표
- 실제 근거: [Evidence Index E04](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “작은 RF가 더 좋은 validation 점수여도 LR의 선택 목적은 지연이라는 trade-off를 설명한다. Quality는 validation 품질, Edge는 제한 조건을 만족하는 latency로 선택했다.”
- 예상 시간: 75초.
- 예상 질문: 왜 DNN 대신 RF/LR인가?
- 답변: 운영14계약과 당시 고정 연구 후보의 선정 결과이며 Top40 DNN을 직접 대체할 수 없다.

## 13. 정확도와 운영 위험

- 핵심 메시지: Native 실행 성공은 탐지 안전성 인증이 아니다.
- 화면 본문: RF Test FPR15.19%; LR Test FNR27.25%
- 그림·표: 실제 CSV 기반 성능 SVG
- 실제 근거: [Evidence Index E04](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “Validation만 보여 주지 않고 Test confusion matrix와 base-rate 위험을 같이 보여 준다. Native 실행 성공은 탐지 안전성 인증이 아니다.”
- 예상 시간: 60초.
- 예상 질문: Zero-day를 잡는가?
- 답변: 이 실험으로 일반적인 zero-day 탐지 능력을 입증하지 못한다.

## 14. 실제 Deep Learning

- 핵심 메시지: Top40 DNN은 존재하지만 현재 Native14와 다르다.
- 화면 본문: 40→128→128→64→15; BN/ReLU/Dropout; AdamW
- 그림·표: DNN layer표
- 실제 근거: [Evidence Index E05](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “높은 accuracy와 낮은macroF1의 차이, loss/softmax/eval mode를 설명한다. Top40 DNN은 존재하지만 현재 Native14와 다르다.”
- 예상 시간: 75초.
- 예상 질문: CNN/LSTM도 썼나?
- 답변: 조사 범위에서 학습·운영 근거를 확인하지 못했다.

## 15. DNS INT8의 경계

- 핵심 메시지: 양자화 Artifact 분석과 원본 학습 검증을 구분한다.
- 화면 본문: 9→64→32→16→1; input/output quantization; trainingUNKNOWN
- 그림·표: DNS model표
- 실제 근거: [Evidence Index E06](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “이전 구현 parity가 원본 학습 extractor 동등성을 의미하지 않음을 설명한다. 양자화 Artifact 분석과 원본 학습 검증을 구분한다.”
- 예상 시간: 60초.
- 예상 질문: 성능그래프가 왜 없는가?
- 답변: 해당 DNN의 평가 원본이 없어 임의 그래프를 만들지 않는다.

## 16. Agent와 일반 Pipeline

- 핵심 메시지: 추가 근거를 계획하고 평가하는 작업에 LLM을 제한한다.
- 화면 본문: Observation/Hypothesis/Decision 분리·ToolRegistry
- 그림·표: 그림7
- 실제 근거: [Evidence Index E01/E08](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “규칙으로 고정할 수 없는 제한 조사 제안과 deterministic 집행을 구분한다. 추가 근거를 계획하고 평가하는 작업에 LLM을 제한한다.”
- 예상 시간: 60초.
- 예상 질문: 그냥 chatbot과 무엇이 다른가?
- 답변: explicit state·Tool·checkpoint·권한·평가·audit가 실행 과정의 근거다.

## 17. 기존 SOCRuntime 재사용

- 핵심 메시지: 조사 core의 상태·claim·policy 계약을 유지했다.
- 화면 본문: Continuous→Source→Task→ApplicationService→SOCRuntime
- 그림·표: 그림5
- 실제 근거: [Evidence Index E08](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “Collector가 LLM을 기다리지 않는 별도 queue/consumer 경계를 설명한다. 조사 core의 상태·claim·policy 계약을 유지했다.”
- 예상 시간: 75초.
- 예상 질문: 새 Orchestrator는 없는가?
- 답변: 기존 core에 좁은 adapter/store를 연결했으며 범용 Agent framework는 없다.

## 18. 역할·충돌·중복 제어

- 핵심 메시지: 같은 사건을 반복 조사하지 않고 새 증거는 revision으로 구분한다.
- 화면 본문: Network/DNS/Auth/Investigation; target/scope/clock/bucket
- 그림·표: 그림5·revision표
- 실제 근거: [Evidence Index E08](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “알 수 없는 identity는 근거 없이 merge하지 않으며 conflict는 추가 조사의 이유다. 같은 사건을 반복 조사하지 않고 새 증거는 revision으로 구분한다.”
- 예상 시간: 60초.
- 예상 질문: Native conflict도 검증됐나?
- 답변: 실제 발생하지 않은 상황은 offline fixture 검증과 구분한다.

## 19. 우선순위·Checkpoint

- 핵심 메시지: 빠른 사건만 처리하지 않도록 공정성과 복구를 명시한다.
- 화면 본문: priority0–2/overtaking8/claim/uncertain step
- 그림·표: Task 상태전이·그림7
- 실제 근거: [Evidence Index E08](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “crash후외부호출 자동반복이 아닌 review 상태가 안전한 복구임을 설명한다. 빠른 사건만 처리하지 않도록 공정성과 복구를 명시한다.”
- 예상 시간: 60초.
- 예상 질문: Exactly once인가?
- 답변: 외부 side effect까지 일반적 exactly-once를 보장하지 않고 identity/claim으로 중복을 제한한다.

## 20. Tool Calling과 Policy

- 핵심 메시지: LLM 계획은 실행 권한을 만들지 못한다.
- 화면 본문: typed structured output·read-onlyTool·최대round·HumanGate
- 그림·표: 그림7·10
- 실제 근거: [Evidence Index E01/E08/E09](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “Selector가 존재해도 Continuous 빈 registry로 추가 모델 호출을 막는 실제 경계를 설명한다. LLM 계획은 실행 권한을 만들지 못한다.”
- 예상 시간: 60초.
- 예상 질문: Prompt injection으로Root실행 가능한가?
- 답변: LLM shell통로와권한발급통로가없고Tool/schema/policy로제한한다.

## 21. 실제 LLM API 결과

- 핵심 메시지: Plan 성공과 Assessment Timeout을 함께 보존한다.
- 화면 본문: 2requests/retry0; 9.139s Plan/20s timeout; billingUNKNOWN
- 그림·표: API 실험표
- 실제 근거: [Evidence Index E10](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “시간초과가무료/원격미실행이라는주장이아님을비용·checkpoint와연결한다. Plan 성공과 Assessment Timeout을 함께 보존한다.”
- 예상 시간: 75초.
- 예상 질문: 다시호출하면되지않나?
- 답변: uncertain request자동retry금지이며새별도승인이필요하다.

## 22. Control/Data Plane

- 핵심 메시지: 생존 신호와 업무 진척을 분리해야 한다.
- 화면 본문: Heartbeat/ProcessIdentity vs Queue/Window/StorageProgress
- 그림·표: 그림8
- 실제 근거: [Evidence Index E14/E16](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “긴write가control을막는문제와heartbeat만살아있는문제를동시에다룬다. 생존 신호와 업무 진척을 분리해야 한다.”
- 예상 시간: 60초.
- 예상 질문: DB가멈춰도RUNNING인가?
- 답변: control생존과data정체를분리해DEGRADED로표시해야한다.

## 23. Heartbeat RCA

- 핵심 메시지: 수신 경합 수정 뒤 실제 송신 공백은 남아 있다.
- 화면 본문: seq408→409;4.181s gap; IPCempty; causeUNKNOWN
- 그림·표: Timeline RCA표
- 실제 근거: [Evidence Index E12/E16](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “throttledcounter와elapsedinterval의한계로원인을단정하지않는다. 수신 경합 수정 뒤 실제 송신 공백은 남아 있다.”
- 예상 시간: 75초.
- 예상 질문: Timeout을늘리면해결아닌가?
- 답변: 계약위반을숨길뿐이며새stage진단으로지연구간을좁힌다.

## 24. STOP·Cleanup

- 핵심 메시지: 정상 종료는 Exit0보다 많은 증거를 요구한다.
- 화면 본문: ACK/CLOSED/counter/drain/socket/PID/link/map
- 그림·표: 그림9
- 실제 근거: [Evidence Index E10–E14](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “소유Scope와GlobalKernel·과거증거와현재snapshot을분리한다. 정상 종료는 Exit0보다 많은 증거를 요구한다.”
- 예상 시간: 60초.
- 예상 질문: 현재자원이없으면과거Cleanup도성공인가?
- 답변: 종료시점증거가없으면소급Verified로바꾸지않는다.

## 25. 단일 CLI·GUI

- 핵심 메시지: 사용자 명령은 단순해도 Backend 권한·상태는 정확해야 한다.
- 화면 본문: setup/start/status/stop/gui/doctor; origin/blocked reason
- 그림·표: 실제Native실패GUI이미지
- 실제 근거: [Evidence Index E15/E18](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “숫자가없으면실패라는fullacceptance요구를없는결과생성으로해결하지않는다. 사용자 명령은 단순해도 Backend 권한·상태는 정확해야 한다.”
- 예상 시간: 60초.
- 예상 질문: 모델latency가왜비어있나?
- 답변: 해당session실제승인추론이없으면없는값이정확하다.

## 26. 실험 설계와 결과

- 핵심 메시지: Replay·Native·API를 같은 시험으로 합산하지 않는다.
- 화면 본문: 제한Native성공/20분Replay성공/최신91.81s실패
- 그림·표: Experiment Results 비교표
- 실제 근거: [Evidence Index E10–E14](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “실제wall시간과event시간·whole/attach/seal구간의차이를설명한다. Replay·Native·API를 같은 시험으로 합산하지 않는다.”
- 예상 시간: 60초.
- 예상 질문: 1시간은검증됐나?
- 답변: 아니다.과거53분대/18분/최근단기시험을합쳐성공으로세지않는다.

## 27. 최소 안정화와 회귀

- 핵심 메시지: 이번 변경은 원인 진단 보강이며 Native 해결 선언이 아니다.
- 화면 본문: typed completed-loopstage·strictmanifest·Workspace/Export/build
- 그림·표: Validation Results
- 실제 근거: [Evidence Index E16](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “첫회귀의manifestmismatch도보존하고새hash정합성을검증한과정을설명한다. 이번 변경은 원인 진단 보강이며 Native 해결 선언이 아니다.”
- 예상 시간: 60초.
- 예상 질문: manifest갱신이승인우회아닌가?
- 답변: 새sourceidentity를기록한것이며실제실행권한은별도미발급이다.

## 28. 성과·한계·다음 조건

- 핵심 메시지: 수집·입력 신뢰·조사·감사를 연결했지만 장시간과 일부 source는 미완료다.
- 화면 본문: Native20/60min·Assessment·HostIF·DNS9·GlobalKernel
- 그림·표: 한계 및차기Scope표
- 실제 근거: [Evidence Index E04/E06/E07/E12](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “운영승격보다다음제한시험에서무엇을관측해야하는지구체적으로말한다. 수집·입력 신뢰·조사·감사를 연결했지만 장시간과 일부 source는 미완료다.”
- 예상 시간: 60초.
- 예상 질문: 실무전환에가장필요한것은?
- 답변: 다양한독립데이터/장기간실환경/운영승인/복구검증이며모델score만높이는것이아니다.

## 29. 결론

- 핵심 메시지: 자율 조사의 가치는 근거와 통제를 잃지 않는 데 있다.
- 화면 본문: LLM recommends/Policy decides/Human approves/Executor acts
- 그림·표: 전체지도와결과요약
- 실제 근거: [Evidence Index E01/E08/E17](Evidence_Index.md); 모델표는 [Model Analysis](Model_Analysis.md), 실험표는 [Experiment Results](Experiment_Results.md).
- 발표 대본 초안: “계획·구현·실험·실패·불확실성을구분하는엔지니어링을최종성과로정리한다. 자율 조사의 가치는 근거와 통제를 잃지 않는 데 있다.”
- 예상 시간: 60초.
- 예상 질문: 프로젝트의차별점은?
- 답변: 실제Native입력계약과기존조사workflow를감사·승인·cleanup증거로연결한것이다.

## 발표 전 체크

Native 원본 화면과Fixture화면을섞지않는다. top40/Network14/DNS9그래프의입력·split을캡션에명시한다. TaskWAITING_HUMAN을조사해결로바꾸지않는다. 예전승인CLI명령을발표중실제로재실행하지않고`--preview`와보존결과읽기를구분한다. 미공유Git외부증거는권한·민감정보검토후별도제공하며APIkey/패킷payload는슬라이드에넣지않는다.
