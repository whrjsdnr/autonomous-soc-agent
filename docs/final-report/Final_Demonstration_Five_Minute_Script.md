# 5분 발표 대본 및 화면 해설

## 0:00–0:40 — 문제와 목표 / Native Dashboard

“Autonomous SOC Agent는 탐지 결과를 조사와 감사까지 연결하는 연구용 SOC 시스템입니다. 단순히 로그를 LLM에 요약시키는 대신, 관측한 사실·가설·결정을 구분하고 명시적인 Incident 상태를 관리합니다. 오늘은 실제 실행에서 확보한 결과를 GUI로 보여드리겠습니다. Native 시험과 PCAP·API 시험은 서로 다른 실행이며, 새 실시간 수집을 하고 있는 것은 아닙니다.”

문제는 탐지량뿐 아니라 입력 신뢰성, 중복 조사, 장애 후 종료 증명이다. 전체 Live 무인 운영이 완료됐다는 소개는 하지 않는다.

## 0:40–1:30 — 수집·Feature·모델 / Continuous

“과거 제한 Native 시험에서 Packet54건, DNS Transaction3건을 수집했고 세 Window의 Attestation을 검증했습니다. Flow 중 ELIGIBLE5개만 분석 대상으로 삼았으며 INCOMPLETE2개를 정상 입력으로 승격하지 않았습니다. RF/LR Prediction8건, Incident2건이 남아 있습니다.”

“RF는 비선형 특징 상호작용을 표현하는 quality 모델, LR은 작은 모델과 낮은 지연을 지향하는 edge 모델입니다. 선택 기준은 검증 데이터의 AP·F1·Recall·FPR와 지연입니다. RF가 모든 환경에서 더 좋다는 뜻은 아닙니다. 실제 보고서의 test 결과에서도 RF 오탐, LR 미탐 trade-off가 남습니다.”

근거: [Model_Analysis.md](Model_Analysis.md) §5. RF128trees/max_depth12/min_leaf3; LR StandardScaler+C1/max_iter2000. RFtest F1≈0.9187/FPR≈0.1519, LRtest F1≈0.8407/FNR≈0.2725. 이 수치를 현재 Native 탐지 정확도로 소개하지 않는다. Native 작은 샘플은 실행 연결 검증이다.

## 1:30–2:25 — Incident·Orchestration / ELIGIBLE 보고서·Task

“ELIGIBLE Incident를 선택하면 실제 RF/LR 결과, 입력 provenance, Audit를 확인할 수 있습니다. SOCRuntime은 기존 Planner·Tool·Assessor를 조합합니다. Claim과 revision으로 같은 증거의 중복 실행을 막고, Evidence가 바뀌면 재평가하며, Checkpoint로 진행 상태를 보존합니다.”

“이 Native 회차의 조사는 SCRIPTED입니다. Task5개와 우선순위, WAITING_HUMAN 상태를 보실 수 있습니다. LLM 제안과 실제 실행 권한은 다르고 권한 검증은 결정론적 코드가 맡습니다.”

Continuous에서 ELIGIBLE 행 선택 → Inspect Selected Incident → AI Analysis의 Prediction·Evidence/Audit. 이 회차의 SCRIPTED 조사는 분석 보고서가 아니라 별도 Continuous Task에 있으므로 Continuous 하단 또는 Investigation에서 보여준다. INCOMPLETE 행의 Prediction0은 입력 차단의 정상 결과다.

## 2:25–3:20 — 실제 LLM Plan·Tool·Assessment / API 화면

Native 창 닫기 후 `show-demo api` 실행.

“이 화면은 별도 PCAP 시험에서 실제 API를 두 번 호출한 결과입니다. 첫 호출은 조사 계획, 두 번째는 수집한 Evidence 평가입니다. 중간에 허용된 read-only Tool을 사용했습니다. Structured Output을 검증하고 정책·Checkpoint·Audit를 통과시켰습니다. 현재 화면 열기는 API를 다시 호출하지 않습니다.”

“다른 운영 시험에서는 Assessment Timeout과 Usage 미수신이 발생해 비용을 UNKNOWN으로 남겼습니다. 그 이력은 성공으로 덮지 않았습니다. 조사 결론도 관측 사실과 분리하며 자동 방화벽 변경 같은 대응은 허용하지 않습니다.”

AI Analysis → Investigation 탭에서 plan/step/status/assessment, Evidence·Audit에서 provenance·감사 확인. 실제 API2회 기록과 Native SCRIPTED를 합쳐 같은 Session의 Full E2E로 설명하지 않는다.

## 3:20–4:10 — Replay와 Authentication / 보조 화면

“저장 PCAP의 20분 Replay 시험에서는 누적406 Prediction과203 Incident를 기록했습니다. 이것이 20분 Native 운영 성공을 뜻하지는 않습니다. 최근 행만 보여주는 GUI 목록과 전체 누적 계수도 구분해야 합니다.”

“Authentication은 계정별 Window를 사용하고 기존 IsolationForest로 이상 점수를 평가하는 구조입니다. IF는 특정 공격명을 맞히는 지도 분류기가 아니라 상대적으로 고립되는 패턴을 찾습니다. 그러나 실제 Host READY·입력 적격성·작업별 IF 승인까지의 전체 Live 경로는 아직 미완료이므로 이 화면에서 IF 성공을 주장하지 않습니다.”

시간이 부족하면 replay/authentication은 준비된 실제 Screenshot으로 전환한다. 별도 Host 읽기 진단16건은 일반 로그 포함/적격 인증 이벤트와 다르므로 IF 입력16건이라 부르지 않는다.

## 4:10–5:00 — 종료·한계·기여 / STOP·Cleanup

“과거 Native 회차의 TCX STOP ACK, Helper CLOSED, 소유 Root·Runtime Cleanup 증거가 보존되어 있습니다. Exit0만으로 전체 Kernel Cleanup을 성공 처리하지 않습니다. 오늘 GUI는 원본을 읽기 전용으로 열고 새 실행을 차단합니다. 닫았다가 같은 명령으로 다시 열어도 결과와 Audit가 유지됩니다.”

“핵심 성과는 탐지·조사·승인·감사를 하나의 추적 가능한 흐름으로 연결한 점입니다. 남은 과제는 Host 시작 지연과 TCX 장시간 송신 공백의 직접 원인 규명, 실제 동일 Session의 전체 Live 성공, 더 긴 운영과 입력 분포 변화 검증입니다.”

창 닫기 또는 Ctrl+C. 시간 내에는 새 Capture·모델·API 버튼을 누르지 않는다.

## 예상 질문

- **지금 실제 분석인가요?** 과거 실제 Native/Replay/API 결과의 검증된 조회다. 이번 시연에서 새 추론·외부 API를 실행하지 않는다.
- **모든 경로가 하나의 Native Session에서 성공했나요?** 아니다. 별도 성공·실패 범위를 구분하며 FULL_LIVE_E2E_VERIFIED를 부여하지 않았다.
- **왜 RF와 LR을 모두 쓰나요?** 검증 지표와 지연 목표가 다른 quality/edge 프로파일이다. 상충 결과는 추가 Evidence/조사 대상으로 다루며 한 결과를 공격 사실로 확정하지 않는다.
- **왜 딥러닝이 최종 실시간 모델이 아닌가요?** 연구 모델의 학습 성능과 운영 Feature 계약은 별개다. 이번 실시간 경로에서 확인된 모델은 Network14 RF/LR이다. 사용하지 않는 DL을 운영한다고 주장하지 않는다.
- **왜 IF 결과가 없나요?** 실제 Host 입력·READY·Window 적격성의 Live 검증이 끝나지 않았다. 새 Fixture 결과를 Host 결과로 대체하지 않았다.
- **LLM이 Root를 사용할 수 있나요?** 아니다. Plan은 제안이며 Tool 권한, 승인, 실행 한도는 별도로 검증한다.
- **중단 후 모든 작업이 완료됐나요?** 아니다. Native POISON1, Replay PENDING4를 그대로 보존한다. GUI close와 작업 처리 완료는 다르다.
- **Live 재시험을 바로 할 수 있나요?** 새 승인과 잔류 자원 검증 등 독립 조건이 필요하다. 시연용 명령은 Live 권한을 생성하지 않는다.
