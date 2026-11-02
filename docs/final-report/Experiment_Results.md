# 실험 결과 원장 — 성공·실패·Scope의 분리

## 1. 측정 규칙

전체 실행은 Launcher/설치/준비/READY/수집/STOP/정리까지의 wall time이다. Collector attached wall은 부착 구간이며, 검증된 수집 시간은 독립 Seal의 enabled interval 합이다. 단순 프로세스 uptime을 순수 수집으로 사용하지 않는다. STOP 진단 Seal은 실패 후 수집된 유용한 증거이지만 자동으로 모델 적격 구간이 되지 않는다. 서로 다른 Session의 packet·Prediction·시간을 합하지 않는다. 아래 값은 기존 실제 증거를 읽어 재구성했으며 이번 보고서 작업에서 새 Native/API 실행은0회다.

Packet 표기는 해당 시험의 TCX supported metadata/callback 수이며, Raw frame 전체 수나 시스템 전역 packet 수와 같다고 가정하지 않는다. 실제 GUI도 raw packet count/system-wide loss UNKNOWN을 명시한다.

## 2. 주요 시험 비교

| 시험/실행 코드 | 환경·승인 범위 | 전체/순수 검증 수집(s) | Packet·DNS | Window·입력 | Prediction·Incident/Task | GUI·Cleanup | 판정·최초 오류 |
|---|---|---|---|---|---|---|---|
|초기 제한Native AI, e3412e8 보고 기준|전용NS lo/Ingress, 제한 capture·작업승인|정확한 시간은 해당 원본 참조|20·DNS값 미기재|2, eligible1|2·Incident1|연결·ownedCleanupVerified|제한 E2E; 당시 SCRIPTED|
|Native Orchestration, c542398 실행/7a1b6f3 보고기준|600s 전체, TCP4/DNS UDP2TCP1, 별도 작업Action|404.593137 /396.136964|54·3|3VERIFIED, eligible5/incomplete2|8·Incident2/Task5|6개Tk화면·owned 모두Verified|NATIVE_ORCHESTRATION_VERIFIED, SCRIPTED; error없음|
|TCP전용 장시간,3fac4c0 실행|전체3600목표,localTCP36연결,DNS제외|Collector포함3208.187698 /uptime3195.347421(순수와다름)|metadata360(마지막20미전달)·DNS0|Root18/Runtime17seal,eligible17/incomplete17|22·Incident11|Runtime/RootownedVerified,remoteACKUNKNOWN|PARTIAL,RUNTIME_FIRST_ERROR:TimeoutError|
|실제 API A,66814fc|보존NativeIncident,2call/$0.05/no retry|Plan9.139,Assessment20s timeout|새Capture0|고정revision|모델Action아님, API2|Plan/Timeout/Audit·재연결2|Plan VERIFIED_API; Assessment Timeout/전체PARTIAL|
|11-02 별도Assessment 재검증,568e759/43b2042|보존Plan/Tool 재사용,1call/$0.05/20s/no retry|20.065073 whole,request20.022782|Capture0|고정기존Evidence|API1/Assessment없음|Tk2회Timeout·비용UNKNOWN표시/AuditVerified|PARTIAL,LLMTimeoutError|
|Native one-hour B,66814fc|순수3600목표/전체4200,localTCP/DNS|1165.985 /1080.335|134+격리10·3|6VERIFIED+diagnostic1, eligible9/incomplete6|8·Incident2/Task5|실제GUI/RootownedVerified,RuntimeUnverified|PARTIAL,ProducerReceiveTimeout|
|20분 실제경과Replay, c6405d7 시기 작업소스|저장PCAP/실제RF·LR/SCRIPTED/Unixcontrol simulated|1200.132397 wall, Native0|packet619/received1035, DNS0|flows207, eligible206/incomplete1|406·Incident203|GUI3회재연결,STOPPED/CleanupVerified|VERIFIED_OFFLINE, Kernel미실행|
|6분Heartbeat진단,5e70da8/a2914a0|전체600,기존NS/TCP4/DNS3,모델제외|370.838988 /361.041374|54·3|3VERIFIED,eligible5/incomplete2|0(미승인)·DNS SCRIPTEDtask3|재연결·TCX/Helper/Root/RuntimeVerified|NATIVE_HEARTBEAT_DIAGNOSTIC_VERIFIED|
|Native20 저장복구, c6405d7/fd53942|순수1200/전체1800,TCP8/DNS3,모델제외|66.986 whole / RuntimeVERIFIED0|callbacks14=수신12+격리2, DNS2|RuntimeWindow0/진단Seal1|0|Helper/TCX/RootVerified,RuntimeUnverified|HELPER_HEARTBEAT_OR_PROCESS_STALE|
|설치mode 실패, a2914a0 시기준비|단일승인 Native입장|4.196 /0|0·0|0|0|설치권한문제 보존|PermissionError,외부time-rebinder오류|
|mode복구 후, a2914a0|새Scope/새승인·NS/TCP/DNS|199.394 /적격Window0|34·3|RuntimeWindow0|0|TCXACK/RuntimeUnverified,Root/HelperVerified|RuntimeReceiveTimeout; ObserverHeartbeatStale|
|DNS상태 격리1,260e760/49ef77b|새Native20 Scope,모델미입력|427.693390 /420.273763|54·3|3VERIFIED,eligible5/incomplete2|0(당시Actionyes없음)|모든ownedCleanupVerified|Root DNS_RECEIVER_NOT_RUNNING_OR_PROVED_COMPLETE|
|최신전체,db5e8dc/aead2e9 실행|1200/1800목표,TCP8/DNS3,새Binding|91.808838 /85.895973|24·3|STOPSeal1VERIFIED,eligible2/incomplete2|0(첫180sSeal전실패),DNStask3|실제Tk실패화면,모든ownedCleanupVerified|HELPER_HEARTBEAT_OR_PROCESS_STALE|

초기20건 행은 [Continuous 보고](../linux-soc-v1/continuous-runtime-integration-report.md)의 해당 성공 요약 수준이다. 미확인 전체 시간·DNS값을 임의 보간하지 않았다. [E10–E14](Evidence_Index.md#e10) 및 [역사 Native 성공 보고 원본](assets/native-orchestration-report-7de4794.md)을 연결한다.

## 3. 제한 Native Orchestration의 실제 증명

원본 `native-orchestration-approved-attempt-20261030T093317Z/native-result-verified.json`, 실행 Session `bd5cd8aa-66b4-4e1d-b997-bc38f9bfb97b`, DNS `0771bfdf-3f98-4181-b21e-3b15772e15c8`이다. 실행 코드는c542398이며71377c7은 그 뒤 Worker status correction이다. 수정 코드를 이전 성공에 소급 적용하지 않는다.

TCX54 callbacks=epoch별34+20+0, DNS14metadata=6DNSmessage+8TCPcontrol, RCODE0/error0이다. 별도 승인된 봉인Job `35480ca1733c9044da127d11e8aa36ea0dd145fcd78e6eef2afff05b49686937`에 대해8RF/LR호출을 수행했다. Task5는 immutable revision으로 각1회Claim/DONE, Read-only report완료/Assessment checkpoint7/WAITING_HUMAN이다. WAITING_HUMAN은 침해확정이나 response완료가 아니다.

Audit58행 chainVerified, drop/sourcegap/modelerror/restart0이다. 두 번째 적격 Window의 미승인Job은 종료 후POISON/INFERENCE_UNAVAILABLE로 남았다. 모델이 모든 적격입력을 자동승인받아 소진한 시험이 아니다. SCRIPTED Provider의 실제Workflow 통과를 실제LLM 조율 성공으로 표기하지 않는다.

## 4. 실제 API Plan과 실패 Assessment

고정 Incident `83d6db5e-7b0a-5b39-934a-97e860b3b752`, Task `74819a09-b7c4-5891-a35d-d4ca71e25c99`, revision `9c82b6ff11f6a23cec30163e2280b4c3474e729640b947de3dceac85c1901295`를 사용했다. 실제 Provider OpenAI/gpt-5-mini, 호출2회/재시도0, Plan input2264/output689, 당시 계약 예상확정 응답비용$0.001944이다. Assessment는20초 Timeout이고usage미수신이므로 전체 billing UNKNOWN이다. 로컬reserved combined$0.02255775와 실제 과금을 동일시하지 않는다. [E10](Evidence_Index.md#e10)

Plan과Tool이 성공했어도Assessment가 실패했으므로 LLM_ORCHESTRATION_VERIFIED를 부여하지 않았다. Replan미실행이다. provider원격원인UNKNOWN이며 후속wrapper assertion/exit2는 최초 APITimeout과 구분한다. GUI는checkpoint5FAILED/Plan/Timeout을 실제 재연결2회 표시했다. 실제 API 응답을 재사용한 것과 새로운LiveNative에서동시LLM조사한 것을 혼동하지 않는다.

## 5. 실제 20분 Replay의 증거

원본 공통 Git `runtime-storage-isolation-20261102T013653Z/soak20-recovery/verified-result.json`, [검증 요약 사본](assets/replay20-summary.json). wall1200.132397초, source unchanged, queue/service/orchestration/분석DB integrity OK. Queue207행=DONE203/PENDING4, packets619·flows207·eligible206·incomplete1·predictions406·incidents203·drop0/modelerror0. 상태STOPPED/CleanupVerified다.

Control publication max1.090384초, data storage max5.268050초, GUI3회재연결. 별도observer는관측publication간격최대2.092039초,age2.094743초를기록했지만 scope가 later portion/관측sequence차이이므로 전 구간wire gap 최대라고 해석하지 않는다. received1035에는 excluded416 등이포함돼 packets619와다르다.

이 시험은 저장된실제PCAP와실제RF/LR을사용했지만 control은simulatedUnix이고Nativeevents0이다. 20분wall성공은 가상event-time5시간 또는5000event내구성과도다른시험이다. 이전soak20-final/stages/accepted에서는CONTINUOUS_DATA_PROGRESS_STALLED가발생했고실패증거를남겼다. 성공한recovery만있었던것처럼축약하지않는다.

## 6. 최신 실패의 독립 카운터

| 계층 | 실제 관측 | 해석 |
|---|---|---|
|Helper 마지막heartbeat|seq408, generate→receive1.302270ms|해당 record IPC 전달 정상|
|다음CLOSED|seq409, previous-send완료와4.181036875s차이|연속송신공백 확인; 정확한작업UNKNOWN|
|Reader판정|age2.236042s, pollgapmax0.818836s|2s계약위반; Reader종료와다름|
|IPC|FIONREAD0, send/receivebuffer212992, queue0/32|관측시점backlog없음; 모든시간혼잡부재증명아님|
|CPU|nr_throttled51→71,throttled_usec동일4520591|snapshot해석제한; quota원인확정불가|
|RootControl|AuditHeartbeatmax1.536483s|Helper2s실패와다른생존경로|
|RuntimeStorage|update max6.952602s,publicationmax0.039924s|해당계층격리계측,Helper공백원인확정아님|
|최종process|모든ownedserviceMainPID0,Runtimeexit2,TCPsignal15|실패후stop; Exit0전체성공아님|

첫180초자동Seal전에실패했으므로RF/LR/latency/NetworkIncident0이다. 이시험은사용자가ModelActionyes를입력하지않아서만실패한것이아니다. 마지막GUI의DNSSTOPPING은뒤에ac33af8에서수정된실제표시결함이며과거snapshot을바꾸지않았다. DNStransaction3과Cleanup성공은보존하되전체통합FAIL이다.

## 7. 현재 결과를 발표할 때의 제한

실험수치가다른것은버전/권한/Session/측정경계가다르기때문이다. Packet134+격리10을144개모두Runtime처리로표시하지않고·Window6+diagnostic1을모두적격Window7로세지않는다. 실제APIPlan성공을SCRIPTEDAssessment와합쳐완전한실제LLM성공으로표시하지않는다. Snapshot의CleanupVerified는그시점의소유Scope에만적용한다.

최종운영판정은NATIVE_OPERATIONS_PARTIALLY_VERIFIED다. 20분·1시간실제수집목표는미달이며추가실행은새Binding과인간승인·인증후에만가능하다. 이번보고서의신규테스트/빌드는Validation_Results에별도기록하고위과거실험카운터를갱신하지않는다.

## 8. 2026-11-02 단일 Assessment의 후속 실제 결과

원본 공통 Git `reliability-live-validation-review-20261102T001146Z/llm-assessment/future-attempt/result.json`과 `api-failure-0.json`이다. Provider OpenAI/gpt-5-mini,실제1회/재시도0회,예약$0.011354,출력한도4096토큰,local deadline20초였다.실제응답latency기록20,022.782ms/전체20.065073초,최초LLMTimeoutError,usage null/Assessment null/replan false다.

local deadline 이후 HTTP worker alive가관측됐으므로원격미실행/요청취소완료를보장하지않는다.`confirmed_response_estimate_usd=0`은확정응답이없다는뜻이며실제무료가아니다.billing_outcome UNKNOWN_REQUIRES_REVIEW, total_estimated null을유지했다.기존Workflow를자동Resume하지않았다.

`gui-audit-verification.json`은별도Tk연결2회에서실제호출수1·Timeout·unknowncost·기존Plan/완료Tool유지를확인했고Audit/receiptbinding PASS였다.이후Native에서의LLM성공으로합산하지않는다.이후새API는이번보고서작업에서호출하지않았다.
