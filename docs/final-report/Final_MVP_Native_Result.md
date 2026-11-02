# Research MVP Native 통합시험 — 첫 시험 실패와 수정

## 실제 실행 결과 — 별도 시험과 합산 금지

실행 코드1fcbff2/동결HEAD bbaeccd/보고기준6f6bcb0.
Runtime `b3edc588-aec1-47ae-940a-3ba10d7e0060`, DNS `5cbf2a22-aeec-4d08-8f01-79c34653e01e`.
사용자 Scope/R1직접확인과sudo인증뒤승인된1회실행. 설치8경로중4변경/4동일검증,
백업8개,KernelBPF/TCX/READY까지진입했다. 원본검토서와실행증거는 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/research-mvp-short-native-review-20261102T091500Z`에보존했다.

| 항목 | 이번 시험의 실제 결과 |
|---|---|
| 관측 전체 worker 실행 | 56.471198초 |
| Root coordinator 실행 | 53.535426초 |
| Root의Collector 시작이후경과(시작/정리포함) | 48.473210초 |
| 검증된Runtime 순수수집 | 0초 — Runtime Window 미봉인 |
| 실패종료의진단Seal enabled interval | 29.293076603초 — Runtime성공수집으로승격하지않음 |
| TCX Native 이벤트 | 12 |
| DNS Transaction | 2 — UDP1/TCP1 |
| DNS 원시메타데이터 | 12개,2Query/2Response/8TransportControl |
| 고정TCP Helper 시작 | 0 — DNS공급원완료전실패 |
| Runtime Window / ELIGIBLE | 0 / 0 |
| RF/LR / Network Incident | 0 / 0 |
| 조사Task | 2 — 실제DNS증거의SCRIPTED 경로,실제LLM아님 |
| Queue Drop / Source Gap | 0 / 0 |
| Queue | 빈상태,과거PENDING2/POISON1은별도기존Session에보존 |
| 실제LLM API / 비용 | 0회 / $0,Key미조회 |
| 최초오류 | CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT |
| Runtime / Root driver 종료코드 | 2 / 2 |
| 자동재실행 | 없음 |

두번째UDP는TCP닫기후35초뒤의고정공급인데그전에실패종료했다. 임의로추가전송하지않았다.
DNS Helper의raw dns_parse_failures8은여기서는TCP제어프레임8건이며Semantic DNS ParseFailure8건이아니다.
기존GUI projection은두지표의범위를이미구분한다. DNS실패수치로잘못해석하지않는다.

## 최초오류와원인구분

마지막정상Control sequence16의Root생성→Runtime수신지연1.402894ms.
이후동일Root PID/Start Identity와연결된IPC상태에서 5.000684396초
인증메시지미수신으로기존5초계약에따라실패했다. 단순무트래픽은Control Heartbeat가계속오므로
이Timeout을무시할근거가아니다. Receiver Queue0/Drop0; 마지막Worker단계INSTALLED_INTEGRITY.
Runtime저장작업최대1.160812초,Control게시최대0.050423초가관측됐다.
마지막Root송신공백의직접원인은UNKNOWN이다. 해당시점Root의CPUThrottling/lock대기/IPC송신시도
전체Trace가없다. CPUQuota25%와같은설정이존재한다는이유로Throttling을확정하지않는다.
프로세스가살아있다는것은Heartbeat송신이나데이터처리정상을증명하지않는다.

## 확인된코드결함과최소수정 — 코드2cfcf7e

1. `ControlTransport.send()`가데이터JSON을Heartbeat/STOP공유lock안에서해석했다.
   느린Data준비가Control을막을수있다. JSON해석을lock밖에서먼저하도록변경했다.
2. 동일함수가generation검증전에이미소켓에데이터를발행했다.
   generation없는잘못된데이터가전송되고나서KeyError가발생함을실제비권한UNIX소켓으로재현했다.
   길이/JSON/generation검증을발행전에수행해미검증데이터가소켓에나가지않도록수정했다.

추가회귀2건은수정전에실패했고수정후기존Control회귀포함8PASS(5.45초).
느린데이터해석중에도인증Control sequence가진행하며,데이터generation은발행후에만갱신된다.
기존5초Receive/Worker계약,Helper2초계약,Namespace/권한/Source/승인검증은변경하지않았다.
이재현결함이이번Native송신공백의직접원인이라는인과관계는아직입증되지않았다.
운영근본원인이모두해결됐다고주장하지않는다.

## 종료·Cleanup 독립검증

- TCX STOP요청 monotonic954287.513852323 → ACK954289.588428588,차이2.074576초.
- TCX ACK와단일진단Seal/FD·Socket종료,원격소유Cleanup VERIFIED.
- DNS authenticated CLOSED/Counter87/Counter VERIFIED/최종sent12,
  ACK순서/Listener·Channel·ReaderJoin/DurableCleanup VERIFIED.
- Helper UID/GID1000,Eff/Prm/Inh/Amb0,CapBnd8192(NET_RAW상한)유지. ExitCode는직접미관측(null);
  그것을Exit0으로꾸미지않고인증CLOSED/프로세스EXITED/서비스종료증거로소유정리를판정한다.
- Root고정서비스의MainPID/Tasks와소유Socket종료,RootAudit SERVICE_STOPPED.cleanup VERIFIED,
  기존Audit prefix보존과TCX소유정리결합으로Root소유범위 VERIFIED.
- Runtime STOPPED/Cleanup VERIFIED/Queue·Audit Flush VERIFIED. Runtime종료2는실패를보존한다.
- Global Kernel Cleanup UNKNOWN. 기존Program1145/과거Heartbeat원인과과거UNVERIFIED/FAILED는그대로다.

## GUI와AI 판정

실제Tk창은실패Session의Native원본분류,오류,DNS증거,소유Cleanup을표시했다.
이번live종료·재연결/Network14적격성/RF-LR/추론Latency/NetworkIncident값은확인되지않아
전체GUI통합성공으로판정하지않는다. 과거Prediction8/GUI재연결성공을이번Session결과로합치지않는다.

API는이번Native Session의실제Network Incident/Evidence Revision을고정하는조건이었다.
그입력이생기지않았으므로API를호출하지않았고,과거Incident로자동대체하지않았다.
실제LLM Plan/Assessment 성공판정도없다. 기존과거Plan성공/AssessmentTimeout기록은보존한다.

| 요청한판정 | 이번시험판정 |
|---|---|
| NATIVE_MVP_VERIFIED | 미충족 — 실제진입은했으므로PARTIALLY_VERIFIED |
| RF_LR_NATIVE_VERIFIED | 미실행 — 적격Window/작업승인없음 |
| LLM_PLAN_VERIFIED | 이번시험미실행 |
| LLM_ASSESSMENT_VERIFIED | 이번시험미실행 |
| GUI_INTEGRATED_VERIFIED | PARTIALLY_VERIFIED — 실패표시확인,전체연결미완료 |
| CLEANUP_VERIFIED | VERIFIED — 이번소유범위만 |

## 수정본 검증과 다음 시험

수정코드2cfcf7e의Native/legacy/Supervisor/Wheel은Workspace2회+Export SHA재현일치.
새Root service.py SHA `79fd55fd5b8dc6eafa887372eb02607aae23cd960bbd35f9b155ae70d976c4e8`.
새Wheel SHA `78e5f32833ae5c7fbbae103f32b1bd9ccd383648d253ae885557fc7ae0fb92d4`.
실제설치본은교체하지않았다. Workspace/Export전체관련회귀는진행중이며완료후추가한다.
사용자가수정본의실제통합시험을새로허용했다. 별도새Session/Manifest/Binding과직접Scope/R1/sudo가
필요하며이번소비영수증을재사용하지않는다. 600초/모델16회작업별확인/API2회$0.05의기존제한을
임의확대하지않는다. 실패시자동재실행하지않고최초오류와Cleanup을다시독립보존한다.
