# 개발 타임라인·기술적 의사결정·RCA

## 1. 이력 복원 방법

`git log --reverse`, 해당 Commit source diff, 당시보고서와현재실행원본을비교했다. 아래는대표적인전환점이며모든Commit목록이아니다. 초기기획의의도는AGENTS/당시문서에근거하고, 기록없는대안비교는사후설계분석이다. `git show 7de4794:docs/linux-soc-v1/native-ai-orchestration-e2e-report.md`처럼현재문서가사전준비서술로바뀐경우에도역사blob을읽었다. [E01/E11](Evidence_Index.md#e01)

## 2. 시간순 주요 전환

|시기·Commit|기존문제|설계판단·구현|검증과한계|
|---|---|---|---|
|09-14 d1a2fba/a8796c4|보안chat과사건상태혼재|ExplicitIncident/Evidence모델|Foundation소스/테스트|
|09-14 03169aa/3e5ec99|LLM/Tool직접결합|Provider독립LLM·secureToolRegistry|Mockable경계|
|09-14 865bfa9/2c59547|추천과집행혼재|Policy·HumanApproval·governedexecutor|권한우회차단|
|09-14 539efcf/f0920a7/1f25649|탐지후조사단절|Orchestrator·LLMPlanner·Assessor|단일조사Workflow|
|09-15 a49e4ca/5ba8ea1|모델/도구선택과추가조사|SecurityAISelector·AdaptivePlanner|모델선택도권한경계유지|
|09-16 fcaff81/b3f18b2|무한루프·근거없는feature|Boundedloop·provenancefeatures|stop조건·schema|
|09-17 eed10ae|계정행동분석|AuthenticationIF·집계|HostLive성공과별개|
|09-22 a9f4f71/b9f8990|여러모델결과불일치|deterministicfusion·fusionawareassessment|RF/LR분석은침해확정아님|
|09-23 42a0007|중단후상태손실|persistentgovernance|claim/checkpoint/audit|
|10-15 ML연구기록|Top40와실시간입력불일치|Network14producer·CTU연구RF/LR|검증selectedsubset·분포이동한계|
|10-29 36c2ecc|BTF누락|clangdebugBTF·userspaceparse·재현build|Kernelverifier별도|
|10-29 072f58b|BPFVerifier 거부·errno손실|파싱/종료진단최소수정|새승인후Kernel시험|
|10-29 e3412e8|실제모델입력까지미연결|Nativeattestation→RF/LR→Incident|20packet/2prediction제한E2E|
|10-30 143c1e6|Continuous분석과조사core분리|기존Application/SOCRuntime연결|Workspace/Export·복구테스트|
|10-30 c542398/7a1b6f3기준실행|Native조사전체미검증|정확한봉인작업Action·SCRIPTED조사|54packet/8prediction/2incident/ownedcleanup|
|10-30 71377c7|정확한modeladmission후worker표시|4줄상태보정+회귀|앞선실행에소급적용안함|
|10-30 66814fc/970c43a|1시간/API/실패상태불확실|시간계약·CLIexecuted불확실성보존|실제Plan성공·AssessmentTimeout·18분Native|
|11-02 568e759/43b2042|Control/조사/저장/종료결합|독립Control·외부호출불확실성|offlineReliability통합;Native별도|
|11-02 c6405d7/fd53942|Heartbeat·저장경합|controlpublication·dataprogress격리|20분wallReplay성공,Native20실패|
|11-02 5e70da8/a2914a0|Reader/Consumer경합·CLOSEDstale|queuedcontrol재검사·PID/clock/IPCdiagnostics|6분실제진단성공,장시간미완료|
|11-02 260e760|Control에서DNSsnapshot대기|DNSread를기존storageworker로이동|아직SQL순서뒤에대기한계|
|11-02 db5e8dc|독립DNSfreshness실패·빈DNSchart|전용observer/readlock·실제counter투영|1449회귀·후속Native91.81s실패|
|11-02 ac33af8/253dc0c|반복STOP이CLOSED덮음|terminalstate불변/원본증거보존|집중42회귀;남은송신gapUNKNOWN|
|이번보고서변경|Helperloop어디서공백인지불명|기존transporttrace에typedstage경계|offline검증만;실제원인해소주장안함|

## 3. BTF 누락과 Kernel Verifier

**상황/증상:** Collector exit1, libbpf가 BTF required/missing을보고했다. BPF `.maps`선언과builder `-g0`가충돌해Object에필요한BTF가없었다. **직접원인:** 빌드옵션/Artifact정합성. **수정:** BTF를남기고prefixmap으로재현경로를정규화;section·libbpf파일open/parse회귀. **검증:** userspaceparse와실제load를분리해다음시험에서BTF오류해소를확인했다. [Continuous보고](../linux-soc-v1/continuous-runtime-integration-report.md)

BTF를 보존하는 수정은 BPF Object 빌드의 debug 정보에 적용했고, 다른 User Space C 빌드의 `-g0`까지 일괄 제거한 것으로 서술하지 않는다.

그다음Verifier오류는별개였다. 코드/포인터접근을verifier허용형태로고치고NativeC실패errno가cleanup중무조건EPERM으로덮이던결함을수정했다. Kernel오류텍스트·최초errno·실제자식종료코드를보존했고HostC harness는실제load를대체하지않았다. BTFparse성공을TCX성공으로과장하면이단계를놓친다.

## 4. PHASE_D_COLLECTOR_SCOPE_MISMATCH

**상황:** Host에서Non-consumingcheck를수행했을때Targetnamespace/collectorbinding과다르면차단된다. 이것은일부문맥에서의도된보안차단이며“에러코드가있으니삭제”할대상이아니다. **해결원칙:** Host와Target을정확히표시하고기존controller승인·Namespace진입후검사해야한다. **검증근거:** [Final통합보고](../linux-soc-v1/final-soc-agent-integration-report.md). 잘못된Scope의check를PASS로바꾸는수정은하지않는다.

## 5. DNS Helper UID EPERM

**상황/증상:** RootLauncher에서Helper로전달한UID/GID권한전환이EPERM으로실패했다. **직접원인:** bootstrap의권한전달계약불일치. **수정/재시험:** 승인된UID/GID1000·supplementarygroups없음·capabilitydrop·NNP1계약을실제두시험에서확인했다. RootHelper로계속실행해우회하지않았다. **검증:** [운영보고](../linux-soc-v1/soc-agent-operations-verification-report.md)의수정목록. 모든capability가모든시점0였다는서술은부정확하다. rawsocket개설시의제한된cap와개설후제거를구분한다.

## 6. Producer Receive Timeout

**상황:** Kernel/Collector카운터는증가했는데RuntimeWindow가0인시험이있었다. dataevent침묵과control생존을하나로판단하거나수신과영속write를같은loop에두면어느구간이정지했는지불명확하다. **수정:** 수신/영속쓰기분리, monotonicdeadline, processidentity/IPC/마지막성공수신·latency진단, control우선처리, 실패STOP/ACK/diagnosticseal경로. **UNKNOWN:** 실제과거의어느syscall/scheduling이공백을만들었는지는로그만으로확정못했다. [Timeout보고](../linux-soc-v1/tcx-producer-timeout-cleanup-report.md)

**회귀:** 무트래픽/지연/queuefull/producerexit/STOPACK누락을구분해테스트했다. 후속실환경에서Window생성은확인됐지만1시간시험1080.335초후ReceiveTimeout이재발했다. 따라서“코드수정후모든NativeTimeout영구해결”은거짓이다.

## 7. Runtime Heartbeat·SQLite·Data Progress

**상황:** 1시간목표시험이193.593초검증수집후RUNTIME_HEARTBEAT_STALE, age약8.45초로실패했다. 저장·상태게시·읽기·observer를분리해서분석해야한다. **확인결함:** 긴SQLite/fsync작업이controlpublication또는DNSstatusrefresh순서를막을수있었다. **수정:** controlpublication·serializeddatastorage·DNSstatusobserver분리;processidentity/monotonicstamp;data-progress별도검사. **경계:** Heartbeat만살리고data가멈추면DEGRADED이어야한다. [E14/E16](Evidence_Index.md#e14)

Replay에서는stage완료가있는데전체observationlifetime만으로정체를판정하던오류도발견했다. lastactualsame-taskprogress로정의하고실패했던soak원본을보존했다. 최종1200초Replay성공은slowwrite/control독립에대한offline근거이며Kernelload/cgroup/Helper송신스케줄링을증명하지않는다.

## 8. Helper Heartbeat 경합과 남은 송신 공백

**확인된경합:** consumer가cachedheartbeatage만보고실패하기전에이미socket에있던authenticatedcontrol을검증해서읽지않는경우가있었다. **수정:** 빈poll뒤재스케줄링과consumer상황에서boundedcontrol재검사, CLOSED이후stale차단방지, packet/counteradmission보존. **회귀:** queuedheartbeat/emptyIPC/forgedidentity/backlog/closed/clock반례를검증했다. 2초Helper/5초Control상한은유지했다.

**후속6분실환경:** control최대1.108초/54packet/3DNS/모든ownedcleanup성공. **최신반례:** 후속91.81초trial은socketempty·이전송신후4.181초gap을보였다. 따라서초기reader경합수정은유효해도최신sendergap의완전한해결책은아니다. **UNKNOWN:** interfaceidentity/sysfs/proc읽기·packetparse·countergetsockopt·CPUdeschedule중정확한원인. **이번최소보강:** 완료loop단계timestamp를기존trace에추가했다. elapsed에는대기/스케줄링이포함되므로단계가길어도CPUburn이라고단정하지않는다.

## 9. STOP ACK·Helper Cleanup·GUI terminal state

ACK/CLOSED와실제Helperexit·socketclose·threadjoin·durableaudit완료는독립증거다. 기존에는STOPACK시간을전체helper수명과혼동하거나CLOSEDauditcommit을기다리지않아UNVERIFIED가남을수있었다. 5b14a67은cleanupcommitjoin/STOPACKphase를분리했다. rootownedcleanup과runtimecleanup도별도로유지했다. [Lifecycle보고](../linux-soc-v1/dns-helper-lifecycle-cleanup-report.md)

최신failed-stop이후중복request_stop이CLOSED를STOPPING으로덮는표시결함은ac33af8에서종료event를먼저확인하도록수정했다. wireCLOSED와진짜resourcecleanup은이미증거가있었지만GUIstate가잘못됐다. 수정은새코드회귀이며과거화면·원본Session상태를덮어써성공처럼만들지않았다.

## 10. Root Installer Scope·외부 준비 스크립트

Root고정8경로중변경5/검증3등계약을installer가정확히따라야한다. 승인되지않은파일을복사하거나verify-only파일inode/mtime을바꾸면binding위반이다. 이문제는새scopecandidate와읽기전후SHA검증으로정리했다. 새정책활성화도source/manifest를바꾸면최종binding을다시대조한다.

후속외부time-rebinder는숫자420(0644mode)까지시간숫자로잘못치환해1560을만들었고설치mode03010/PermissionError로Capture전실패했다. 원인은제품모델이아니라준비스크립트의AST범위오류였다. mode값보존·명시적fchmod0644와별도새scope복구를검증했다. 반복에따른실패도예산·증거에서삭제하지않는다.

## 11. LLM Assessment Timeout·비용 UNKNOWN

Plan은실제응답했지만Assessment는20초timeout이다. provider가원격으로처리했는지/어떤요금이청구됐는지모른다. HTTPtimeout·구조화출력·payload·tokenbudget·requestcancellation을구분해야한다. 기존코드는plan/assessment독립checkpoint, reserved/confirmedcost, usage누락UNKNOWN, uncertainexternalstep자동retry차단을보강했다. 실제API재검증없이성공으로바꾸지않고로컬LLM설치·모델자동변경으로우회하지않았다. [E10](Evidence_Index.md#e10)

## 12. 왜 Native는 Replay보다 어려웠는가

Replay는저장source/deterministiceventtime·권한Mock·짧거나통제된IPC를이용한다. Native는Kernelhook/라이브socket/cgroupquota/OS스케줄링/권한전환/동시audit/GUI관측이함께작동한다. 실제wall시간의빈구간은eventtimeclock과다르고CPUquota는평균상한이지각threaddeadline보장이아니다. 이미통합테스트를통과했는데Native실패가발생하는이유를“테스트를안했다”또는“OS가느리다”한마디로끝낼수없다.

차기수정의핵심은더긴timeout이아니라정확한단계별측정·불확실성보존이다. 새진단code는새binding/승인을필요로하며이보고서의offline통과를새Native승인으로대체하지않는다. 다음순서는제한시험1회→증거판정→충분한수집/종료성공일때만장시간검토이며자동Root재실행은하지않는다.
