# 최종 검증·Heartbeat 진단 보강·보존 결과

## 1. 변경 범위

기준 HEAD `253dc0c`, Source672개. 새 범용 Orchestrator·모델·승인·예산 시스템을 만들지 않았다. 기존 `stream_helper.run`의 diagnostic mode에 완료된 loop의 시작/인터페이스 검사/select 완료/패킷 처리/Counter sample 완료 timestamp를 추가했다. `TransportTrace.completed_loop`는 optional typed frozen record이며 순서 역전을 거부한다. 생성·이전 send 시작/완료·수신·관측 시각과 함께 다음 실패의 구간을 좁힐 수 있다.

이는 실제 Helper 송신 공백 원인을 해결했다고 주장하는 수정이 아니다. Elapsed stage에는 descheduling이 포함되고, 마지막 완료 loop 이전/이후나 STOP 중간의 미완료 작업은 여전히 UNKNOWN일 수 있다. 2초 Helper·5초 Control·socket timeout0.5초·8192B metadata limit·Counter/Namespace/권한/Replay gate는 바꾸지 않았다. 메타데이터가 늘어나는 만큼 실제 제한 환경의 overhead 검증은 다음 승인 시험 대상이다.

변경 파일은 Helper/Transport2개·관련 SHA manifest3개·기존 Helper 테스트1개다. 정상 lifecycle·마지막 CLOSED timing 보존·30ms identity 지연·역전 clock 거부를 추가했다. 기존 assertion을 삭제하거나 완화하지 않았다. Manifest 갱신은 새 source identity 기록이며 Root 설치·실행 승인 발급이 아니다.

## 2. 테스트 실행 이력과 실패 보존

공통 Git 증거 디렉터리:
`technical-report-validation-20261102T081212Z/`.

- 초기 집중 Helper/diagnostics:34 PASS. 오래된 pytest garbage cleanup warning은 별도 환경 경고이며 사용자 자료를 삭제하지 않았다.
- 초기 Workspace/Export broad:각939 PASS 뒤 TOTAL_HELPER_BUNDLE_MISMATCH1 FAIL. 새 Helper source의 SHA가 기존 manifest와 달라 정상적으로 차단됐다. 관련 manifest3개를 정확히 갱신했다.
- 추가 집중 첫 실행:동일 basename module collection충돌5 ERROR. 소스를 바꾸지 않고 기존 broad와 동일한 `--import-mode=importlib`로 교정했다.
- 다음 집중:241 PASS/27 FAIL. 고정 연구 의존성 root 설정을 빠뜨려 STREAM_ARTIFACT_ENVIRONMENT_BLOCKED가발생했다. 기존 명시적 `SOC_RESEARCH_VALIDATION_REPOSITORY` 설정으로교정했다.
- 명시적 root 설정 집중:268 PASS,47.58초. 이 suite는 Streaming/DNS diagnostics/Direction이며 실제 Capture·DNS traffic·API가아니다.
- Ruff B905의 explicit strict인자를수정하고새 source snapshot/manifest를동결했다. source변경중의초기·중간 broad 실행은취소해PASS에포함하지않는다.
- 최종 Workspace/Export broad는 `r3/`의명령·원본로그·JSON결과를기준으로기록한다. 아래 최종 결과가이전 실행을대체하는것이지실패기록을삭제하는것은아니다.

추가 최종 broad의 Workspace에서는900 PASS 뒤 `test_waiting_planner_does_not_block_collector_delivery`의5초진입대기가Timeout됐다. 같은source의Export는1453 PASS/1 SKIP을완료했다. Workspace실패후snapshot은STOPPED/cleanupVERIFIED/last_error없음/제외event13을기록했고,부하를분리한동일테스트는2.49초에PASS했다. 이자료만으로정확한I/O·스케줄링원인을확정하지않는다. assertion이나5초조건을바꾸지않고전체 Workspace를 단독 재실행했고1453 PASS/1 SKIP으로 통과했다.

## 3. 최종 결과

| 검증 | 최종 결과 |
|---|---|
|Workspace 전체 관련 회귀|1453 PASS /1 SKIP,455.01초; 단독 실행|
|독립 Export 동일 회귀|1453 PASS /1 SKIP,616.17초|
|최종 Helper/Heartbeat 집중|34 PASS,6.90초|
|Streaming/Direction 집중|268 PASS,47.58초(전체 회귀와 겹침)|
|실제 Tk Continuous/Flow|Workspace5 PASS/33.63초,Export5 PASS/34.58초|
|Ruff Check/Format·Diff|PASS,Source/테스트 기대값 완화 없음|
|Source 안정성|최종 Workspace/Export 실행 전후 Source SHA 동일|

SKIP1은 `test_idle_budget.py:138`의 기존 retained-session 명시적 opt-in 검사다. 실제 권한 검사를 임의 활성화하거나 skip을 새로 추가하지 않았다. 각 suite는 서로 중복하므로 PASS 수를 합산하지 않는다. 최초 병렬 Workspace의5초 Planner 진입 Timeout은 실패로 남기고, 단독 PASS만으로 그 순간의 정확한 스케줄링/I/O 원인을 해결했다고 주장하지 않는다.

## 4. 재현 빌드

`r3/reproducible-builds.json`: Native Continuous6개, 기존 Native compile산출물, Supervisor image2개를 Workspace2회/독립Export에서각각SHA동일확인했다. Supervisor는guarded preview만수행했고활성화하지않았다. BTF는 userspace parse/파일 build 검증이며 실제 Kernel load가아니다.

Wheel3회SHA동일:
`6bd6b787a04ec69dedca968b337ac70b1cc5949fcce25973fea3d54f8392e209`.

실제 Root 설치·TCX attach·DNS traffic·Native Model Action·외부 API·영수증소비·실행예약은0회다. 회귀에는기존 격리 OFFLINE/FIXTURE 모델Worker가포함되며새Live결과로보고하지않는다.

## 5. 보존·설치·모델 정합성

일반 사용자 읽기만으로 직전 설치 대상8경로 SHA가실행manifest의new_sha와일치함을확인했다. preserve_and_verify85개도전부일치했다. Root전용backup경로는PermissionError로현재읽기검증하지못했다. 기존백업의과거검증을새검증으로표현하지않으며권한을올리지않았다.

기존Ledger81행/SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`를유지한다. 기존PENDING2/POISON1원본을처리·삭제하지않았다. 최신실패119핀·이전성공113핀·기존보존묶음194핀은모두SHA일치다. 서로중복할수있는묶음이므로단순합산해고유파일수로보고하지않는다. 기존Native성공/실패의별도증거는각각본래Session그대로다.

모델·Scaler·작은Feature계약9항목의바이트SHA는모두일치했다. [검증원장](Model_Artifact_Verification.json)은역직렬화없는검사다. ML작업트리기존변경목록도동일하다. [Evidence Manifest](Evidence_Manifest.json)에읽은원본과과거/최종sourceSHA를구분했다.

기존Root Manifest는과거동결Helper를가리키므로이번후보의실행권한을증명하지못한다. 현재수정본을과거승인으로설치하면안된다. 새helper/wheel/source정합성과새정책·session binding은실제시험직전에기존CLI로다시확정해야한다.

## 6. 다음 실제 시험의 최소 조건

이 절은 시험 제안이며 실행승인이 아니다. 우선 짧은 제한 Native 진단1회를 검토한다. 기존Target `net:[4026532232]`·lo/Ingress, 전체600초내/수집5~7분후정상종료를제안하고현재Launcher가전체Deadline을보장하는지새Binding으로확인한다. 제안트래픽은기존localTCP최대4연결과dnsmasqUDP2/TCP1이다. 정확한주소·포트·payload·간격은새검토서에서기존고정구현과대조해야한다.

자원은Collector128MiB/CPU25%,Runtime512MiB/CPU50%,Queue32와기존Helper/DNS/Storage상한을유지하는것을전제로한다. 실제Scope·변경Root경로·백업·정책기간·R1은새검토서에고정해야하며이문서만으로실행하지않는다.

필수관측은helper완료loop구간/생성·송신·수신/observer시각/CPUcounter/IPC,Control/DataProgress,Window/Attestation,QueueDrop·SourceGap,TCXACK/HelperCLOSED·counter·ACK/Root·Runtimecleanup이다. GUI재연결이수집기를중단하지않는지도같은Session에서검증한다. 실패하면최초오류와cleanup후속오류를분리하고자동재실행하지않는다.

RF/LR은실제봉인ELIGIBLE작업별Action승인후에만수행한다. APIAssessment는기존Provider/모델/가격·호출횟수·cost/token/timeout·usage미수신UNKNOWN계약을별도검토한다. DNS9/HostAuth는필요한입력·권한계약없이어떤값도합성하지않는다. 짧은시험성공만으로20분/1시간검증을완료했다고보고하지않는다.

## 7. 상태 판정

보고서·모델분석·오케스트레이션문서·발표원본의완료여부와Native운영판정을독립적으로기록한다. 최신Helper송신gap원인은UNKNOWN이며20분/1시간Native운영미완료다. 새진단의비권한회귀가통과해도실제Native문제해소판정은부여하지않는다.

## 8. 최종 독립 판정

- TECHNICAL_REPORT_COMPLETE: 필수7문서·세부근거·실험/한계 정리 완료.
- MODEL_ANALYSIS_VERIFIED: 실제소스·저장결과·9개SHA의분석을검증했다. DNS학습의미/HostLive모델검증까지완료했다는뜻이아니다.
- ORCHESTRATION_DOCUMENTED: 실제core재사용·호출/claim/revision/priority/recovery/AI와규칙경계문서화.
- RELIABILITY_INTEGRATED: **PARTIALLY_VERIFIED**. 비권한진단통합·회귀·빌드는통과했으나실제Helper송신gap원인은UNKNOWN이다. 이라벨을완전한안정성해결로부여하지않는다.
- NATIVE_OPERATIONS_PARTIALLY_VERIFIED: 제한E2E성공은보존,20분/1시간전체운영은미완료.
- PRESENTATION_READY:29장구성/대본초안·49개Q&A·실제그림근거준비. 실제PPT/PDF제작·현재Live데모완료를뜻하지않는다.

## 9. Git·문서 검증 기록

코드 Commit `1fcbff2` (변경6파일). 조사기준253dc0c와실제실행HEAD들은별도로기록했다. Native/Supervisor/Wheel빌드는이Commit과내용이같은동결source로검증했다. 이문서군을포함하는후속Commit이문서Commit이며최종응답에정확한HEAD/Push결과를보고한다. 문서에는Mermaid10개·발표29장·Q&A49개·실제보존Screenshot3개·실제수치SVG2개와출처원장을포함한다.
