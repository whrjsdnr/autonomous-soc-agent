# TCX Producer Timeout·Runtime Cleanup 안정화

2026-10-30. 운영 코드 `68209cf52a663c1f824e5f8d88deb2b4a9af05cf`,
Tree `1e94fd6544a9437de491cf7bba382ac2cb7c17a6`.
이 작업은 비권한 복구 개발이다. Root 설치·sudo·Namespace 진입·TCX 부착·Packet/DNS Live·
모델 Action·외부 API·예약·영수증 소비를 수행하지 않았다.
과거 시험의 PARTIALLY_VERIFIED 및 Cleanup/원인 UNKNOWN은 그대로다.

## 증거 기반 RCA

기준 보고서는 `packet-dns-cleanup-final-retest-result.md`다. 보존된 실제 시험은
Native24건·DNS3거래, Root 전체93.187초, Runtime Seal0개·ELIGIBLE0개였다.

| 단계 | 관측·판정 |
|---|---|
| Kernel → Collector | Load·Attach·READY 성공, Native metadata24건 확보 |
| Root 진행 | Audit Heartbeat 04:41:42.633102016Z → 04:41:47.887047871Z, **5.253945855초 공백** |
| IPC → Receiver | 마지막 인증 envelope Unix1793335302.6358576, sequence69, generation676800991435621 |
| Receiver 실패 | 기존5초 계약 위반, 관측 age5.254290초, 최초 `CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT` |
| Queue | TCX handoff/Runtime Queue drop0. Native24건은 Feature 작업 Queue가 아닌 미봉인 Capture Window에 대기 |
| Window | Root 로컬 Seal1, Runtime 수신0. 로컬 Seal만으로 적격성을 주장할 수 없음 |
| 후속 오류 | 외부 `RUNTIME_HEARTBEAT_STALE`, Runtime `CONTINUOUS_NATIVE_COLLECTOR_EARLY_EXIT`, TCP 취소 |
| 종료 | Runtime2·Root2·바깥 CLI1. Helper 소유 Cleanup VERIFIED, TCX ACK 미수신·Runtime Cleanup UNVERIFIED |

**정확한 Root syscall·CPU scheduling·I/O 지연 원인은 UNKNOWN**이다. 시간 상관만으로
Producer 정지·DNS 실패·CPU throttling·Queue 포화를 원인으로 확정하지 않았다.

확인된 운영 코드 결함은 다음과 같다.

1. `TCXProducer.events()`가 수신 실패 시 즉시 소켓을 닫았다. 동일 채널로 STOP·Seal·ACK를
   수집할 수 없어 Root 물리 자원 정리와 별개로 Runtime의 종료 증거가 누락됐다.
2. Native `observe()`의 ingress 영속 저장 `retain` 및 적용 완료 `applied`가 기존 비동기
   저장 래퍼를 거치지 않았다. 느린 SQLite/fsync가 수신 이벤트 루프를 막을 수 있다.
   비권한 장애 주입으로 이 코드 결함을 검증했지만, 과거5.254초 공백의 직접 원인이라는
   증거는 없으므로 역사적 RCA와 구분한다.
3. Replay 재시도 설정의 기본값이 Native 수집 루프에도 적용될 수 있었다. 같은 Producer
   객체를 다시 열며 최초 ACK/상태를 초기화하는 잠재 경로였다. 과거 실패의 실제 재시도
   원인으로 확정하지 않으며, Native에는 자동 재연결을 허용하지 않는다.
4. 배치의 첫 프레임을 영속 처리하는 동안 background receiver가 실패하면 같은 배치의
   나머지 프레임이 뒤늦게 전달될 수 있었다. 실패 이후 배치 tail도 입장을 차단해야 한다.

## 수정한 운영 경로

`continuous/tcx_producer.py`:

- 기존 **5초 envelope 생존 제한 유지**. 패킷이 없어도 정상 control heartbeat가 도착하면
  실패하지 않는다. Peer 생존은 IPC 진행·Capture Integrity를 대신하지 않는다.
- wall timestamp와 monotonic 수신 경과 시간을 별도 기록한다. 마지막 envelope·검증 완료·
  데이터 수신, Root clock sample, PID/start ticks, IPC 연결, handoff Queue/drop을 보존한다.
  PID 정보가 없으면 UNKNOWN/UNOBSERVABLE이며 프로세스 종료 코드를 만들어내지 않는다.
- 수신 reader를 종료·join한 후, 동일 인증 채널에서 **단 한 번의 bounded STOP 교환**을
  수행한다. 전체 종료 drain5초, 기존 send2초, 메시지·Seal 수 제한을 적용한다.
  reconnect·Collector restart·수신 timeout 연장은 하지 않는다.
- 정상/종료 reader는 동일 envelope 및 sequence·epoch·counter·clock·Seal·ACK validator를
  재사용한다. 대기 중인 envelope를 먼저 확인해 관측된 회전 generation을 존중한다.
- 실패 후 배치 tail·늦은 패킷은 격리하고, 검증된 Seal은 **진단 증거**로만 보관한다.
  Runtime 입력·Feature·모델 Queue로 전달하지 않는다. 과거 정상 Window도 소급 변경하지 않는다.
- ACK 누락·위조·Scope/세대/SHA 불일치·drain 취소는 UNVERIFIED다. 최초 오류와
  종료 중 후속 오류·함수/행번호를 독립 기록한다. 취소돼도 소유 소켓을 finally에서 닫는다.
- Producer 객체 재사용을 거부한다. 이미 검증된 ACK는 소켓 종료 후에도 그 Binding으로만 조회한다.

`continuous/service.py`:

- Native ingress `retain`/`applied`도 기존 직렬화된 비동기 저장 경로로 보낸다.
  writer를 취소 시 join하는 계약·원래 DB 검증·commit/fsync는 유지한다. Replay 동작은 유지한다.
- Native retry0 강제. Replay 설정은 Native 재연결 권한이 될 수 없다.
- 종료 drain 중에도 최초 source failure를 DEGRADED/last_error로 표시하며 Live 수집을 주장하지 않는다.
- 바깥 EARLY_EXIT가 최초 source 코드를 가리지 않게 한다.
- 기존 Audit에 `CONTINUOUS_TCX_CLEANUP_EVIDENCE`로 ACK·진단 Seal·격리 계수·종료 상태를
  저장한다. 후속 오류는 type뿐 아니라 code도 보존한다.
- 실패한 Capture의 적격성과 자원 Cleanup을 분리한다. ACK/소켓/reader/flush가 검증돼도
  미봉인·불완전 Window를 VERIFIED/ELIGIBLE로 바꾸지 않는다.

`gui/continuous_view.py`: 실제 Backend의 TCX STOP ACK·Cleanup 증거 상태·진단 Seal 수를
표시한다. 진단 Seal이 추론 권한이 아니라는 점을 명시한다. 기존 Native/Replay 구분을 유지한다.

## 비권한 검증

새 `test_tcx_failure_cleanup.py`는 실제 AF_UNIX/SOCK_SEQPACKET 및 운영 `events()`·
`observe()`·`run()`·CLI 자식 프로세스를 사용한다. Root 권한/설치 endpoint만 모의한다.
별도 fault injection은 IPC timeout·영속 쓰기 지연·취소로 한정한다.

- 실제5초 receive timeout → 동일 채널 STOP → 지연 Seal/ACK → FD 종료.
- 무트래픽5초 이상 + 지속 heartbeat는 정상이며 패킷을 생성하지 않는다.
- wall clock 이동과 monotonic liveness를 구분한다.
- namespace/policy/generation ACK 위조, sequence gap, counter 오류, Seal digest 오류 차단.
- 실제 Peer 종료, ACK 누락·5초 bounded 종료, 중간 취소·partial Window·소켓 종료.
- background timeout 이후 동일 배치 tail 입장 차단.
- 실제 Native ingress `retain`/`applied` 지연 중 수신이 계속되고 writer를 안전하게 마치는지 확인.
- 운영 Runtime에서 Audit·Queue·Window 상태 확인. 늦은 Seal이 Feature Queue에 들어가지 않음.
- 실제 CLI 자식의 **Exit2·최초 Timeout**을 유지하면서 ACK·Cleanup 증거 저장을 확인.
- 실제 Tk/Backend 재연결 후 오류·ACK·진단 Seal·Capture UNKNOWN 구분을 확인.
- 기존 실제 Unix STOP/epoch rotation 테스트의 Root mock PID만 현재 프로세스 PID로 보완했다.
  새 start-identity 관측에 맞춘 권한 경계 Fixture 수정이며 기존 assertion은 유지했다.

집중 회귀22 PASS, 기존 STOP·회전 회귀4 PASS. 최종 Workspace·Export·GUI 결과는
아래 완료 기록과 `.git/tcx-timeout-stabilization-20261030T050100Z/final/` 로그를 기준으로 한다.
이전 개발 중 변경된 Source를 감지한 SOURCE_CHANGED_DURING_BUILD 거부와 중단 로그도 보존했다.
최종 회귀는 확정 Commit의 변경 없는 Source 및 독립 Git Export에서 수행한다.

## 재현 빌드·무결성

- Source archive SHA256: `fc1f2b642a985dad47ca40a3345b1f9d5cfadd67f96d4d0351315fae1ba4bab8`.
- Wheel SHA256: `b7f0504cecce4388fdee8d3699a554daa80213de20c19f7791d02ef115838ed6`.
- Workspace·독립 Export 이중 Wheel build 일치.
- Native6개 이중 build 모두 일치. BTF는 libbpf userspace open/parse만 수행했다.
  Kernel load는 수행하지 않았다. Native6개 SHA는 기존 성공본과 동일하다.
- 세부 Git/Tree/Native6개 SHA는 `final/artifact-identity.json`에 있다.
  이것은 **GUARDED·미설치 개발 Artifact**이며 실행 승인 영수증이 아니다.

기존 trial84개 파일 및 기존 Ledger·설치 설정을 SHA pin으로 보존하고 종료 시 재검증한다.
Ledger81행·SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`.
과거 사용량·영수증·Root Audit·Rollback·SQLite 증거를 갱신하지 않는다.

## 다음 제한 시험의 최소 조건

1. 이 Source/Wheel을 기존 CLI의 자동 무결성 경로로 포함하고, 새 Source·Artifact·Session·
   Root Manifest·Namespace·최신 Ledger Binding을 확정한다. Root6개 내용이 같아도 과거
   소비된 실행 승인이나 R1을 변경 Artifact에 자동 승계하지 않는다.
2. 기존 전용 Namespace `net:[4026532232]`, lo/Ingress, 고정 로컬 TCP/DNS Scope와
   기존 자원 제한으로 새로운 R1·Root 진입/필요 설치·Native Capture·트래픽 승인을 검증한다.
   DNS UDP2/TCP1, TCP 최대38, 전체3600초 등은 새 검토서에 정확히 결합된 경우에만 사용한다.
3. 유효기간·Scope yes·사용자 직접 sudo 인증·Namespace 내부 check PASS 후 최대1회 실행한다.
   이번 작업은 실행 예약이나 인증 대기 터미널을 만들지 않았다.
4. 최초 오류·동일 채널 STOP 요청·ACK·진단/정상 Seal 구분·Queue/Audit drain·소유 자원
   Cleanup을 독립적으로 수집한다. ACK가 없으면 UNVERIFIED로 종료하며 자동 재실행하지 않는다.
5. 실제 ELIGIBLE Window의 모델 Action은 별도 승인이다. DNS9·외부 LLM API는 포함하지 않는다.

기존 읽기 전용 Cleanup 검사나 승인 프레임워크 개발을 반복하지 않는다.
**비권한 수정/검증과 실제 Live 성공은 구분한다.** Root Heartbeat 공백의 역사적 원인은 UNKNOWN,
기존 TCX ACK 미수신·Runtime Cleanup UNVERIFIED는 그대로이며 새 Native 운영 성공을 주장하지 않는다.

## 최종 완료 기록

- Workspace·독립 Export 각각 **고유1172건 검증 완료**, 미해결 테스트 실패0.
  단일 전체 회귀는1158 PASS/14 FAIL이었고,14건은 위 운영 수정과 무관한 기존 Fixture 문제였다.
  수정 후 동일 선택 집합의 `--lf` 회귀에서 **14/14 PASS**를 각각 확인했다.
  통과했던1158건을 불필요하게 반복하지 않았으며 초기 실패 로그도 보존했다.
- 추가 확인: 전체 Loader 진단24 PASS, SourceGuard 조립4 PASS, 실제 Tk4 PASS,
  Export의 TCX 오류/ACK 재연결1 PASS, 집중22 PASS·기존 프로토콜4 PASS.
- 추가 Fixture 수정은 테스트 파일2개뿐이다. C mock counter의 observed를 outcome 합계27로
  맞추고, 실제 broker가 설정하는 started_ns를 채웠다. `_prepare` mock은 기존 recovery/
  namespace_build 인자를 명시적으로 받고 None을 검증한다. 운영 parser·인자·보안 gate·
  기존 assertion은 변경하지 않았다. 수정 전후 SHA/patch는 `final/validation-fixture-corrections.*`에 있다.
- Ruff 전체 PASS, Format1523개 파일 PASS, git diff --check PASS.
- 5,000건 격리 Replay도 두 환경에서 통과했다. 가상 이벤트 시간이며 실제 Kernel 운영 시험이 아니다.
- Native6개·Wheel 재현 SHA 일치. Wheel의 Python619개 파일도 운영 Source와 직접 대조했다.
- 기존 증거·Ledger·설치 설정 **88개 SHA 모두 일치**, 기존 Ledger81행 유지.
- 운영 Source68209cf와 별도의 Fixture/보고서 Commit으로 결과를 기록한다.
  실제 Native 재시험·정책 활성화·설치·승인 소비는 수행하지 않았다.

최종 개발 판정은 **비권한 복구·검증 완료 / LIVE 재검증 대기**다.
과거 실환경 PARTIALLY_VERIFIED를 OPERATIONS_VERIFIED로 변경하지 않는다.
