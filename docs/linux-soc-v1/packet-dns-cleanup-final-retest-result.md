# Packet·DNS Cleanup 최종 재시험 결과

2026-10-30. **PARTIALLY_VERIFIED / NATIVE_OPERATIONS_NOT_VERIFIED**.
승인 기준 문서 `142c69e`, 운영 Source `5b14a67`, Runtime Session
`f4147fc4-40e3-4a01-bc32-267f4f58ed88`, DNS Session
`bf76008d-6899-48d7-a4bb-7563b816d1d6`, Release0.6.3.

사용자 직접 Scope/R1 확인·sudo 인증 후 정확한 승인 Artifact로 Native 시험1회를 수행했다.
모델 Action·외부 API·DNS9는 실행하지 않았다. 실패 후 자동 재실행·추가 Root 조회도 하지 않았다.
이번 Session과 실행 승인은 소비됐으며 재사용할 수 없다.

## 실제 결과

| 항목 | 결과 |
|---|---|
| Root 전체 실행 | **93.187초**, 승인3600초 이내이나 장시간 시험 미달 |
| Collector 서비스 시작→정산 | **89.152초**, 순수 Capture 시간과 구분 |
| ATTACH_OWNED→Root Seal Audit 간격 | **88.309초**. Kernel 경계 증거가 Runtime에 전달되지 않아 정밀 attested Capture 시간은 UNKNOWN |
| DNS Helper capture elapsed | CLOSED의 monotonic 측정 **70.109초** |
| Kernel Load·TCX Attach·READY | 성공 |
| Native metadata | **24건** |
| DNS 거래 | **UDP2·TCP1, NOERROR3개**, 고정 dnsmasq/Query SHA 일치 |
| DNS 입력 | Raw48프레임·metadata14개·Query3/Response3, capture drop0 |
| DNS raw parse_failures | 8: DNS payload 없는 TCP 제어 프레임 포함. 의미 분석 오류0과 구분 |
| TCP 공급원 | 1회 기동. 조기 중단으로 최종 완료 결과 없음, 완료 연결 수 UNKNOWN. 정리 시 SIGTERM15·systemctl job canceled1 |
| Window | Root 로컬 Seal1, Runtime 수신 Seal0·pending native24 |
| Capture Attestation | **UNKNOWN / WINDOW_NOT_SEALED**, 로컬 Seal 기록만으로 VERIFIED 처리하지 않음 |
| Network14 ELIGIBLE | **0개** |
| 모델 호출·Prediction·Incident·API | **각0**. 모델 Action 미승인, 부적격 입력 추론 없음 |
| Queue / Drop | 최종 Queue 비어 있음. Queue drop0·TCX handoff drop0·DNS capture drop0 |
| Runtime·Root 종료 | **Exit2 / Exit2**, 정상 운영 성공으로 처리하지 않음 |
| GUI | 실제 Native24·DNS3·Helper Cleanup VERIFIED·Runtime Cleanup UNVERIFIED·모델 없음·실제 오류 표시 확인 |

시험 시작·진행은 기존 CLI `soc-agent start --home <검토 profile> --gui` 경로를 사용했다.
원본 Root 기록·로그·종료코드·의사결정은 기반 검토서의 `review/execution/`에 있다.
새 분석·모니터링·GUI·회귀 결과는
`.git/packet-dns-cleanup-final-approved-20261030T043940Z/`에 보관했다.

## 최초 오류와 후속 오류

최초 Runtime 오류는 **ValueError:CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT**이다.

```text
service.py collect:628
→ tcx_producer.py events:276
→ messages:212 → receive:159
→ receive_message:242
→ 기존5초 Root envelope 수신 제한 초과
```

보존된 failure에는 generation676800991435621, last_sequence69,
last_message_unix1793335302.6358576, last_message_age5.254290초,
stage AUTHENTICATED_ROOT_RECEIVE와 capture_restarted=false가 있다.

같은 실행의 Root Audit heartbeat도 04:41:42.633102016Z 다음이
04:41:47.887047871Z로 **5.253945855초 간격**이다. 수신 timeout과 정합적인 지연이
관측됐지만, 어떤 syscall·CPU scheduling·I/O가 원인인지는 기록되지 않아 **UNKNOWN**이다.
이것을 DNS Helper 장애·Namespace 오류·BTF 문제·권한 실패로 바꾸지 않는다.
기존5초 제한을 늘리거나 검증을 우회하지 않았다.

외부 Root coordinator는 뒤이어 04:41:47.935274Z에 **RUNTIME_HEARTBEAT_STALE**을 기록했다.
Runtime journal의 CONTINUOUS_NATIVE_COLLECTOR_EARLY_EXIT와 TCP job canceled는
후속 종료 결과다. 이 오류들로 최초 TCX receive timeout을 덮어쓰지 않았다.

확인된 후속 경로는 `TCXProducer.events()`의 finally가 receive/messages를 닫고 소유 socket도
종료한다는 것이다. 이후 STOP ACK 수신 경로가 없고, `request_stop()`은 연결 없는 owner를
거부하므로 `remote_cleanup=UNKNOWN`이 남는다. Root 서비스의 실제 소유 자원 정리와
Runtime이 프로토콜 STOP ACK를 검증했다는 주장을 분리해야 한다.
이번 실행에서는 이 실패 경로를 보존했으며 운영 코드·Root 실행 파일을 수정/재설치하지 않았다.

## DNS Helper 종료 증거 — 이번 실행에서 VERIFIED

다음은 이번 정확한 DNS Session의 실제 증거이며 과거 실행에 소급 적용하지 않는다.

- `verified-ready.json`: Helper PID2858683·Start ticks67680939·Target Identity와 FD 소유권 검증.
  실제 UID/GID1000, effective/permitted/inheritable/ambient Capability0, NoNewPrivs1 유지.
- `verified-closed.json`: CLOSED, Counter sequence375, COUNTER_VERIFIED,
  kernel_packets_total/received_frames48, sent_packets14, capture_drops_total0.
  Session·Counter·전달14개를 검증했다. UID/GID·Capability 제거 상태도 재확인했다.
- STOP 요청 Unix1793335309.6357474, 인증된 CLOSED 수신1793335309.651856.
  DNS STOP ACK는 이 검증된 CLOSED이며 존재하지 않는 별도 ACK를 만들어내지 않았다.
- `cleanup.json`: authenticated_closed/stream_completion_verified=True, 원 PID identity
  EXITED_ZOMBIE 후 서비스 종료, listener/channel FD 종료·reader join·cleanup VERIFIED.
  Root 서비스 정산도 MainPID0·Result success·ExecMainStatus0이다.
- 파일·디렉터리 fsync 후 게시된 Cleanup SHA와 실제 파일 SHA가 일치한다:
  `7125a736792097d5507f6fb20eb2eee267e8259b7456c0ae5b113aff5e9eb192`.
  CLOSED의 model canonical digest도 receipt의 closed_sha256과 대조했다.

따라서 **이번 DNS Helper 소유 Capture/Transport Cleanup은 VERIFIED**다.
이는 이번 TCX·Runtime·전역 Kernel의 Cleanup을 증명하지 않는다.

## Cleanup 독립 판정

| 영역 | 이번 실행의 판정 |
|---|---|
| DNS Helper | **VERIFIED**, CLOSED·최종 Counter·STOP 응답·durable receipt·소유 FD/reader/프로세스 종료 |
| DNS 공급원/client | 완료 거래3개·client_fds_closed·child exit0·서비스 정산·Namespace socket 검사 확인 |
| TCX 프로토콜 STOP ACK | **UNVERIFIED**, Runtime에서 수신하지 못함. collector_cleanup/remote_cleanup UNKNOWN 유지 |
| Root 소유 물리 자원 | **VERIFIED 범위 한정**, Root Audit SERVICE_STOPPED cleanup VERIFIED, 서비스5개 MainPID0, 소유 Unix 경로 없음, 저장된 Target TCX/Socket 검사 PASS, Link/Map 없음 |
| Runtime 전체 | **UNVERIFIED**, Collector/Worker STOPPED와 별개로 TCX ACK가 누락됨 |
| Runtime Flush·Audit | **VERIFIED**, final_flush와 Audit19행·detail/state digest 확인 |
| 전역 Kernel·과거 Cleanup | **UNVERIFIED 유지**, 현재 BPF program ID 변화의 소유권·원인 단정 없음 |

Root 로컬 Seal은 Receiver가 종료된 뒤 발생했다. Runtime에는 Seal이 전달되지 않았으므로
Flow Completeness·Network14 적격성을 만들거나 모델에 입력하지 않았다.
과거 Program1145·Helper heartbeat UNKNOWN, FAILED·false·과거 Cleanup UNVERIFIED는 그대로다.

## 승인·보존·회귀

- 새 통합 승인과 기반 Native Binding을 자동 대조했다. 입장 시 유효시간은 약3시간57분으로65분 이상이었다.
- 실제 Scope/R1 yes 뒤 기존 CLI가 새 human decision과 독립 조건부 결정 기록을 발급했다.
  model_action=false, api=false, max start1, automatic_retry=false가 보존됐다.
- Root7개 경로 설치·전후 SHA·새 백업7개를 Root installer가 검증했다. 실제 내용 변경은 승인된3개 설정뿐이다.
- 사전99개 SHA 중96개 그대로, 승인된 설치 정책 JSON·Runtime unit·DNS unit3개만 정확한 새 SHA로 변경됐다.
  기존 원본 실행·SQLite/Queue·과거 증거는 덮어쓰지 않았다. 자동 Rollback이나 권한 확대도 하지 않았다.
- Root Audit는 기존 prefix를 보존하고 **85행 Append**, chain 검증 PASS.
  이번 Runtime Audit19행·state/detail digest 검증 PASS. Legacy Ledger81행·SHA·계측은 그대로다.
- 비권한 timeout 진단·receiver backpressure·Helper lifecycle 회귀는 Workspace/독립 Export 각각 **19 PASS**.
  실제 Tk5개 화면·종료/재연결2회 PASS. Native24/DNS3·서로 다른 Cleanup·모델0을 실제 Backend로 확인했다.
  테스트는 Root·AF_PACKET·Target 권한 경계만 모의하며 실제 Native 재시도를 수행하지 않았다.

## 최종 운영 판정

**PARTIALLY_VERIFIED**: 실제 Packet·DNS 수집과 DNS Helper 필수 Cleanup 증거는 검증됐다.
그러나 93초 조기 종료, TCX receive timeout·STOP ACK 누락, Runtime Seal/ELIGIBLE0 때문에
1시간 운영·전체 Runtime Cleanup·Native AI E2E·최종 운영 릴리스는 검증되지 않았다.

다음 핵심 작업은 보존된5.254초 지연의 원인 계측과 TCX 실패 시 STOP ACK/Seal 증거를
잃는 경로의 비권한 복구 검증이다. Timeout·SHA·Scope·Counter 기준을 완화해서 통과시키지 않는다.
현재 승인과 Session은 소비됐으므로 Root/Native 재시험에는 새 정확한 Binding과 별도 승인이 필요하다.
이번 작업에서 자동 재실행하지 않았다.
