# Native 20분 Packet·DNS·GUI 제한 시험 결과 — 2026-11-02

최종 판정: **PARTIALLY_VERIFIED — Native 20분 목표 실패**.
승인된 단일 시험은 수행됐지만 DNS Helper Heartbeat 오류로 조기 종료됐다.
자동 재실행하지 않았다. Runtime Cleanup은 UNVERIFIED이므로 후속 권한 실행을 중단한다.
별도 Replay의 실제 경과 1,200.13초 성공 결과는 그대로 보존한다.

## 실행 Identity와 승인

- 실행 HEAD `fd53942d831769e0d6e542d843f22e72213f4be5`, 운영 코드 `c6405d7`.
- 검토 패키지 `.git/native20-storage-recovery-20261102T034709Z/native/approval-package-final.md`.
- Runtime Session `d4cd38bd-072c-42db-bfe1-0e1552cde664`.
- DNS Session `48193936-2e60-4ebb-9ad9-8f7b61c4aea3`.
- 기존 Namespace `net:[4026532232]`, `lo / Ingress`, Release `0.6.3`.
- 실행 전 Source672개·Artifact·Root Manifest·고정 의존성·기존 증거의 읽기 전용
  SHA 대조1,502건 통과. 사용자 실제 터미널에서 Scope yes 및 직접 sudo 인증 완료.
- 새 정확한 인간 결정·R1·독립 결정 기록을 사용했다. 기존 소비 영수증을 재사용하지 않았다.
- Root8경로 백업·검증, 승인된 설정4개 변경·나머지4개 verify-only.
  설치 후8경로 SHA와 보존 대상85개 SHA 재검증 통과. 기존 Rollback 삭제 없음.
- 전체 상한1,800초, 순수 수집 목표1,200초. TCP 최대8연결, DNS UDP2/TCP1만 허용.
  승인된 CPU·메모리·Queue32·저장량 점검 상한을 확대하지 않았다.
- RF/LR·DNS9·외부 API·Host Authentication 수집 제외. 모델 승인 파일 발급0회.

## 실제 결과

| 항목 | 결과 |
|---|---|
| 전체 Worker 실행 | 66.986초, 실제 Root 자식 Exit2 |
| Root trial 실행 | 65.410초 |
| Collector 시작 이후 종료·정리까지 | 60.472초 — 순수 수집 시간과 다름 |
| 원시 Seal의 enabled capture interval | 53.693초 — 실패 Stream 진단용이며 적격 수집 완료 증거가 아님 |
| Runtime VERIFIED 수집 시간 | 0초 |
| Kernel Load·TCX Attach·Collector READY | 확인 |
| Native callbacks | 14건: Runtime 수신12건·실패 후 격리2건 |
| DNS | 완료 Transaction2건(UDP1/TCP1), 승인된 DNS 전체 Probe는 중단됨 |
| TCP Helper | 시작0회 |
| Runtime Window | 0개, Attestation UNKNOWN / WINDOW_NOT_SEALED |
| 진단 Seal | 1개, 실패 후 Cleanup 증거이며 모델 Admission 권한이 아님 |
| ELIGIBLE / INCOMPLETE | 0 / 0 — 미완성 입력이 적격 판정을 받은 것이 아님 |
| Queue / Drop / Source Gap | 빈 Queue / 0 / 0 |
| RF/LR Prediction / Incident / API | 모두0, 승인 범위대로 실행 안 함 |
| SQLite / Service Audit | service·queue integrity_check OK, Audit29행 chain 검증 통과 |
| Ledger | 기존81행·SHA 불변 |

## 최초 오류와 후속 오류

최초 Runtime 오류는 `CaptureUnavailable:HELPER_HEARTBEAT_OR_PROCESS_STALE`이다.
DNS transport-failure 기록 시각은 2026-11-02 13:48:29.859795 KST이며,
Root observer는 13:48:30.892529 KST에 해당 오류를 CAPTURE 실패로 기록했다.

DNS Reader의 마지막 Heartbeat 관측 Age는2.015534초, 기존 Deadline은2초,
최대 Reader poll gap은3.643053초다. Queue depth0, high-water12/32,
counter issue 없음이다. 이 기록은 Heartbeat 관측 공백을 입증하지만 Helper가
그 시점에 종료됐다는 증거는 아니다. 이후 동일 Helper에서 STOP에 대한 CLOSED와
검증된 최종 Counter를 받았다. Helper 송신 지연·Reader 스케줄링·GIL·호스트 지연
중 근본 원인은 **UNKNOWN**이다. Timeout 값을 바꾸거나 성공으로 해석하지 않았다.

후속 Producer 오류는 `CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT`이다.
동일 Root PID/start identity 및 IPC 연결이 남은 상태에서 마지막 수신 이후
5.000173초가 지났고 receiver queue depth0/drop0이었다. 마지막 Control stage는
`INSTALLED_INTEGRITY`, 직전 기록의 receive latency는0.148038초였다.
프로세스 종료와 전송·실행 지연을 동일하게 취급하지 않으며 실제 원인은 UNKNOWN이다.

Runtime의 최초 오류는 유지됐다. STOP Audit의 별도 secondary_errors에는
`TimeoutError` 및 DNS `CaptureUnavailable`이 기록됐다. Runtime 프로세스의 최종
CLI 오류도 TimeoutError/Exit2다. 세부 Timeout 발생 await 지점은 해당 실행의
기록만으로 특정할 수 없어 UNKNOWN이다. Runtime 정상 종료 성공으로 처리하지 않는다.

## Control / Data Progress

보충 Observer는 전체 실행 중 후반18.987초, 새 게시9회를 관측했다.
관측된 Control timestamp 간격 최대4.645804초, active Heartbeat Age 최대5.027733초다.
이는 전체 구간을 빠짐없이 측정한 최대 간격이 아니며, 5초 계약 충족으로 판정하지 않는다.
실행 전체 성공 조건인 안정된20분 Heartbeat 관측은 미완료다.

최종 Runtime 계측의 저장 작업 최대4.432309초(operation update),
Control publication 최대3.642816초, Data Progress degradation/recovery0회였다.
Data Progress 정체가 없었다거나 저장 지연이 근본 원인이라고 단정하지 않는다.

## STOP / Cleanup

| 영역 | 판정과 증거 |
|---|---|
| TCX Collector | VERIFIED: bound STOP ACK·진단 Seal·receiver join·socket close |
| DNS Helper | VERIFIED in owned scope: authenticated CLOSED·Counter·STOP 순서·reader/handshake join·listener/channel close·Helper EXITED |
| Root-owned 자원 | 기록된 Scope VERIFIED: 소유 서비스 PID0·cgroup 없음, Producer socket 없음, TCX Link/Map 전후 빈 목록 |
| Runtime | **UNVERIFIED**: 실제 프로세스 종료, STOP Audit secondary Timeout/CaptureUnavailable, 최종 DEGRADED |
| Global Kernel | **UNVERIFIED**: 전역 Program ID 집합 변화가 관측됐으며 소유권·원인 확인 없이 정리 성공으로 확대하지 않음 |

Helper 최종 Counter는 received_frames25, sent_packets13, kernel_packets_total28,
capture_drops0, COUNTER_VERIFIED다. Runtime에 전달된12개 외1개는 실패 이후 격리됐다.
완료되지 않은 DNS traffic 자식은 기존 실패 Cleanup 경로에서 종료됐으며(-9),
이를 UDP2/TCP1 전체 송수신 성공으로 보고하지 않는다.

기존 FAILED·false·UNKNOWN·UNVERIFIED를 소급 변경하지 않는다.
Root Audit의 기존 내용 prefix도 유지됐으며 새 실행 기록만 뒤에 추가됐다.

## GUI

단일 CLI `start --gui`로 기존 일반 사용자 GUI를 연결했다. 조기 중단으로
수집 중 close/reconnect 안정성 검증 단계에는 도달하지 못했다.
종료 후 별도 소유 Tk GUI2개를 순차 연결·정상 close/reconnect하고 screenshot을 남겼다.
두 화면은 동일 Session의 실제 보존 Backend를 읽어 NATIVE_SERVICE,
Native live False, Collector/Worker STOPPED, Runtime DEGRADED·Cleanup UNVERIFIED,
TCX ACK True, Helper EXITED·Cleanup VERIFIED, Transaction2·Prediction0을 표시했다.
이는 실패 결과의 재연결 검증이며 실제20분 Live 관제 성공이 아니다.

## 증거와 다음 단계

증거 루트: `.git/native20-storage-recovery-20261102T034709Z/`.

- `native20-result.json`, `completed-evidence-sha256.json`.
- `native/execution/first-error.json`, `root-finished.json`, `root-deadline-result.json`,
  `runtime-final.json`, `installed-files.json`, 실제 systemd 최종 상태·Journal·Kernel Snapshot.
- `native/dns-session/transport-failure.json`, `verified-ready.json`,
  `verified-closed.json`, `cleanup.json`.
- `live-observer-result.json`, `live-observations.jsonl`.
- `gui-check-failed-retained.json`, GUI screenshot2개.

이번 실행에서 운영 Source·Artifact는 수정하지 않았다. 문서·보충 읽기 전용 관측만 추가했다.
이미 성공한 비권한948건 회귀 및 Replay20분 결과를 실제 Native 검증으로 확대하지 않는다.
이번 실환경 시험 자체는 실패했으며 1시간 시험으로 진행할 수 없다.
다음 작업은 비권한 환경에서 DNS2초 lease 관측·Producer control 지연·Runtime cleanup
Timeout의 개별 재현과 최소 수정이다. 실제 재시험은 새 Binding·새 단일 실행 승인과
직접 인증이 필요하며, 이번 승인으로 자동 재실행하지 않는다.
