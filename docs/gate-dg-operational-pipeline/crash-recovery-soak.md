# P1 Authentication Crash Recovery / Soak — 2026-10-14

## 판정과 검증 범위

**VERIFIED — WSL 격리 SQLite의 10개 강제 종료 지점, 5분 Smoke, 30분 재시작 Soak 및 단일 Worker 30분 연속 Soak 범위.**
운영 전체·별도 Linux 호스트·Windows Native·전원 장애·2시간 Extended Soak·LLM 자율 조사: **INCONCLUSIVE / NOT_TESTED**.
실제 기존 PAM 모듈 인증 실패 기록을 읽고 재사용했다. 새 로그인 시도·실패·sudo 실행·권한 변경을 하지 않았다.
Native 기록은 sudo/pam_unix 모듈 실패이며 최종 로그인/전체 PAM 결과나 공격 사실을 뜻하지 않는다.
Fixture는 명시적 OpenSSH 텍스트 Fixture이다. 실제 OS 이벤트로 위장하거나 모델에 전달하지 않았다.

## 1. 기준선과 변경

HEAD `bc0e31cc87d7b0127cff70fa051075aa515fbeff`, main. 시작 상태 `/tmp/soc-crash-before.txt`.
프로덕션 코드·DB Schema·합성 v2·운영 Provenance v3·Policy/Approval/Decision 계약은 변경하지 않았다.
신규 파일만 추가:

- `tests/authentication_crash_harness.py` — 소유한 spawn 자식/Pipe nonce handshake, 테스트 전용 hook, 강제 종료, 재개·정합성·Guard 검증.
- `tests/diagnose_authentication_stability.py` — Native read-only 재수집과 분리된 Fixture Soak, 실측 JSONL, 정상 Worker 교체·연속 실행.
- `tests/integration/authentication_stability/test_crash_recovery.py` — 10개 Crash Point 및 변조/재시도 한계 테스트.
- 이 보고서.

## 2. 실제 저장 순서와 위험 경계

1. `LinuxAuthenticationCollector.poll()`은 읽기 전용 조회/커서 원본 검증 후 CommonEvent를 메모리로 반환한다.
2. `EventQueue.enqueue()`의 단일 SQLite transaction에서 retained event와 cursor를 함께 기록한다. Queue Full·Rollback 시 둘 다 진행되지 않는다.
3. `EventQueue.claim()`은 별도 transaction으로 CLAIMED/token/attempts를 기록한다.
4. `OperationalSourceStore.ingest()`는 source, watermark, `_snapshot()`의 window SQL을 하나의 Source DB transaction에서 Commit한다.
5. `ingest_authentication()`은 저장 원본·window를 재조회하고 `build_receipt()`로 Provenance를 계산한다. 이 시점 Receipt는 메모리이며 별도 독립 DB Commit이 없다.
6. `EventQueue.finish()`는 Queue DB transaction으로 DONE와 receipt/outcome을 기록한다.
7. READ Tool은 queue binding/receipt/source/window/Provenance를 다시 대조한다. Source만 있고 Ack receipt가 없으면 조회는 Fail-Closed한다.

Queue DB와 Source DB는 서로 다른 Commit이다. cross-DB 원자성이나 Exactly-Once Delivery를 주장하지 않는다.
재전달은 at-least-once이며, Source identity/digest idempotency로 이 실험의 집계 effect가 한 번만 발생함을 확인했다.
프로세스 중단으로 CLAIMED가 남으면 **exclusive_runtime_lock을 소유한 단일 Writer만 recover()**한다. 재시도 한계 도달 시 POISON은 정상 완료가 아니다.
반복 장애로 Source가 Commit되고 receipt가 끝내 POISON 상태라면 자료는 남지만 READ는 차단된다. 운영자가 원본/receipt를 안전하게 조정할 별도 절차가 필요하며 이를 자동 완료로 처리하지 않는다.

## 3. Crash Point와 조정 근거

| 지점 | 실제 hook 경계 | Fixture | 실제 Native projection 재사용 |
|---|---|---|---|
| CP-01 | 읽은 projection이 메모리에 있고 enqueue 전 | PASS | PASS |
| CP-02 | Queue event+cursor SQL 후 Commit 직전 | PASS | PASS |
| CP-03 | Queue Commit 직후 — cursor도 이미 같은 Commit | PASS | PASS |
| CP-04 | claim Commit 직후 | PASS | PASS |
| CP-05 | Source+Window Commit 직후 | PASS | PASS |
| CP-06 | Window SQL 직후, Source transaction Commit 전 | PASS | PASS |
| CP-07 | Native receipt/Provenance 계산 후, Ack 전 | PASS | PASS |
| CP-08 | Queue finish/Ack 직전 | PASS | PASS |
| CP-09 | Queue finish Commit 직후 | PASS | PASS |
| CP-10 | 실제 governed READ handler의 Source window 재검증 중 | PASS | PASS |

CP-03의 “Queue Commit 후 cursor 저장 전”, CP-06의 독립 “Window Commit”은 실제 구조상 존재하지 않는다. 존재하는 경계로 조정했다.
CP-01 Native 실험은 실제 수집 projection을 자식에 전달한 뒤 종료한다. journald 프로세스나 조회 명령을 종료한 실험은 아니다.
CP-10은 실제 InvestigationOrchestrator → Tool → 저장 자료 재조회 경로 안의 hook이다. DB 쓰기나 모델/LLM 실행은 없다.

최종 진단에서 **20회** 강제 종료(10 지점 × Fixture/Native). 자동 pytest의 반복 실행은 이 숫자에 합산하지 않는다.
부모는 자신이 생성한 Process 객체, active_children, 자식 Pipe PID·nonce를 확인한 뒤 kill()한다. WSL에서는 SIGKILL, 운영 PID/서비스는 대상이 아니다.
kill 시 자식이 실제 Writer Lock을 보유했고 다른 Writer가 같은 lock을 획득하지 못했다. 종료 후 OS lock 해제로 새 Writer가 복구했다.
각 지점에서 재개 전 source row count, cursor Commit 유무, 단일 DONE, original source digest, window total=1, PRAGMA integrity_check/foreign_key_check를 확인했다.
각 지점 복구 후 기존 InvestigationOrchestrator의 READ 조회와 실제 Guard의 WRITE 거부를 검사했다. WRITE Spy 0, NOT_INFERABLE/WRITE_DENIED 유지.

## 4. 실측 시간과 추이

| 실행 | 실제 경과 초 | Worker 프로세스 수 | Fixture 고유 이벤트/Ack | Native 저장 / 인증 effect | 샘플 수 |
|---|---:|---:|---:|---:|---:|
| Smoke | 303.14 | 5 | 49/49 | 784 / 1 | 17 |
| 재시작 Soak | 1803.69 | 29 | 244/244 | 2624 / 1 | 96 |
| 단일 Worker 연속 Soak | 1804.21 | 1 | 244/244 | 2624 / 1 | 59 |

Smoke·재시작 Soak은 약 60초마다 Worker를 정상 종료/재생성한다. 연속 Soak은 동일 Worker를 30분 실행한다.
Native collector도 각 Worker에서 실제 journal cursor를 읽고 이벤트를 enqueue/처리한다. Unsupported 기록은 인증으로 변환하지 않는다.
Fixture는 약 5초 간격으로 고유 이벤트 1개와 명시적 중복 enqueue 1회를 넣는다. 고부하 처리량/SLO 시험이 아니다.
Native와 Fixture는 각각 별도 Queue/Source DB이다. 동일 staging Incident UUID를 사용해도 DB 경계가 분리되며 자료를 섞지 않는다.

| 실행 | Worker RSS 최초→최종 MiB | 샘플 최소/최대 MiB | Fixture SQLite 최초→최종 bytes |
|---|---:|---:|---:|
| Smoke | 165.31 → 173.43 | 165.31/173.43 | 339968 → 1163264 |
| 재시작 Soak | 165.54 → 246.08 | 165.54/253.23 | 339968 → 13332480 |
| 연속 Soak | 165.48 → 246.89 | 165.48/247.39 | 339968 → 13332480 |

RSS는 Linux /proc/self/statm resident pages 실측이다. 같은 Worker가 두 DB를 처리하므로 Native/Fixture RSS는 별도 메모리 할당 측정이 아니다.
각 JSONL에는 elapsed, collected/enqueued/claimed/acked/retried/rejected/deduplicated, window count, provenance validation failures, read/write-blocked, queue depth, oldest pending age, restart count, RSS, SQLite size를 기록했다.
collected는 진단의 고유 projected/Fixture event 수이다. 명시적 duplicate enqueue는 별도 deduplicated 수에 들어간다. Native 요약에서 인증 effect와 총 OS records를 구분한다.
약 25초 간격/Worker 종료 샘플은 batch drain 이후 snapshot이므로 실행 중 순간 최대 queue depth/latency를 의미하지 않는다.
Provenance 재검증 실패나 child exception은 실행을 중단하고 FAIL로 처리한다. 0은 실제 성공한 검증 샘플의 오류 건수이다.
최종 모든 Queue가 DONE이며 pending=0, Fixture unique event=Ack=window effect를 검증했다. Native 인증 실패 effect도 중복 없이 유지됐다.

## 5. 테스트와 수정

집중 회귀 첫 실행: **501 passed, 1 failed**. 실패 원인은 새 변조 테스트가 SQLite 실제 열 `digest` 대신 없는 `source_digest`를 사용한 테스트 오기였다.
해당 테스트를 실제 Schema의 `digest`로 수정: **1 passed**. 최종 신규 집중 테스트: **14 passed**.
첫 회귀에 포함된 기존 관련 테스트는 **488 passed**이며 신규 14개와 분리한다. 중복 실행 숫자는 합산하지 않는다.
추가 보안 검증: receipt/source/cursor 변조 거부, retry exhaustion의 POISON/불완전 receipt READ 거부.
프로덕션 결함은 이번 범위에서 발견하지 않았다. 기존 Guard를 완화하거나 test skip/xfail을 추가하지 않았다.
Ruff src/tests PASS, format --check PASS, git diff --check PASS. 기존 사용자 수정 및 protected SHA 확인은 최종 로그에 기록했다.

## 6. 재현 명령과 증거

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q tests/integration/authentication_stability
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m tests.diagnose_authentication_stability \
  --directory /tmp/NEW_PRIVATE_PATH --native-crashes
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m tests.diagnose_authentication_stability \
  --directory /tmp/ANOTHER_NEW_PRIVATE_PATH --soak-only \
  --worker-lifetime-seconds 1800 --soak-seconds 1800 --native-crashes
```
기존 경로를 덮어쓰지 않는다. Native 옵션은 읽기 가능한 기존 record만 사용하며 성공/실패 이벤트를 만들지 않는다.

실행 결과 JSON/JSONL은 원본 사용자명/IP/host를 포함하지 않으며 private /tmp 경로에 보관한다. 재부팅/청소로 사라질 수 있으므로 이 보고서의 요약과 SHA를 함께 사용한다.

| 증거 | SHA-256 |
|---|---|
| `/tmp/soc-auth-stability-20261014-final/results.json` | `b8844eadc9c18ec654cc1e185f40e93c2c250a3a7ec6fbf425bb7c826bc5ffc8` |
| `/tmp/soc-auth-stability-20261014-final/smoke/metrics.jsonl` | `52a28a2b8bdf6e881df3fe7e0dd10453d11f9c46a081f7e31e7c3ec34f949527` |
| `/tmp/soc-auth-stability-20261014-final/soak/metrics.jsonl` | `05c55dc169ccb76dd9d5389ac88e9ddf14e32cb8214a0559f297991db46de485` |
| `/tmp/soc-auth-stability-continuous-20261014/results.json` | `0a2d5c582d6fe31f3e7fe9c9087946755799046a4bbf95a95284f4d494e81ba6` |
| `/tmp/soc-auth-stability-continuous-20261014/continuous/metrics.jsonl` | `925e47d81b684721593ddf88b65e2afdd83585baf12da852547d681345ebde46` |
| `/tmp/soc-auth-crash-final-focused.log` | `170535cba2f291f8e390db3a95d14db7cb799b9e45e9e9343d0c9a5a1b2741c9` |
| `/tmp/soc-auth-crash-regression.log` | `6a088b71eb36811e14d57f987e024c80df320ceafd643cbd40568921974cd0dc` |
| `/tmp/soc-auth-crash-final-reopen.log` | `e003276926c00fb89e739e1cd56c6bf56e35839dec5625ff7c13a2edf627b212` |

## 7. 미검증·운영 위험

- Windows Security 로그는 기존 PERMISSION_DENIED 상태를 유지했다. Windows 권한/정책 변경 및 Native 실험 없음.
- 별도 Linux Desktop/Headless 호스트, 실제 인증 성공 이벤트, LLM 자율 조사, 모델 추론 미검증. PAM 모듈 실패→deterministic READ-only 조사만 검증했다.
- 2시간 Extended Soak, 대규모/장기 retention, Disk full, 전원 차단/파일시스템 torn-write, 커서 원본 rotation/deletion, OS 재부팅은 이번 실험에 포함하지 않았다.
- 반복 crash가 retry limit에 도달하면 POISON으로 격리된다. Source Commit 후 receipt가 없다면 안전하게 READ를 차단하며 자동 승인/완료로 바꾸지 않는다.
- Queue 100,000 tombstone와 Source capacity 한계에서 archival 절차가 없으면 intake가 안전하게 중단된다. 자동 자료 삭제/중복 이력 폐기는 하지 않는다.
- Cross-DB publication은 idempotent 재처리이며 독립 snapshot을 동시 Writer에 대해 원자적이라고 주장하지 않는다. 이번 Harness는 실제 exclusive single-writer lock을 사용했다.
- /proc RSS의 제한된 30분 추이만으로 memory leak 부재나 운영 용량을 보증하지 않는다.
- Provenance v3 DECLARED_UNATTESTED는 source/처리 연결 검증이며 암호학적 OS 진위 attestation/Feature 학습 정합성 증명이 아니다. Network/DNS NOT_INFERABLE 유지.
- Python 내부 TCB 밖 악성 코드 격리는 별도 process/OS permission 영역이다. 테스트 객체의 frozen 여부를 보안 격리로 주장하지 않는다.
- Commit/Push, 운영 DB Migration, 보안 WRITE Handler, Live LLM, 모델 재학습을 수행하지 않았다.

다음 권장 검증: 승인된 별도 Linux 호스트/Windows 읽기 권한 환경, 2시간 연속 부하, retention/디스크 장애, journal rotation 및 POISON operator recovery 절차.

## 8. 최종 별도 프로세스 재조회와 보존 확인

모든 Soak Worker 종료 후 별도 Python 프로세스에서 6개 저장소 조합을 다시 열었다.
각 Queue의 DONE 수, source/window total, Provenance, SQLite integrity_check, 실제 Orchestrator READ 및 WRITE Spy 0을 확인했다.

| 실행 | 데이터 | Queue DONE | 인증 이벤트 / Window effect |
|---|---|---:|---:|
| smoke | FIXTURE | 49 | 49 / 49 |
| smoke | REAL_OS | 784 | 1 / 1 |
| soak | FIXTURE | 244 | 244 / 244 |
| soak | REAL_OS | 2624 | 1 / 1 |
| continuous | FIXTURE | 244 | 244 / 244 |
| continuous | REAL_OS | 2624 | 1 / 1 |

| 실행 | Native SQLite 최초→최종 bytes |
|---|---:|
| Smoke | 368640 → 1998848 |
| 재시작 Soak | 368640 → 5890048 |
| 연속 Soak | 368640 → 5890048 |

Fixture는 historical timestamp의 50초 범위를 순환시키며 하나의 5분 Window를 갱신했다. 30분의 실제 입력률/여러 Window 운영 모델을 재현했다고 주장하지 않는다.
Queue의 완료 receipt에는 당시 Window Provenance가 포함되며 READ는 보존 이력을 재검증한다. 데이터 증가에 따른 직렬화·조회 비용과 RSS 증가를 별도 용량 검증해야 한다.
At-least-once 재처리는 영속 Queue의 재시도 범위에 관한 설명이다. 수집 전 원본 journal이 삭제/rotation되거나 재시도 한계에 도달한 이벤트의 무제한 복구를 보장하지 않는다.

최종 Ruff src/tests PASS, Format 732개 파일 PASS, Diff PASS.
기존 사용자 수정 README.md/docs/soc-command-center.md/pyproject.toml은 시작 SHA와 일치한다. 기존 모든 status entry 및 미추적 자료를 보존했다.
보호 파일 tests/fusion_support.py SHA:
`e5f9d10f706f71b82e80261f7633a1504e27ba24499be948d04adb6eeb3a21c9`.
프로덕션 수정 0개, 신규 test/diagnostic Python 3개와 보고서 1개이다.
