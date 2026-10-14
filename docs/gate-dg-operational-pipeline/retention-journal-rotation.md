# P1 Operational Retention & Journal Rotation — 2026-10-14

## 판정

**VERIFIED — WSL 정상 Native 수집/재개, 보수적 Dry-run 보호, Fixture Rotation/저장 실패/유지보수 Crash 범위 한정.**
실행형 Cleanup, 실제 Journal 파일 Rotation/Vacuum/손상, Windows·별도 Linux 호스트, 디스크 전체 고갈 및 신규 장시간 Soak는 미실행/미적용이다. 운영 전체 검증을 뜻하지 않는다.

## 1. 기준선과 실제 저장 관계

HEAD `0c2e5355d56761370f846113d1570260f0ac86b1`, main. 시작 Git 상태 `/tmp/soc-retention-before.txt`.
기존 사용자 README.md/docs/soc-command-center.md/pyproject.toml 변경과 미추적 자료는 보존했다. Commit/Push 없음.

`native_authentication.LinuxAuthenticationCollector.poll()` → `EventQueue.enqueue()`의 Queue+Cursor 동일 Commit → claim → `OperationalSourceStore.ingest()`의 Source+Watermark+Window 동일 Commit → `build_receipt()` → 별도 Queue.finish Receipt Commit → READ 재검증 순서다.
`authentication_investigation.read_authentication_view()`는 완료 Queue Receipt, Source, Window 및 Provenance를 함께 대조한다. 완료 Queue는 단순 처리 tombstone이 아니며 독립적으로 제거할 수 없다.
Source는 Incident/Window/Provenance와 연결된다. Window는 사건 조사 자료다. Core Incident Evidence의 외부 참조를 모두 조회·승인하는 통합 authority는 없다.

## 2. 보존 정책과 구현 범위

새 `retention.py`의 `soc-auth-retention-plan:v1`은 모든 기록을 보호하고 eligible=0이다. 기본 보존 일수=None, 자동 정리=False, 삭제=0.
7/30/90일은 향후 승인 검토 후보일 뿐 활성 정책이 아니다.

| 데이터 | 제외/보호 사유 |
|---|---|
| PENDING/CLAIMED/Retry/POISON | 미완료·재시도/격리 이력, 삭제 금지 |
| DONE Queue | Evidence Receipt, 재처리 dedup, 외부 참조 불명 |
| Source/Quarantine | Incident 연결, Provenance 원본, 외부 참조 불명 |
| Window | Incident 연결, 조사 종료 상태 불명, Provenance 계산 근거 |
| Cursor | 초기화·삭제 금지, retained Queue 필요 |
| Provenance | 완료 Queue Receipt에 포함된 source/window receipt; 독립 삭제 API 없음 |
| Core Incident Evidence | 이번 정리 대상이 아님; 기존 저장소/API 불변 |

`retention_plan()`은 기존 READ validation과 Cursor validation을 실행하고 local reference validity를 기록한다. 실패 시 UNVERIFIABLE/명시적 오류로 보호하거나 저장소 읽기 실패를 전파한다.
각 항목은 종류, 익명 reference hash, 실제 stored row digest, eligible=False, 제외 사유를 가진다. inventory digest와 항목 수 일치도 typed model에서 검증한다.
`deny_cleanup()`은 Audit 후 명시적으로 거부한다. 삭제 SQL/실행형 Cleanup은 구현하지 않았다. 임의 approval JSON을 삭제 권한으로 취급하지 않는다.
따라서 참조를 완전히 증명할 수 없는 기록을 speculative candidate로 만들지 않았다. 실제 Cleanup은 향후 승인된 기간·cross-store reference authority·정책·복구 계약을 먼저 설계해야 한다.

## 3. Audit와 오류 처리

`MaintenanceLog.create()`는 명시적인 새 private observer SQLite만 만든다. 기존 Queue/Source/Core DB에는 테이블 추가나 Migration을 하지 않는다.
관측 계약 version=1, pipeline binding digest, sequence/previous/digest, UTC 시각, 제한된 operation/status와 summary hash만 저장한다. 원문 이벤트/계정/IP/host/cursor/오류 텍스트는 저장하지 않는다.
이는 별도 로컬 maintenance hash chain이다. 기존 Core Audit Chain이나 승인 기록의 일부라고 주장하지 않는다. privileged DB writer에 대한 cryptographic attestation도 아니다.
Audit 실패는 호출자에게 전파한다. Queue Commit 후 Audit Commit 실패 시 기존 Queue를 되돌렸다고 주장하지 않는다. 미완료 COLLECTION_START는 `collection_outcome_unknown`으로 관측하며 reconcile이 필요하다.

## 4. Rotation 및 Cursor

systemd의 공식 [seek cursor 설명](https://github.com/systemd/systemd/blob/main/man/sd_journal_seek_head.xml)은 지정 Entry가 없으면 근처 Entry로 이동할 수 있어 exact cursor 검증이 필요하다고 설명한다.
[journalctl 공식 문서](https://github.com/systemd/systemd/blob/main/man/journalctl.xml)는 접근 가능한 active/rotated 파일을 함께 조회한다. Rotation 자체와 Entry 삭제는 다른 상황이다.
기존 Collector는 probe cursor의 projection digest를 보존된 event와 대조한 뒤 --after-cursor를 사용한다. 이 검사를 유지했다.
새 `journal_health.collect_with_health()`는 기존 Pipeline.collect를 호출하는 명시적 관측 entrypoint이며 기존 모든 Desktop/Headless 호출을 자동 교체한 것은 아니다. 기존 직접 호출도 오류를 전파하며 fallback은 하지 않는다.

| 상태 | 의미/동작 |
|---|---|
| INITIAL_READ | 새 빈 Queue/Cursor의 초기 조회, 기존 populated Queue의 cursor 누락은 이 상태가 아님 |
| RESUMED_EXACT | 기존 cursor probe 일치 및 조회 성공 |
| RESUMED_WITH_REPLAY | exact probe 뒤 이미 retained된 event 재전달, 중복 처리 |
| GAP_DETECTED | 저장 cursor의 exact entry 검증 실패. 누락 원인/범위 UNKNOWN, 진행 금지 |
| CURSOR_INVALID | 보존 cursor 무결성 실패/기존 Queue에 cursor 누락, 진행 금지 |
| PERMISSION_DENIED | backend가 명시한 권한 거부만 분류 |
| SOURCE_UNAVAILABLE | 읽기 실패/불명확한 backend 응답; 권한·손상 원인을 추측하지 않음 |
| BACKPRESSURE | 일부 이전 event는 Commit됐을 수 있음. 마지막 durable cursor 유지 |
| STORE_FAILURE | SQLite 읽기/쓰기/Commit 실패, 진행 금지 |

최신/처음으로 재탐색하거나 Cursor를 삭제·초기화하는 경로는 없다. Gap을 복구 성공으로 표시하지 않는다.
새 Health의 accepted_count는 신규 Queue 증가분, batch_record_count는 반환 batch 수다. 부분 batch Commit 뒤 overflow를 전체 실패/전체 성공으로 숨기지 않는다.

## 5. 검증 결과 구분

| 시나리오 | 방식 | 결과 |
|---|---|---|
| 새 수집 → 중지/재개 → READ | 실제 WSL journald, 기존 PAM opt-in profile | PASS |
| cursor retained Rotation | command 경계 JSON Fixture, 실제 Collector/Pipeline/SQLite | PASS |
| cursor deleted Vacuum 및 closest surviving entry | 격리 Fixture, exact mismatch | GAP_DETECTED, cursor 불변 |
| collector 중단 중 새 record | Fixture에 새 record 추가 후 after-cursor | PASS |
| duplicate/redelivery | 동일 source/digest Fixture | RESUMED_WITH_REPLAY, 집계 1회 |
| 명시적 권한 상실/읽기 실패/손상 응답 | command 오류/JSON Fixture | Fail-Closed |
| 디스크 full / checkpoint commit 실패 | Queue/Source _commit의 실제 sqlite3 error 주입 | rollback 및 retry 확인 |
| SQLite Busy/Locked | private DB 별도 connection BEGIN EXCLUSIVE | STORE_FAILURE |
| read failure | private connection 오류 주입 | STORE_FAILURE |
| Queue full / 느린 Worker | capacity=1 실제 Queue, drain 전 overflow | 마지막 Commit cursor 유지; drain 뒤 2건 저장 |
| 미처리/retry/POISON/모호한 참조 | 실제 SQLite 상태/변조 Fixture | protected, 삭제 거부 |
| 실제 Journal 파일 vacuum/rotation/손상 | 미실행 | NOT_TESTED |

새 진단은 실제 128건+재개 1건을 retained Queue로 처리했다. 대부분은 인증 변환 미지원 기록이며 인증 실패 1건만 Source/Window로 연결했다.
실측 Native: Queue 129, Source 1, Window 1, embedded Provenance 2, protected 132, eligible=0, local integrity=VALIDATED_LOCAL.
해당 실제 이벤트는 pam_unix 모듈 실패이며 전체 sudo/PAM/login 최종 결과나 공격 사실로 승격하지 않았다. 새로운 인증 시도/실패/권한 상승 없음.
실제 Native 정상 재개의 Gap count/resume failure=0이다. Fixture Gap과 Native 정상 재개를 구분한다.

## 6. Crash Recovery

기존 `tests/authentication_crash_harness.py`의 PID/nonce/active_children/writer-lock 검증을 공통 helper로 추출해 재사용했다. SIGKILL 대상은 Harness의 spawn 자식뿐이다.

| 지점 | 결과 |
|---|---|
| MP-01 Plan 생성/Audit 직후 | plan audit 유지, 자료 불변 |
| MP-02 Cleanup 거부 Audit Commit 전 | audit rollback, 원본 불변 |
| MP-03 Cleanup 거부 Audit Commit 후 | DENIED 유지, 원본 불변 |
| MP-04 Cursor recovery START 기록 후 | STARTED 유지, unknown outcome, cursor 불변 |
| MP-05 Gap Audit Commit 전 | STARTED만 유지, unknown outcome, cursor 불변 |
| MP-06 Gap Audit Commit 후 | GAP_DETECTED 유지, cursor 불변 |
| MP-07 Queue recover/replay 직전 | retained pending 처리, source 2건, 중복 효과 없음 |

신규 강제 종료 7개 지점 PASS. Cleanup DELETE transaction Commit 전후는 실행형 삭제가 없어 NOT_APPLICABLE이며 이를 PASS로 대체하지 않는다.
Queue+cursor Commit/claim/source/window/provenance/ack Crash는 기존 10개 지점 회귀를 재실행했다. 원본 삭제 없는 실제 3 DB의 integrity_check와 Agent READ/WRITE Spy 0을 검증했다.

## 7. Memory/Storage — 새 짧은 실측

새 Fixture 60건 profiling 전체 경과 64.86초. 신규 30분 Soak가 아니다. historical 50초 범위/단일 5분 Window Fixture를 사용했다.
| 고유 event | RSS after GC MiB | traced before GC bytes | traced after GC bytes | SQLite bytes | Source/Window/Provenance |
|---:|---:|---:|---:|---:|---:|
| 0 | 164.76 | 7035 | 8274 | 335872 | 0/0/0 |
| 10 | 168.80 | 629103 | 49574 | 438272 | 10/1/20 |
| 30 | 169.15 | 827670 | 82909 | 737280 | 30/1/60 |
| 60 | 172.42 | 719997 | 123154 | 1486848 | 60/1/120 |

모든 sample queue depth=0, oldest pending age=0, WAL size=0, journal_mode=delete이다. idle snapshot이므로 순간 최대 적체/지연의 증명이 아니다.
GC 후 CommonEvent tracked 객체는 1개(진단의 마지막 event), AuthenticationSource/NativeAuthenticationReceipt는 0개였다. GC-tracked 객체 전체/네이티브 라이브러리 할당을 다 측정한 것은 아니다.
10건에서 traced bytes는 629103→49574, 60건에서는 719997→123154로 GC 후 감소했다. RSS는 모두 회수되지 않았다. 이를 메모리 누수나 특정 캐시 탓으로 단정하지 않는다.
실측상 보존 DB 성장, 단기 Python 객체 회수, 일부 지속 Python allocation이 함께 관측된다. top allocation에는 main.py/typing.py/source_store.py가 있었다. source_store.py 경로는 row hashing/serialization이며 캐시 누수의 입증은 아니다.
SQLite page_count는 Queue 40→279, Source 42→84였다. cache_size=-2000은 설정이며 실제 page cache 사용량은 측정 불가(None)로 남겼다.
완료 Queue outcome이 당시 Window Provenance를 포함하고 READ가 retained history를 대조하므로 저장·조회 비용이 입력 보존량과 함께 증가한다. 삭제로 무결성을 깨는 대신 승인된 archive/reference 설계가 필요하다.
이전 30분 Soak 보고서의 RSS 증가 결과는 선행 증거이며 이번 새 profiling으로 재실행/새 장시간 PASS를 주장하지 않는다.

## 8. 발견한 결함과 테스트

재현 가능한 기존 결함: Source SQLite Commit failure가 INVALID_INPUT으로 기록됐다. 실패 재현 테스트에서 이 오분류를 확인했다.
`authentication_pipeline.step()`에서 StorageError를 먼저 분리해 기존 Queue의 STORAGE_FAILURE category로 retry 기록하도록 4줄을 추가했다. 정상 success path, Source/Window/Receipt 형식, retry limit, Decision/Approval 계약은 불변이다.
초기 신규 구현의 inventory SHA는 canonical object 계약에 맞춰 items object로 수정했다. 초기 테스트 import/상태 가정 오류도 실제 인터페이스에 맞게 수정했다. 보안 검사 삭제/skip/xfail 없음.
관련 회귀 524 passed. 그 이후 replay/partial capacity/audit tamper 3개 추가: 신규 25개+기존 Crash 14개 집중 실행 39 passed. 최종 신규 25개도 별도로 재확인했다. 중복 실행은 합산하지 않는다.
전체 회귀는 반복하지 않았다. 프로덕션 변경은 오류 category와 명시적인 새 maintenance/health 경계이며 기존 정상 Source/Core 동작 관련 집중 증거를 사용했다.

## 9. 변경 파일

- 신규 `src/soc_agent/security_ai/operational/retention.py`: typed plan, 보호, 삭제 거부, 별도 hash-chain observer, metadata metrics.
- 신규 `src/soc_agent/security_ai/operational/journal_health.py`: 기존 collect의 상태 분류/관측, reset/fallback 없음.
- 수정 `src/soc_agent/security_ai/operational/authentication_pipeline.py`: StorageError category 분리.
- 수정 `tests/authentication_crash_harness.py`: 소유한 자식 종료 검증 helper 재사용.
- 신규 `tests/integration/authentication_retention/test_retention_rotation.py`.
- 신규 `tests/integration/authentication_retention/test_maintenance_crash.py`.
- 신규 `tests/diagnose_retention_journal.py`.
- 이 보고서.

## 10. 재현과 증거

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q tests/integration/authentication_retention tests/integration/authentication_stability
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m tests.diagnose_retention_journal --directory /tmp/NEW_PRIVATE_PATH
```
기존 경로를 덮어쓰지 않는다. profiler/Native 저장소는 분리되며 기본 기간/삭제 정책은 없다. 실제 journald 설정·서비스·파일은 수정하지 않는다.

| 증거 | SHA-256 |
|---|---|
| `/tmp/soc-retention-journal-profile-20261014/results.json` | `51a1e89800340cc446b4227ec8074e448d9da864abd86732c96e4abf26bb8b4f` |
| `/tmp/soc-retention-regression.log` | `ab8f76698f117d33251eab9f97d8ef83dbefec7be33d446d4ca614ee3983b839` |
| `/tmp/soc-retention-final-focused.log` | `0f1bb703dc41eedd3fc5d9eb1ed8764d73f7943abcad894fa089ff53190e0f99` |
| `/tmp/soc-retention-final-new.log` | `f63f437895306184c23e8fa444e539f24758cc0cd41a454f1e11ea3d396b475f` |
| `/tmp/soc-retention-storage-repro.log` | `21117531321c60a5df7e659b277ed6fa5d93d10355893b09b89b1018ff926624` |

## 11. 남은 운영 제한과 다음 단계

- 실제 Cleanup/Archive 승인과 cross-store evidence reference authority가 없어 eligible=0이다. 디스크 회수가 됐다고 주장하지 않는다.
- 실제 Journal binary의 Rotation/Vacuum/손상/삭제는 미실행. command-boundary Fixture와 정상 Native 재개만 확인했다.
- 권한 거부는 Fixture로 검증했으며 실제 WSL 권한을 변경하지 않았다. Windows Security 기존 PERMISSION_DENIED 및 별도 Linux 호스트는 미검증 유지.
- health wrapper는 명시적 API이며 모든 기존 서비스/CLI 진입점에 자동 활성화하지 않았다. 운영 서비스 적용 시 같은 writer lock과 observer store를 구성해야 한다.
- Queue/Source/Observer 3개 DB의 원자성을 주장하지 않는다. 미완료 intent는 outcome unknown으로 남으며 재조회가 필요하다.
- 새로운 maintenance table은 새 observer DB에만 생성했다. 기존 DB Migration/운영 DB 변경 없음.
- 7/30/90일 후보는 미승인. POISON/retry/참조 불명 데이터를 자동 삭제하지 않는다.
- 후속 권장: 승인된 archive+reference contract, 저장 용량/retention high-water 운영 경보, page cache/allocator 장기 profiling, 테스트 전용 Journal binary rotation 환경.
- Synthetic v2/Operational Provenance v3/Network-DNS NOT_INFERABLE/Agent WRITE_DENIED/Policy-Approval는 유지됐다. 기존 Audit Chain 재작성 및 모델/LLM 실행 없음.

## 12. 최종 보존·정적 검사

Ruff src/tests PASS, Format 738개 파일 PASS, git diff --check PASS.
기존 Git status entry 전체가 보존됐다. Source Store/provenance.py/native_authentication.py/authentication_investigation.py는 HEAD와 바이트 단위로 동일하다.
보호 파일 tests/fusion_support.py SHA:
`e5f9d10f706f71b82e80261f7633a1504e27ba24499be948d04adb6eeb3a21c9`.
이번 파일은 신규 6개·수정 2개(보고서 포함 총 8개)이며 사용자 기존 변경은 포함하지 않는다.
