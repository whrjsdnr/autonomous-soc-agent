# P1 Archive Readiness & Capacity Monitoring — 2026-10-14

## 판정과 범위

**VERIFIED — 읽기 전용 Archive readiness, 예시 임계값 기반 capacity 관측, 격리 Fixture 장애/Crash 및 실제 WSL 5분 관측 한정.**
Archive 실행·이동·삭제·승인 발급·자동 제어는 구현/실행하지 않았다. 운영 전체, Windows/별도 Linux 호스트 및 실제 저용량 디스크 장애는 미검증이다.

## 1. 기준선과 재사용 구조

HEAD `85a98ae01a474700d382779e65961853262bfd9c`, main. 시작 상태 `/tmp/soc-archive-before.txt`.
기존 AuthenticationPipeline, persistent Queue, Source Store, 5분 Window, v3 receipt와 read_authentication_view를 재사용했다. 새 모델/Source/Incident 저장소를 만들지 않았다.
Queue와 Cursor는 동일 transaction, Source와 Window는 동일 transaction, Queue Ack는 별도 DB Commit이다. capacity 관측/경보 observer 기록도 별도 commit이며 cross-DB 원자성을 주장하지 않는다.

## 2. Archive readiness 계약

`soc-auth-archive-readiness:v1`: ArchiveRequest는 Incident UUID, 고유 source event UUID, 대응 expected source digest를 요구한다. 중복/길이 불일치를 거부한다.
필수 항목 검증: Queue 존재·상태, source 존재·digest, Incident binding, 기존 Source/Window/Provenance/Evidence 대조, 대상 중복, 보호·승인 경계.
유효한 현재 대상도 Incident 연결·Provenance 참조·외부 Evidence 참조 불명으로 **PROTECTED**다. 외부 참조가 해소됐다고 판단하지 않는다.
필드의 상태 enum은 READY_FOR_REVIEW/PROTECTED/INCOMPLETE_EVIDENCE/INTEGRITY_FAILURE/APPROVAL_REQUIRED/BLOCKED를 지원한다. 현재 producer는 보호·오류 상태만 발급한다. READY_FOR_REVIEW 및 APPROVAL_REQUIRED의 발급 절차는 미구현이다.
archive_execution_allowed는 Literal[False], approval_requirement는 NO_EXECUTION_APPROVAL_CONTRACT. 어떤 상태도 실행 허가가 아니다.
미완료/Retry/POISON 및 missing target은 INCOMPLETE_EVIDENCE, 불일치는 INTEGRITY_FAILURE, 잘못된 Incident/저장소 읽기 실패는 BLOCKED다.

## 3. 결정적 Manifest

핵심 필드: archive_candidate_id, binding_digest, source_event_ids, expected_source_digests, 검증된 source_digests, window_ids, incident_ids, provenance_references, evidence_digest, retention/readiness status, blocking_reasons, 실행 불가 flag, manifest_digest.
event/digest pair와 source/window/provenance references를 정렬한다. candidate hash는 binding+Incident+정렬된 요청에서 계산한다. manifest hash는 core JSON에서 계산하며 created_at을 제외한다.
같은 저장 상태·대상·binding 입력에서 core와 digest 일치를 검증했다. created_at은 UTC 가변 metadata다. 다른 store binding/상태는 같은 입력이 아니다.
비밀번호/토큰/인증 메시지/계정/IP/host 원문을 포함하지 않는다. event/Incident UUID는 연결 식별자이며 source reference는 hash다.
생성 중 저장 mutation/Audit/approval 발급을 하지 않는다. 누락/변조 검증 없이 source digest·window linkage를 유효하다고 출력하지 않는다.

## 4. Approval 경계

기존 PolicyEngine.evaluate → GovernedExecutor.request_approval/preflight → ApprovalManager의 등록 Tool/action binding 계약을 조사했다.
Archive Tool이나 Executor를 등록하지 않았다. READY_FOR_REVIEW는 문서 검토 상태이지 파일 이동·삭제용 ActionProposal/ApprovalRequest가 아니다.
임의 approval_id 필드/실행 flag 추가 및 manifest digest 변조를 거부한다. hash는 로컬 내용 일치 수단으로 승인/서명/진위 증명이 아니다.
기존 Agent READ registry/guard를 실제로 호출해 WRITE Spy 0을 확인했다. READ 결과로 WRITE 권한을 얻지 않는다. 승인된 Archive 실행은 다음 별도 계약 단계다.

## 5. Capacity 계약과 의미

`soc-auth-capacity-observation:v1`: 모든 metric은 nullable이다. 읽기/계측 불가를 None(UNKNOWN)으로 두고 errors에는 고정 code만 기록한다.
Queue depth=Pending+Claimed, pending=Pending만, retry=실패 후 Pending(attempts>0) 또는 재시도 Claimed(attempts>1), poison=POISON이다.
oldest age는 ingestion UTC 기준이다. 미래 시각이면 None. empty queue의 0은 측정된 빈 상태다.
SQLite main/WAL bytes, freelist page 수, source/window 수, 완료 receipt 내 embedded source/window Provenance 수를 측정한다. Provenance는 별도 standalone table 수가 아니다.
disk free는 Queue/Source 경로 파일시스템의 최소 free bytes이다. RSS는 현재 observer process의 Linux resident pages이며 pipeline 전용 메모리를 분리한 수치가 아니다.
관측 JSON digest는 measured_at을 제외한다. threshold에 따른 기본 finding과 overall state를 다시 검증하며 재해시한 false NORMAL 표기를 거부한다.
누락은 UNKNOWN. 알려진 CRITICAL이 있으면 overall CRITICAL이고 UNKNOWN finding은 함께 남긴다. 그 외 UNKNOWN > WARNING > NORMAL 순서다.
이전 같은 binding 관측 대비 Queue/DB/WAL 증가 delta를 기록한다. 증가 자체는 INCREASED 정보이며 임의 증가율 SLO로 심각도를 올리지 않는다.

## 6. 임계값 — 운영 기준이 아닌 예시

| Metric | WARNING 경계 | CRITICAL 경계 |
|---|---:|---:|
| Queue depth | ≥128 | ≥224 |
| oldest pending seconds | ≥300 | ≥900 |
| SQLite main bytes | ≥256 MiB | ≥512 MiB |
| WAL bytes | ≥16 MiB | ≥64 MiB |
| available disk bytes | ≤512 MiB | ≤128 MiB |
| process RSS | ≥512 MiB | ≥1024 MiB |

경계 직전/동일/critical 및 역순 임계값 거부를 검증했다. 실환경 용량·입력률에 맞춰 별도 검토해야 한다. 경고는 자동 삭제/차단/Backpressure 설정 변경 명령이 아니다.
기존 Queue의 bounded capacity/QueueFull 제어만 유지했다. monitor는 실행형 제어를 추가하지 않는다.

## 7. 경보 기록과 실패

기존 MaintenanceLog의 독립 observer chain에 CAPACITY_OBSERVATION 및 NORMAL/WARNING/CRITICAL/UNKNOWN 값을 추가했다. SQL table/schema 및 기존 hash/event 의미는 바꾸지 않았다.
구버전 strict reader는 새 enum을 이해하지 못하면 fail-closed할 수 있다. 기존 운영 DB Migration은 없다. Source/Core Audit Chain을 재작성하지 않았다.
record_capacity는 binding와 observation을 재검증하고 summary digest만 기록한다. observer Commit failure는 전파하며 이벤트 삭제/정상 경보로 대체하지 않는다.
Queue Commit failure에서는 event+cursor rollback, 미저장 event는 DONE 아님을 확인했다. 실제 저디스크는 발생시키지 않았고 sqlite error/low-free metric Fixture를 사용했다.
WAL 측정은 private test SQLite를 WAL mode로 설정하고 실제 파일 bytes와 대조했다. 운영 SQLite mode/OS 설정을 바꾸지 않았다.

## 8. Crash 검증

기존 owned-process harness의 PID/nonce/active_children/writer-lock 검증 helper를 재사용했다. 종료 대상은 test spawn child뿐이다.
| 지점 | 실행 경계 | 결과 |
|---|---|---|
| AP-01 | Manifest의 실제 Source decode 중 | PASS |
| AP-02 | Manifest 생성 완료 후 | PASS |
| AP-03 | capacity의 실제 Queue DB connection read 중 | PASS |
| AP-04 | observer alert Commit 전 | PASS: rollback, 경보 0 |
| AP-05 | observer alert Commit 후 | PASS: 경보 1 유지 |
| AP-06 | 실제 Agent READ 저장 검증 중 | PASS |

신규 강제 종료 6지점 후 Source/Window/Queue/Cursor/read-view/evidence digest가 이전과 같고 Manifest core hash가 재현됐다. 모든 DB integrity_check 및 WRITE Spy 0도 확인했다.
Queue retry 상태 변화·원본/참조 누락·digest 변조·SQLite read failure는 별도 결정적 Fixture 테스트로 확인했다.

## 9. 실제 WSL 관측

실제 경과 **300.59초**, sample **27개**. 새 private Queue/Source/observer DB에서 실제 journal을 읽고 처리했다.
보존 Queue 544건, 지원 인증 이벤트 1건, 생성 Manifest 1개. 대부분 OS 메타데이터는 인증 변환 미지원이며 모델에 넣지 않았다.
실제 지원 record는 기존 sudo/pam_unix 모듈 실패이다. 전체 login/sudo 최종 실패나 공격 사실을 의미하지 않는다. 새 인증 이벤트를 유발하지 않았다.
전체 sample 상태 NORMAL은 위 예시 threshold 범위에 대한 관측이며 운영 준비/안전 보증이 아니다. Window/Provenance 재검증과 Agent READ/WRITE_DENIED도 확인했다.
| Metric | 최초 | 최종 | 샘플 최소 | 샘플 최대 |
|---|---:|---:|---:|---:|
| queue_depth | 0 | 0 | 0 | 0 |
| sqlite_database_bytes | 610304 | 1490944 | 610304 | 1490944 |
| sqlite_wal_bytes | 0 | 0 | 0 | 0 |
| sqlite_freelist_pages | 0 | 0 | 0 | 0 |
| source_record_count | 1 | 1 | 1 | 1 |
| window_record_count | 1 | 1 | 1 | 1 |
| provenance_record_count | 2 | 2 | 2 | 2 |
| available_disk_bytes | 952061255680 | 952148213760 | 952059572224 | 952148664320 |
| rss_memory_mb | 160.77734375 | 162.3046875 | 160.77734375 | 162.3046875 |

샘플은 batch drain 이후의 snapshot이므로 순간 최대 적체/latency가 아니다. Native 수집은 실제 OS, threshold/저디스크/손상/Crash는 Fixture/오류 주입이다. 모델/LLM 추론 및 Archive 실행은 없다.

## 10. 테스트 결과와 수정

전체 관련 집중 실행: 571 passed, 2 failed. 실패는 새 테스트의 json import 누락 및 AP-03 hook이 DONE row만 있는 측정 경로에서 호출되지 않은 테스트 오류였다.
두 테스트를 수정한 최종 신규 집중 실행: **47 passed**(기능 41+Crash 6). 기존 관련 **527개**는 첫 관련 실행에서 모두 통과했다. 중복 실행 숫자를 합산하지 않는다.
최초 Retry metric은 최초 실패 Pending을 놓쳤다. 새 모듈에서 Pending attempts>0/Claimed attempts>1로 수정하고 재검증했다.
UNKNOWN metric의 재해시 false NORMAL 거부, malformed receipt 측정 UNKNOWN도 추가했다. 기존 Guard/테스트를 삭제하거나 skip/xfail로 완화하지 않았다.

## 11. 변경 파일

- 신규 `src/soc_agent/security_ai/operational/archive.py`: Request/Manifest와 read-only 검증.
- 신규 `src/soc_agent/security_ai/operational/capacity.py`: nullable metrics, 예시 thresholds, findings/관측과 observer 기록.
- 수정 `src/soc_agent/security_ai/operational/retention.py`: observer enum 추가. 기존 보호/삭제 거부 규칙 불변.
- 신규 `tests/diagnose_archive_capacity.py`.
- 신규 `tests/integration/archive_capacity/test_archive_capacity.py`.
- 신규 `tests/integration/archive_capacity/test_crash.py`.
- 이 보고서.

## 12. 재현과 증거

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q tests/integration/archive_capacity
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m tests.diagnose_archive_capacity --directory /tmp/NEW_PRIVATE_PATH --seconds 300
```
진단은 새로운 private 경로만 허용하고 기존 파일을 덮어쓰지 않는다. observer DB만 새로 만들며 실제 보안 WRITE·journal 변경·권한 상승을 하지 않는다.
| 증거 | SHA-256 |
|---|---|
| `/tmp/soc-archive-capacity-20261014/results.json` | `f387f36cdab47a6ef6bcdf4b1a153768c11388bac066e22a3e5159a3b7c98f9d` |
| `/tmp/soc-archive-capacity-20261014/samples.jsonl` | `9ee06a8b6ca7a40bb3096453add130ab446c02ebf7205d571a7f4665d991d042` |
| `/tmp/soc-archive-capacity-regression.log` | `6bca9098b89aff6ed91c1d299c9b53b706176990786a238ecce5502191bf407f` |
| `/tmp/soc-archive-capacity-final-focused.log` | `68585ba55b18f597260a707e7371256567dca8a492b927cdd0e73fcd6606592d` |

## 13. 미구현·미검증과 다음 단계

- 실제 Archive executor, 이동/삭제/자동 정리, 승인 발급 미구현. 외부 Evidence 참조 authority가 없으므로 모든 실제 후보는 PROTECTED다.
- READY_FOR_REVIEW/APPROVAL_REQUIRED producer, 승인된 retention 기간, archive 복원/참조 재결합/atomic publication은 별도 다음 계약 단계다.
- 새 monitor는 명시적 API/diagnostic이며 모든 운영 Desktop/Headless service에 자동 활성화하지 않았다.
- Windows/별도 Linux 호스트, 실제 저디스크·운영 WAL 장애·장기 고부하·5분 이상 지속 capacity alert delivery는 별도 검증 필요. 이번 5분은 27회 주기 관측이다.
- Hash는 무결성 연속성이지 OS 진위·서명·approval 증명이 아니다. Python TCB 밖 악성 코드 격리는 별도 OS/process 경계다.
- 지표는 physical count이며 Source/Provenance의 semantic integrity를 대신하지 않는다. Archive/read-view는 별도 기존 검증을 유지한다.
- 다음 권장: cross-store reference authority/사람 검토 UX·approved archive execution 계약, 운영 monitor entrypoint/주기·alert 전달 경로, 플랫폼/부하별 threshold 검증.
- Synthetic v2/v3/Network-DNS NOT_INFERABLE/Agent WRITE_DENIED/Policy/Approval/Decision payload는 유지됐다. Commit/Push·운영 DB Migration·원본 journal 변경 없음.

## 14. 최종 확인

형식이 잘못된 완료 Receipt(`[]`/`{}`)는 Provenance 0건으로 표시하지 않고 해당 측정을 UNKNOWN으로 처리했다. 정상 source receipt는 기존 NativeAuthenticationReceipt 타입으로 검증하고 정상 NOT_INFERABLE 구조만 0건으로 센다.
최종 신규 실행 47 passed, Ruff src/tests PASS, Format 744개 파일 PASS, git diff --check PASS.
기존 status entry 전체와 Source Store/provenance.py/AuthenticationPipeline/Native Collector/READ Investigation의 HEAD 바이트 일치를 확인했다.
보호 파일 tests/fusion_support.py SHA:
`e5f9d10f706f71b82e80261f7633a1504e27ba24499be948d04adb6eeb3a21c9`.
이번 변경은 신규 6개·수정 1개(보고서 포함 7개)다. 기존 사용자 변경은 보존했고 Commit/Push는 하지 않았다.
