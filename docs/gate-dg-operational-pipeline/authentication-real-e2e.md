# P1 Native Authentication Real-World E2E — 2026-10-14

## 판정

- **REAL_OS_VERIFIED: WSL의 기존 sudo/pam_unix 모듈 인증 실패 1건 → READ-only 저장 조사 경로 한정.**
- **전체 Autonomous LLM Agent/Windows/실제 성공 이벤트 E2E: INCONCLUSIVE.**
- Network/DNS 및 인증 모델 추론은 실행하지 않았고 NOT_INFERABLE/WRITE_DENIED를 유지했다.

기준 브랜치 main, commit `7b1c20f`. 시작 Git 상태 `/tmp/soc-auth-real-before.txt` 기록.
실제 로그인/실패 반복, SSH 설치·활성화, sudo 실행, audit 정책/권한 변경, 운영 DB Migration,
Live LLM, commit/tag/push는 수행하지 않았다. 이미 보관된 journal을 읽었으며 새로운 인증 이벤트를 만들지 않았다.

## 1. 기존 구조와 최소 변경

기존 Native Collector→EventQueue→AuthenticationPipeline→Source Store→5분 집계→provenance:v3를 재사용했다.
ToolRegistry/Tool/PolicyEngine/ApprovalManager/GovernedExecutor/InvestigationOrchestrator도 기존 구현을 사용했다.
새 Orchestrator·Policy·Approval·모델·DB 저장소를 만들지 않았다.

```text
bounded read-only journald
 → minimized CommonEvent + canonical selected-field digest
 → existing persistent queue/cursor
 → pure AuthenticationSource conversion
 → existing OperationalSourceStore/window
 → existing provenance:v3 revalidation
 → read_authentication_context Tool
 → existing governed InvestigationOrchestrator (one deterministic read step)
```

핵심 변경:

- native_authentication.py: 기존 변환을 순수 authentication_source()로 분리해 저장/조회 양쪽에서 재사용.
  명시적 opt-in PAM failure parser 추가. 기존 project_journal()/Collector 기본 OpenSSH 동작은 유지.
- authentication_pipeline.py: opt-in collector identity를 별도로 bound하고,
  collect/step에서 binding과 event collector의 일치를 강제.
- authentication_investigation.py: 실제 저장 원본·Queue receipt·Window·provenance를 다시 대조한 READ view,
  단일 READ Tool, 기존 ToolGuard protocol adapter, 기존 Orchestrator 연결.
- 새로운 Core Assessment/Decision/Action 연결은 하지 않았다. 기존 InvestigationResult/Evidence 타입도 변경하지 않았다.
  결과는 저장 자료 조회의 Evidence이며 모델 추론·공격 확정·실제 사건 연관성 승인으로 승격하지 않는다.

## 2. 실제 Linux 이벤트 확보와 의미

첫 읽기 전용 조사: auth/authpriv/sshd 기록 256건, 지원 OpenSSH 변환 0건, 별도 sshd 조회도 0건.
추가 원문을 출력하지 않는 분류 조사: session 메시지 182건, 인증 실패 문구 1건, 기타 73건.
문구 존재만으로 변환하지 않았고 해당 1건의 원본 구조와 Producer를 대조했다.

실제 구조는 **pam_unix(sudo:auth)의 authentication failure**로 명시됐으며,
logname/uid/euid/tty/ruser/rhost/user 필드와 prefix/공백 형태를 확인했다.
사용자·IP·host/cursor의 원문 값은 보고서/콘솔에 출력하지 않았다.
확인한 producer: `/usr/bin/sudo`, kernel-added _COMM은 sudo,
logged uid와 journal _UID가 같고 logged euid=0, rhost는 비어 있다.

로컬 libpam-modules 버전: **1.5.3-5ubuntu5.7**.
[Linux-PAM v1.5.3 support.c::_unix_verify_password](https://github.com/linux-pam/linux-pam/blob/v1.5.3/modules/pam_unix/support.c)는
성공하지 않은 모듈 검증에서 해당 failure 형식을 기록한다. 실제 문자열/필드가 그 형식과 맞는지 확인했다.
Ubuntu patch 전체와 배포 바이너리의 source parity 또는 진위 서명을 증명했다고 주장하지 않는다.

**해석 한계:** pam_unix 모듈 인증 시도의 실패이며 전체 PAM stack/최종 sudo 실행/최종 로그인 결과는 아니다.
이후 다른 module/재시도에서 성공했는지 추정하지 않는다. PAM session opened를 인증 성공으로 변환하지 않는다.
모듈별 시도를 login 총계나 공격 확정으로 확대 해석하지 않도록 Tool limitations에 기록했다.

### 명시적 opt-in과 v1 호환

- 기본 collector identity: linux:journal:authentication:v1, event collector journald-auth:v1 (기존 유지).
- opt-in identity: linux:journal:authentication:pam-failure:v1,
  event collector journald-auth-pam-failure:v1, parser pam-unix-sudo-auth-failure:v1.
- include_pam_failures=True는 trusted setup/CLI의 명시적 옵션이다.
  별도 Queue/Source Store를 사용하며 기존 v1 Queue를 조용히 재해석하지 않는다.
- 정확한 sudo:auth prefix, 필드 순서·공백, local rhost, 필수 user,
  _EXE/_COMM 및 logged UID=journal UID를 요구한다. Sudo setuid 특성 때문에 journal real UID는 root가 아닐 수 있다.
  기존 SSH의 root UID 조건은 완화하지 않았다.
- 잘못된/누락 필드, 다른 프로그램, 다른 UID/euid, session 메시지, remote rhost,
  extra instruction/다른 형식은 NOT_INFERABLE. PAM profile의 success 위조도 거부한다.
- sudo/pam_unix 계정은 service-scoped digest로 식별하여 같은 이름의 SSH 관측과 자동 병합하지 않는다.

실제 원본 projection digest:
`3770c878b41cf3587bcf1e1dd9cb90773172aad257249a2da37c29db3fee37bc`.
선택한 원본 필드의 canonical digest이며 전체 journal binary, exact auth attempt clock,
원본 진위 또는 AI 학습 정합성의 증명이 아니다.

## 3. 실제 데이터 단계별 통과 건수

검증된 격리 실행 (`/tmp/soc-auth-real-native-verified.json.log`):

| 지표 | 실제 건수 |
|---|---:|
| native_records_collected | 65 (첫 64건 + 재시작 후 다음 1건) |
| queue_records_persisted | 65 |
| authentication_events_verified | 1 (위 PAM 모듈 실패) |
| authentication_events_rejected | 0 |
| authentication_events_unsupported | 64 |
| authentication_windows | 1 |
| provenance_receipts | 1 |
| WRITE spy calls | 0 |

READ view의 verified는 원본/저장/정규화 연결을 검사한 record 수이며
Source assurance를 cryptographically VERIFIED로 바꾸는 뜻이 아니다.
65건 수집 성공을 65건 인증 성공으로 표현하지 않는다.

실제 Window: total=1, failed=1, succeeded=0, failure_rate=1.0, login_attempt_rate=1/300.
기존 300초 UTC epoch [start,end) 계산을 사용했다.
발생 시각은 journal __REALTIME_TIMESTAMP를 보존한 UTC journal entry 시각이며 실제 시도 시작 순간을 확정하지 않는다.

| Stage | Real OS | Fixture | Status |
|---|---|---|---|
| Native Collection | 기존 기록 65건, PAM 실패 원본 1건 | reviewed 문자열 fixtures | REAL_OS_VERIFIED (WSL) |
| Persistent Queue | 65건, 원본 연결·중복 native 재수집 확인 | capacity/digest/retry/CAS | REAL_OS_VERIFIED |
| AuthenticationEvent | PAM 모듈 failure 1건 | SSH success/failure/PAM failure | REAL_OS_VERIFIED (failure scope) |
| Source Store | 실패 원본 1건 재조회 | source/incident/tamper/reopen | REAL_OS_VERIFIED |
| 5-minute Window | 1개, 실패 1건 | success/failure/역순/지연 | REAL_OS_VERIFIED |
| Provenance v3 | 창 receipt 1개 재검증 | 누락·변조·재해시 공격 | REAL_OS_VERIFIED (chain only) |
| Agent READ-only | 실제 DB 조회 및 기존 Orchestrator read step 완료 | 실제 Policy/Approval/Tool boundaries | REAL_OS_VERIFIED (no LLM) |
| 실제 성공 이벤트 | 미확보 | FIXTURE_VERIFIED | INCONCLUSIVE |
| Windows | 이전 Native probe PERMISSION_DENIED 재사용 | 기존 회귀 | BLOCKED (access) |
| LLM autonomous investigation | 미실행 | deterministic read plan만 검증 | INCONCLUSIVE |

## 4. Queue/Store/Window/Provenance 재개

검증한 실제 데이터 경로:

1. 동일 native record 재수집: Queue dedup으로 cursor를 뒤로 이동시키지 않고 중복 제외.
2. 실제 PAM 실패를 native 재수집 후 Source Store에 다시 전달: admission.duplicate=true, count 증가 없음.
3. Worker 중단 상태: 실제 record를 CLAIMED로 남기고 DB reopen, token/상태 보존 확인 후 recover.
4. 실제 PAM Source commit 후 Queue ack 전에 중단: 다시 DB reopen/recover/step하여 duplicate=true 확인.
   프로세스 SIGKILL은 실행하지 않았다. 저장 경계에서 중단 상태를 만들어 재처리했다.
5. Source/Window/Provenance 저장 후 DB reopen: READ view 일치.
6. 별도 진단 프로세스로 --resume 실행: 실제 window/source/provenance 1개 그대로 재조회.
   이후 추가 미지원 2건으로 Queue 총계 67, unsupported 66, auth 1/window 1/provenance 1 유지.

기존 Queue commit은 durable event와 cursor 단일 Transaction이다.
Source Store commit과 Queue ack는 서로 다른 Transaction이며 **at-least-once + dedup**이다.
exactly-once/cross-DB atomicity를 주장하지 않는다. 진단은 기존 exclusive_runtime_lock을 전체 lifecycle에 유지한다.

Source Store와 provenance:v3는 수정하지 않았다. source assurance는 계속 DECLARED_UNATTESTED,
provenance는 source chain 및 계산 근거 검증이며 모델 입력 권한·Source attestation은 아니다.

## 5. Agent READ-only Tool 경계

실제 기존 InvestigationOrchestrator/GovernedExecutor/PolicyEngine/ApprovalManager/ToolRegistry를 실행했다.
동적 LLM plan 대신 deterministic one-step read plan이다. 실제 LLM 호출을 하지 않았다.

Tool 출력 (새 standalone soc-authentication-read-view:v1):
incident_id, source_reference (digest만), authentication_window, evidence_digest,
provenance_reference (receipt digest), investigation_summary, limitations,
inference_status=NOT_INFERABLE, action_policy=WRITE_DENIED.
Window에 pseudonymous account reference/count/rate를 넣고 실제 username/IP/host/cursor는 노출하지 않는다.

조회 전 검사:

- Queue/Source Store/Incident/collector binding
- Queue event digest와 saved native receipt digest/ID/원본 projection digest
- 실제 Source Store 원본을 pure authentication_source()로 Queue projection에서 재생성하여 비교
- source receipt와 source digest의 연결, 필수 원본 누락 거부
- 기존 Store의 Window coverage/수치/provenance 검산, build_receipt() 재조회
- READ view evidence digest pin, 다른 Incident 요청 거부

ToolGuard protocol adapter는 한 개 READ Tool과 Incident만 허용하고,
ActionProposal 직접 호출·Alias/다른 Tool·WRITE 등록/직접 호출을 실행 경계에서 거부한다.
유효한 test Approval이 있어도 WRITE 거부 테스트를 통과했다.
실제 Native 진단에서도 inert WRITE Spy를 같은 guard로 직접 요청해 거부되었고 spy 호출은 0이다.

이는 이 전용 read adapter의 보호 범위다. 전체 SOC backend 재설계나 모든 Python 악성 코드 격리를 주장하지 않는다.
내부 Python adapter는 TCB이며 프로세스/OS 격리를 대체하지 않는다.
Core IncidentState는 명시적인 staging Incident ID의 격리된 read investigation 상태다.
운영 Core Incident correlation/Assessment/Decision/response를 실행하거나 재정의하지 않았다.

## 6. 실제/Fixture 시나리오 구분

| 시나리오 | 실제 검증 | Fixture/회귀 |
|---|---|---|
| Linux auth success | 미확보 | SSH success mapping PASS |
| Linux auth failure | 기존 PAM module failure PASS | SSH/PAM failure PASS |
| 동일 인증 이벤트 중복 | native failure 재수집 PASS | PASS |
| Collector restart | cursor content validation 및 별도 process resume PASS | PASS |
| Worker 중단·재처리 | 실제 실패 source-commit/ack 경계 replay PASS | CAS/retry/rollback PASS |
| 원본/Receipt digest 변조 | 진짜 journal은 변경하지 않음 | isolated SQLite 변조/재해시 거부 PASS |
| Incident 불일치 | 운영 사건에 시도하지 않음 | binding 및 직접 Action/Tool 거부 PASS |
| 지연/역순 | actual sample 부족 | quarantine 및 창 총계 분리 PASS |
| Window 조회 | 실제 1개 PASS | PASS |
| Agent READ investigation | 실제 저장 데이터/기존 Orchestrator PASS | PASS |
| WRITE 차단 | 실제 진단 inert spy 0 PASS | Approval/alias/direct bypass 거부 PASS |
| Windows access denied | 이전 Native PERMISSION_DENIED 증거 재사용, 새 접근 안 함 | 실제 인증 변환 미실행 |

Windows 읽기 권한을 우회하지 않았고 기존 Security/audit 정책은 변경하지 않았다.

## 7. 테스트·정적 검사

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q \
  tests/unit/operational_features tests/unit/realtime \
  tests/unit/security_ai/authentication tests/unit/security_ai/external \
  tests/unit/external_context tests/unit/investigation tests/unit/tools \
  tests/integration/external_read_only_backend/test_guard.py \
  tests/unit/policy tests/unit/approval
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check .
git diff --check
```

최종 집중·보안 회귀 **586 passed, 0 failed**, 38.19초.
신규 READ investigation 13개 + PAM parser 11개 = 24개를 포함한다.
로그 `/tmp/soc-auth-real-regression-final.log`. 이전 575개 실행과 합산하지 않는다.
전체 회귀/실제 모델/Live LLM/Windows suite는 이번에 실행하지 않았다.

초기 진단에서 restart 시 opt-in collector identity를 전달하지 않아 binding mismatch로 거부됐다.
Guard를 완화하지 않고 진단에 올바른 binding과 명시적 resume을 전달했다.
이미 저장된 64건이 보존되어 재개로 복구됨을 확인했고 최종 새 격리 실행에서도 재검증했다.
초기 테스트의 없는 ApprovalManager.request 호출은 실제 create API로 수정했다.
실패를 skip/xfail로 바꾸거나 기존 검증을 삭제하지 않았다.

정적 검사/무결성 최종 결과는 아래 마지막 확인에 기록한다.

## 8. 변경 파일

수정:
- src/soc_agent/security_ai/operational/native_authentication.py (pure conversion, explicit PAM opt-in)
- src/soc_agent/security_ai/operational/authentication_pipeline.py (collector identity binding)
- tests/unit/operational_features/test_native_authentication.py (command stub의 새 옵션 필드)

신규:
- src/soc_agent/security_ai/operational/authentication_investigation.py
- tests/unit/operational_features/test_authentication_investigation.py
- tests/unit/operational_features/test_pam_authentication.py
- tests/diagnose_authentication_real_e2e.py
- docs/gate-dg-operational-pipeline/authentication-real-e2e.md

README.md/docs/soc-command-center.md/pyproject.toml의 기존 사용자 수정 및 기존 미추적 파일은 보존했다.

## 9. 재현 명령과 한계

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m tests.diagnose_authentication_real_e2e \
  --directory /tmp/soc-auth-real-e2e-20261014-pam-verified \
  --incident 00000000-0000-0000-0000-000000000053 \
  --limit 64 --include-pam-failures
# 별도 프로세스 재개; 기존 Queue/Data 보호
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m tests.diagnose_authentication_real_e2e \
  --directory /tmp/soc-auth-real-e2e-20261014-pam-verified \
  --incident 00000000-0000-0000-0000-000000000053 \
  --limit 1 --include-pam-failures --resume
```

첫 명령은 실행 당시 새 경로였다. 현재는 기존 경로를 덮어쓰지 않으며 재현하려면 새로운 private 경로를 선택한다.
진단 JSON은 보수적으로 aggregate status=INCONCLUSIVE를 유지한다.
위 report의 REAL_OS_VERIFIED는 실제 실패→READ-only data path의 수동 증거 검토에 대한 한정 판정이다.
실제 성공/Windows/LLM E2E 전체 PASS로 해석하지 않는다.

추가 자료/검증: 읽기 가능한 실제 성공 로그, 승인된 Windows Security 접근 및 원본 EventData,
별도 Linux 호스트, operational Incident association/attestation, Live LLM 없는 현재 범위와
별도 LLM 조사 연결 검증, 장시간 부하/retention 및 실제 강제 종료 recovery.
Network/DNS Feature Producer·Golden Pair 차단은 이번 결과로 해결되지 않는다.

## 10. 최종 정적 검사와 보존 확인

Ruff src/tests PASS, format --check 전체 728개 파일 PASS, git diff --check PASS.
기존 최종 통합 Manifest 33/33, realtime Windows Manifest 16/16 SHA 일치.
Source Store 및 provenance.py는 HEAD와 바이트 단위로 동일하다.
보호 파일 tests/fusion_support.py SHA는
`e5f9d10f706f71b82e80261f7633a1504e27ba24499be948d04adb6eeb3a21c9`로 유지됐다.
이번 변경은 수정 3개·신규 5개이며 기존 사용자 수정 3개와 기존 미추적 파일은 유지했다.
전체 회귀·Windows Native 재실행 없이 관련 회귀 586 passed 증거를 사용했다.
Git commit/push 및 실제 대응 Handler 실행은 수행하지 않았다.
