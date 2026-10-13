# P1 Authentication Native Log Integration — 2026-10-13

## 판정과 검증 범위

**INCONCLUSIVE**. 읽기 전용 Linux 수집→Queue와 재시작은 검증했다.
실제 sshd 성공/실패 이벤트가 없어 Native 인증 변환·집계는 미검증이다.
Windows Security 접근은 **PERMISSION_DENIED**이며 Windows auth parser 연결은 보류했다.

기준 main/HEAD `3b6a3e067551ce2a3fdfda6ba5af12b549301622`.
시작 Git 상태 `/tmp/soc-auth-native-before.txt`의 사용자 변경 및 미추적 파일을 보존했다.
기존 Source Store, provenance:v3, 합성 v2, Collector/Queue/Core/모델은 변경하지 않았다.
실제 보안 WRITE, Live LLM, 운영 DB Migration, 서비스 활성화/배포, commit/tag/push는 수행하지 않았다.

## 1. 기존 구현 재사용

| 기존 구현 | 재사용 범위 |
|---|---|
| realtime/collectors.py::LinuxJournalCollector | journald 지원 확인, 원본 machine/cursor/UTC metadata parsing |
| 같은 파일 bounded_command | 고정 읽기 전용 명령, batch/output/timeout 제한 |
| WindowsEventCollector | metadata-only 계약 유지; metadata로 성공/실패를 추정하지 않음 |
| realtime/models.py::CommonEvent | SourceIdentity 기반 stable UUID, 원본 시각, source digest |
| realtime/queue.py::EventQueue | SQLite retention/cursor 동일 Transaction, bounded capacity/dedup/retry/poison/claim token/recover |
| operational/source_records.py::AuthenticationSource | 기존 AuthenticationEvent의 성공/실패/시간/계정/출처 계약 |
| operational/source_store.py::OperationalSourceStore | isolated secure SQLite, 5분 창, 지연 quarantine, digest/window 검산, restart |
| authentication/aggregation.py::AuthenticationWindowExtractor | 300초 UTC epoch [start,end) 계정별 count/rate |
| operational/provenance.py::build_receipt | 원본 및 창 연결 검증, DECLARED_UNATTESTED 유지 |
| runtime_lock.py::exclusive_runtime_lock | 실제 진단 프로세스의 수집/recovery/drain 전체 단일 writer lock |

## 2. Linux Collector와 보수적 정규화

신규 `operational/native_authentication.py`:

- LinuxAuthenticationCollector.poll은 auth/authpriv facility 또는 sshd 기록만 읽는다.
  일반 journal 전체 MESSAGE를 수집하지 않는다. 처음 N개를 읽어 tail-N 유실을 피한다.
- 기존 일반 Collector는 MESSAGE를 수집하지 않는 동작 그대로다. 새 제한 auth wrapper만 필요한 MESSAGE를
  짧게 읽으며 기존 bounded_command의 unlinked temporary command buffer를 거친다.
  원문 MESSAGE/username/IP는 downstream Queue/Source Store/보고서에 저장·출력하지 않는다.
- project_journal은 선택한 필드의 canonical digest를 기록하고 원문 메시지를 폐기한다.
  이는 전체 journal binary/file/원문 bytes digest 또는 출처 진위 증명이 아니다.
- 형식 근거: [OpenSSH V_8_9_P1 auth.c::auth_log](https://github.com/openssh/openssh-portable/blob/V_8_9_P1/auth.c).
  정확한 Accepted/Failed + password/publickey/keyboard-interactive/pam 형태만 지원한다.
  Partial/Postponed, PAM session open/close, 잘린/애매한 메시지는 인증 결과로 변환하지 않는다.
- journal-added `_EXE=/usr/sbin/sshd`, `_COMM=sshd`, `_UID=0` 조합을 요구한다.
  SYSLOG_IDENTIFIER 문자열만으로 sshd를 신뢰하지 않는다.
  [systemd v255 journal-fields 원문](https://github.com/systemd/systemd/blob/v255/man/systemd.journal-fields.xml)의
  trusted field와 app field 구분을 참고했다. 웹 man 페이지 접근 실패는 Native 동작 PASS로 계산하지 않았다.
- username은 지원한 문자 형식과 99자 이하만 허용한다. 100자 truncation 가능성을 피해 계정 충돌을 줄인다.
  다른 daemon/path/sshd-session/형식은 자동 변환하지 않는다.
- 원본 machine/cursor/Event UUID/발생 시각을 보존한다. unsigned microsecond timestamp→UTC이며
  문자열 날짜/음수/불명확한 timezone을 추정하지 않는다. 여기의 시각은 journal entry의
  __REALTIME_TIMESTAMP이며 별도 인증 시도 시각/원천 clock의 정확성을 증명하지 않는다.
- 계정은 machine+시도된 username의 stable digest, 출처는 machine+검증된 canonical IP digest로
  pseudonymization한다. original projection digest는 원문 표현을 포함한다.
- Failed username은 시도된 계정 assertion이며 계정 존재/공격/로그인 사실을 확정하지 않는다.
- parser를 직접 호출하거나 JSON을 재생한 것은 Native origin의 증명이 아니다.
  Source assurance는 DECLARED_UNATTESTED, 모든 receipt는 NOT_INFERABLE/WRITE_DENIED를 유지한다.

## 3. 실제 WSL 수집과 별도 프로세스 재시작

환경: systemd `255 (255.4-1ubuntu8.17)`, journald socket/read 접근 확인.
sshd 대상으로 읽은 probe는 0건이며 openssh-server 설치 버전도 확인되지 않았다.
인증 facility에는 passwd/sudo/cron 기록이 존재한다. session/일반 메시지를 로그인 성공으로 간주하지 않았다.
sshd 설치/활성화, sudo/인증 실패 유도, logger 시험 이벤트 주입은 하지 않았다.

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m tests.diagnose_native_authentication \
  --directory /tmp/soc-native-auth-20261013-run1 \
  --incident 00000000-0000-0000-0000-000000000049 --limit 8
# 종료한 뒤 별도 프로세스로 재시작
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m tests.diagnose_native_authentication \
  --directory /tmp/soc-native-auth-20261013-run1 \
  --incident 00000000-0000-0000-0000-000000000049 --limit 8 --resume
```

| 실제 실행 | collected | NOT_INFERABLE | mapped auth | windows | Queue DONE | cursor |
|---|---:|---:|---:|---:|---:|---|
| 첫 실행 | 8 | 8 | 0 | 0 | 8 | retained |
| 별도 프로세스 resume | 추가 8 | 8 | 0 | 0 | 16 | retained |
| 최종 timestamp 검사 변경 후 limit=1 resume | 추가 1 | 1 | 0 | 0 | 17 | retained |

증거: `/tmp/soc-auth-native-linux-first.log`, `soc-auth-native-linux-resume.log`, `soc-auth-native-linux-final.log`.
17건의 실제 OS 관련 기록은 보존됐지만 17건의 인증 성공/실패 검증이라고 표현하지 않는다.
WSL 검증을 별도 Linux Desktop/Headless 운영 호스트 검증으로 대체하지 않는다.

## 4. Windows 조사 및 실제 권한 검사

Native PowerShell을 WSL interop으로 실행했다. 샌드박스 socket 제한에 대해 승인된 sandbox 외 실행을
사용했지만 Windows 관리자 권한 상승은 없었다. stdin 방식 두 번의 출력 없는 시도는 검증 성공으로
처리하지 않았고, EncodedCommand 방식으로 바꿔 실제 결과를 확인했다.

최종 `python3 /tmp/soc-run-auth-probe.py`는 고정 read-only script를 Native PowerShell에 전달했다.
응답 **PERMISSION_DENIED**, native return code 0 (진단 코드가 거부 상태를 JSON으로 반환).
이는 Security 읽기 PASS가 아니다. 원시 stderr 및 개인 계정 정보를 출력하지 않았다.

공식 계약 조사:

| Event ID | 문서 의미 | 처리 원칙 |
|---|---|---|
| 4624 | 로그인 성공 | 실제 Security/provider/version/target account/time/record 확인 후만 정규화 |
| 4625 | 로그인 실패 | 같은 확인 필요. 불명확한 SID에서 계정 존재를 추정하지 않음 |
| 4634 | 로그오프 | 로그인 success/failure count로 변환하지 않음 |

근거: [Microsoft 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624),
[4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625),
[4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634).

실제 Security EventData 구조는 권한 거부 때문에 확인하지 못했다.
따라서 **Windows 인증 parser/collector 연결은 구현 보류**다. System metadata fallback,
ACL/audit 정책 변경, 권한 상승, Security log 삭제, 실제 로그인 시도는 하지 않았다.

다음 확인은 이미 Security 읽기가 허용된 사용자로 Native PowerShell에서 수행한다.
아래 명령은 권한을 발급하거나 접근 거부를 우회하지 않는다.

```powershell
Get-WinEvent -LogName Security `
  -FilterXPath '*[System[(EventID=4624 or EventID=4625 or EventID=4634)]]' `
  -MaxEvents 3 -ErrorAction Stop |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    [pscustomobject]@{
      EventID = $_.Id
      Provider = $_.ProviderName
      Channel = $_.LogName
      Version = [string]$x.Event.System.Version
      FieldNames = @($x.Event.EventData.Data | ForEach-Object { $_.Name })
    }
  }
```

## 5. 운영 저장·창 집계·Provenance 연결

신규 AuthenticationPipeline은 기존 isolated EventQueue/OperationalSourceStore를 사용한다.
Queue companion native_auth_binding 테이블은 queue store ID/source store ID/Incident/collector를 고정하고
다른 Incident/Store 재사용을 거부한다. 비어 있지 않은 unbound Queue를 자동 채택하지 않는다.
Incident는 로컬 staging association이며 Core Incident Evidence 검증/실제 사건 연관성의 증명이 아니다.

```text
read-only journal → minimized CommonEvent (original projection hash)
→ durable queue + cursor commit
→ reviewed AuthenticationEvent 또는 NOT_INFERABLE
→ Source Store atomic source/watermark/window transaction
→ provenance:v3 source receipt + authentication window receipt
→ queue acknowledgement (기존 허용 outcome 필드)
```

- Queue/cursor commit은 기존 단일 Transaction. 처리 전 cursor가 이동해도 입력은 durable Queue에 남는다.
- Source Store commit과 Queue acknowledgement는 별도 Transaction이다.
  **at-least-once replay + stable source dedup**로 집계 중복을 막는다.
  cross-database atomicity/exactly-once를 주장하지 않는다.
- Source commit 후 ack 전에 프로세스가 중단되는 상태를 Fixture·실제 SQLite로 재현했다.
  단일 writer recover/replay 후 duplicate=true 및 window count=1을 확인했다.
- queue finish는 기존 permitted keys (inference/incident_id/workflow/human_boundary)를 사용한다.
  workflow의 receipt/digest는 이 전용 auth diagnostic Queue 결과이며 SOCRuntime Assessment 실행을 의미하지 않는다.
- finite retry/poison/capacity, cursor integrity, Source Store 창 coverage/digest 재계산 검증은 유지한다.
- NativeAuthenticationReceipt는 원본 projection hash, CommonEvent digest, AuthenticationSource digest와
  source/window provenance를 연결한다. 원본 Source Store 행을 다시 조회해 기존 build_receipt를 호출한다.
- digest는 진위 서명이 아니다. root/journal 변조나 프로세스 내 악성 Python 코드에 대한 완전한 격리가 아니다.
- diagnostic은 전용 private directory/exclusive_runtime_lock을 전체 lifetime 동안 유지한다.
  recover API 직접 호출은 단일 writer 소유권 전제다. 운영 DB를 테스트 DB로 자동 채택하지 않는다.

## 6. 테스트·보안 경계

기존 v2/v3와 Policy/Approval/Execution Guard는 불변이다.
Collector/parser/worker는 모델/LLM/Tool Action을 실행하지 않고 승인·Capability를 발급하지 않는다.
PAM session이나 모델 예측을 관측된 로그인 성공·공격 사실로 승격하지 않는다.

신규 테스트는 OpenSSH text **Fixture** + 실제 isolated SQLite/Queue다.
Native 성공/실패 기록을 사용한 테스트와 구분한다.

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest -q \
  tests/unit/operational_features tests/unit/realtime \
  tests/unit/security_ai/authentication tests/unit/security_ai/external \
  tests/unit/external_context \
  tests/integration/external_read_only_backend/test_guard.py \
  tests/unit/policy tests/unit/approval
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check .
git diff --check
```

신규 auth 25개 포함 **471 passed, 0 failed**, 34.74초.
로그 `/tmp/soc-auth-native-regression.log`.
초기 1개 실패는 테스트 stub이 LinuxJournalCollector 전체를 lambda로 바꿔 실제 parse까지 제거한 오류였다.
명령 object만 stub으로 바꾸고 실제 parser/cursor guard를 유지해 22 passed를 확인했다.
이후 3개 테스트를 추가한 최종 471개 결과와 합산하지 않는다. skip/xfail/테스트 삭제는 없다.

검증: Accepted/Failed, 필수 identity/time, partial/애매한 메시지/PAM session/injection 거부,
SYSLOG_IDENTIFIER 위조, UTC 정규화, 원문/cursor reuse 변조, Incident/Store binding,
중복·역순·지연·quarantine·창 경계, SQLite reopen, crash replay, QueueFull 시 cursor 불변.
기존 Network/DNS input, provenance:v3, 합성 v2, 인증/Queue, 실제 Read-only Guard/Policy/Approval 회귀도 통과했다.
전체 회귀/Windows suite/별도 Linux 호스트/모델 추론은 이번에 실행하지 않았다.

## 7. 변경 및 보존

모두 신규 파일:

1. src/soc_agent/security_ai/operational/native_authentication.py
2. src/soc_agent/security_ai/operational/authentication_pipeline.py
3. tests/unit/operational_features/test_native_authentication.py
4. tests/diagnose_native_authentication.py
5. docs/gate-dg-operational-pipeline/authentication-native.md

기존 Collector/Queue/OperationalSourceStore/provenance.py는 HEAD와 내용이 같다.
기존 통합 manifest 33/33, realtime manifest 16/16 SHA 일치.
보호 tests/fusion_support.py SHA
`e5f9d10f706f71b82e80261f7633a1504e27ba24499be948d04adb6eeb3a21c9` 유지.
Ruff src/tests PASS, Format 전체 PASS, git diff --check PASS.

## 8. 남은 차단 사항

- 실제 sshd 성공/실패 기록 미확보: 정상 권한으로 읽을 수 있는 실기기/기존 기록과 producer version 필요.
- Windows Security 권한 거부: 허용된 읽기 사용자·실제 필드 구조 확보 후만 Windows parser 구현.
- sudo/PAM/cron, sshd-session, 다른 distro/path/문자 형식은 현재 NOT_INFERABLE.
- Core Incident 실제 연결, collector attestation, retention/archival, 부하·별도 Linux 호스트 운영 검증 미완료.
- 실제 인증 AI/Agent Assessment/response 연결은 이번 범위에서 미실행.

단위/SQLite 회귀 PASS와 Native 인증 정규화 미검증을 별도로 유지한다.
