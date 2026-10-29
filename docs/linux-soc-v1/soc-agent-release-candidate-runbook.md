# SOC Agent Release Candidate 운영·복구 Runbook

이 절차는 일반 사용자 Replay/보존 결과 시연과, 별도 권한 계약이 필요한 Native Collector를
구분한다. GUI는 Root로 실행하지 않는다. GUI 종료는 독립 서비스의 Stop이 아니다.
실제 검증 범위·Git·SHA·제한은 [RC 보고서](soc-agent-release-candidate-report.md)를 따른다.
2026-10-29 중단 후 재개한 비권한 사전 검증과 1시간 시험의 미승인 Scope는
[운영 검증 보고서](soc-agent-operations-verification-report.md)에 정리했다.
현재 설치의240초 제한과 봉인 이후 exact 모델 Action 승인은 계속 유효한 경계다.

## 모드와 프로세스 소유권

| 모드 | 입력과 실행 | 권한 |
|---|---|---|
| OFFLINE | 저장 입력 한 번 분석, 검증된 보고서 열기 | 일반 사용자. Native 보존 벡터는 별도 exact model Action 필요 |
| CONTINUOUS / PCAP_REPLAY | 고정 SHA의 기존 PCAP을 읽어 Queue·Feature·AI 처리. EOF 후 자동 반복하지 않음 | 일반 사용자, 실제 Capture 아님 |
| CONTINUOUS / JSONL_REPLAY | 저장 Packet/DNS/Auth/Fixture 이벤트, 커서·중복·품질 검증 | 일반 사용자, Host 로그 수집 아님 |
| CONTINUOUS / NATIVE_SERVICE | 승인된 Root 서비스의 인증 Unix transport만 수신 | 설치/Namespace/Interface/자원/시간/위험 승인 필요. 기존 Diagnostic 승인 재사용 금지 |
| DIAGNOSTIC | 기존 Phase D 제한 진단 | 기존 SHA/Scope/R1/R2/Root/Native 계약 유지 |

Root Collector와 ordinary AI Runtime/GUI는 분리된다. Kernel 재시작을 활성화하지 않는다.
Worker circuit reset은 실패 입력의 자동 Replay나 새로운 Native 모델 승인 발급이 아니다.
`worker_observed_unix`는 supervisor가 Worker task를 관측한 시각이며 모델의 진행률/성공 증거가 아니다.
`collector_message_unix`는 인증된 Root 메시지 수신 시각이다. 재연결 때 과거 값을 지운다.

## 일반 사용자 시작·중지·결과 확인

검증된 프로젝트/기존 Python 환경에서 실행한다. 아래 경로는 새 private directory여야 한다.
설치된 RC wheel을 사용하거나 checkout의 `src`를 명시한다. 실행 중 Source를 교체하지 않는다.

```bash
export PYTHONPATH="$PWD/src"
SOC_CLI_PY=/home/geonug/kdt-linux/autonomous-soc-agent/.venv/bin/python
"$SOC_CLI_PY" -m soc_agent.cli continuous init /absolute/new-runtime --config /absolute/replay-config.json
"$SOC_CLI_PY" -m soc_agent.cli continuous start /absolute/new-runtime
"$SOC_CLI_PY" -m soc_agent.cli continuous status /absolute/new-runtime
"$SOC_CLI_PY" -m soc_agent.cli gui --continuous-runtime /absolute/new-runtime
"$SOC_CLI_PY" -m soc_agent.cli continuous stop /absolute/new-runtime
"$SOC_CLI_PY" -m soc_agent.cli continuous status /absolute/new-runtime
```

설정 파일에는 `source`, `input_file` 절대 경로, 프로그램이 계산한 `input_sha256`, 기존 ML root를
사용한다. 새 키·모델·환경을 GUI가 설치하거나 탐색하지 않는다. `start`의 Heartbeat 확인과
`stop`의 REQUESTED 응답은 각각 모델 성공이나 Cleanup 완료를 의미하지 않는다.
최종 상태·Queue·Audit·`cleanup`을 확인한다. Native에서는 `collector_cleanup`과 STOP ACK도
별도로 확인한다. 서비스 손실/오래된 Heartbeat는 UNKNOWN이며 LIVE 표시를 취소한다.

GUI의 Continuous 화면에서 Attach/Start/Stop, Queue·Drop·Eligibility·Worker·Incident를 확인한다.
Dashboard/System에도 별도 Continuous 요약이 표시된다. Incident를 선택해 AI Analysis의
Incident/Investigation/Evidence·Audit 탭을 연다. 저장 Native 결과는 RETAINED_NATIVE이며
현재 LIVE 수집이 아니다. 보존 결과를 여는 명령은 새 추론/Capture/API를 실행하지 않는다.

```bash
"$SOC_CLI_PY" -m soc_agent.cli gui --analysis-result /absolute/verified-result-directory
```

## 설치·업데이트·Rollback

1. Source manifest, wheel 파일 SHA, Native 파일 SHA, canonical 모델 manifest digest와 물리 파일
   SHA를 각각 확인한다. 모델 manifest의 canonical digest를 JSON 파일 바이트 SHA와 혼동하지 않는다.
2. 업데이트 전 ordinary Runtime을 명시적으로 Stop/Drain하고 결과와 Queue·Audit를 보존한다.
   GUI만 닫아서는 서비스가 중지되지 않는다. Native Root 서비스는 별도 승인/소유권 절차를 따른다.
3. 새 RC는 별도 일반 사용자 환경/새 Runtime directory에서 검증한다. 기존 실행의 `code-identity`를
   덮어써 변경을 허용하지 않는다. 실행 중 editable Source 교체는 금지한다.
4. 이번 RC의 BPF/Provider/Root service/policy/unit은 이전 성공 시험과 동일하다. 이번 작업에서는
   Root 설치/서비스 변경을 하지 않았다. 향후 Root 변경은 정확한 파일 manifest·새 인간 승인·
   사용자 Scope 확인·터미널 sudo 인증으로만 집행한다. 범용 Root 명령 실행 경로는 없다.
5. Rollback은 검증된 이전 wheel/Source와 Root 소유 백업을 각각 사용한다. 일반 사용자 경로는
   새로운 환경으로 되돌리고 기존 증거를 유지한다. Root 파일 복원도 설치와 같은 승인 경계를 따른다.
6. Replay archive만 별도 새 directory로 restore할 수 있다. Native archive restore를 Replay 권한으로
   활성화하지 않는다. 변경된 Artifact에 과거 모델/Root/Native 영수증을 재사용하지 않는다.

## 장애·복구

| 현상 | 확인 및 처리 |
|---|---|
| 오래된 Heartbeat | 마지막 Collector/Worker 관측은 보존하되 현재 LIVE/정리 성공으로 간주하지 않는다. 소유 PID/자식/감사 증거를 먼저 조사 |
| Worker 종료/모델 실패 | Collector/Queue는 유지, 실패 job은 POISON·최초 오류/Audit 보존. 원인 수정 후 명시적 `reset-worker`; 다음 독립 job만 처리. 실패 job 자동 재실행 없음 |
| Collector 종료/불량 Clock·Counter | DEGRADED/CIRCUIT 및 품질 차단 확인. 부분 Window를 적격 승격하지 않음. 승인 없는 실제 Kernel restart 없음 |
| Queue Full | Drop/거부·보존 입력·Queue 상태를 확인. 조용히 버리거나 용량을 임의 확대하지 않음 |
| ENOSPC/저장 quota | 실패 전 cursor가 게시되지 않았는지 확인. Source/Queue/Audit와 `.pending-*` 증거 보존. 별도 저장 공간·보존 정책 검토 후 복구 |
| Checkpoint/Segment/Audit 손상 | 자동 초기화/삭제/재작성 금지. 검증된 archive를 새 Replay directory로 복원; 원본은 조사용 보존 |
| LLM/API timeout/불량 plan | 전송 intent·오류/호출 수 보존, 임의 Shell/알 수 없는 도구 거부. 모델 점수를 사실로 승격하지 않음. 자동 유료 재시도 없음 |
| Cleanup UNVERIFIED | 후속 Start 차단. 마지막 실패가 두 번째 close 성공에 가려지지 않음. 소유 자원·자식 종료/ACK를 조사하고 별도 복구 판단 |
| Source identity 변경 | 기존 Runtime의 code pin을 수정하지 않음. 새 검증된 Artifact와 새 directory/필요한 승인으로 진행 |

모든 진단 결과에서 첫 오류와 후속 Cleanup 오류를 구분한다. 과거 FAILED/false/UNKNOWN을
성공으로 변경하지 않는다. 알려진 `FEATURE_EXTRACTION_INTERRUPTED` 복구는 기존 Policy가
허용한 저장 입력 재검증1회뿐이며 Collector/Host 복구를 했다고 보고하지 않는다.

## 보관·개인정보

Native Kernel transport는 metadata만 보존하며 payload/header cache를 저장하지 않는다.
외부 PCAP과 저장 인증 자료에는 개인정보가 있을 수 있다. 기존 파일을 참조하며 이번 작업에서
Host 인증 로그를 읽지 않는다. 저장 Auth 이벤트의 계정/Source 식별자는 private 파일에 남을 수 있다.
파일0600·directory0700 및 GUI redaction은 암호화나 개인정보 익명화 보장이 아니다.

Queue/Window/seen-event/storage 상한에 도달하면 안전하게 거부/중지한다. `archive`는 quiescent
STOPPED/Cleanup VERIFIED 및 pending/claimed 없음 조건에서 SQLite backup·manifest를 검증한다.
원본 Audit/tombstone을 삭제하지 않고 archive도 저장 공간을 사용한다. 보존 기간 만료 데이터의
자동 삭제/운영 암호화 정책은 활성화하지 않았다. 보관 기간·외부 저장 위치·삭제 권한은 운영 승인에서
결정해야 한다. 외부 LLM의 기존 allowlist projection은 유지하며 원문 Source/계정/도메인을 전송하지 않는다.

## 다음 실제 운영 시험의 최소 조건

- Continuous 전용 Namespace/Interface/설치 파일/Collector 자원·시간·수집량 Scope의 유효한 승인.
  기존240초 시험 승인을 장시간 운영 권한으로 해석하지 않는다.
- 최신 Artifact/Runtime/모델/Lease/Ledger binding과 R1 위험 판단, 실제 모델 Action 승인.
  트래픽을 만들면 구체적인 TCP/R2 계약을 별도로 확인한다. DNS9 학습 추출 계약은 계속 차단한다.
- 사용자 Scope 확인·터미널 sudo 인증, 시작 전·후 소유 Kernel/FD/Map/Link·서비스·Cleanup 비교.
- 실제 API 조사가 필요하면 Native Incident 입력·Provider·모델·유효기간·호출 수/비용의 별도 승인.
- 실패 후 자동 Kernel 재실행 없음. 장시간/장애/부하 실환경 증거가 확보되기 전 OPERATIONS_VERIFIED를
  선언하지 않는다. Program1145 UNKNOWN·과거 전역 Cleanup UNVERIFIED 이력은 계속 보존한다.
