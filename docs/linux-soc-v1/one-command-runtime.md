# SOC Agent application CLI

구현 브랜치: `feat/one-command-runtime`. 일반 사용자 작업 경로는
`/home/geonug/kdt-linux/soc-one-command-runtime`이다. 기존 사용자 main의 변경,
설치본, Rollback, Native 증거와 Ledger는 보존했다.

## Offline 실행

```bash
cd /home/geonug/kdt-linux/soc-one-command-runtime
uv sync --offline
export SOC_AGENT_HOME="$HOME/.local/state/soc-agent-offline-v1"
.venv/bin/soc-agent setup --ml-root /home/geonug/kdt-linux/ML
.venv/bin/soc-agent doctor
.venv/bin/soc-agent start
.venv/bin/soc-agent status
.venv/bin/soc-agent gui
.venv/bin/soc-agent stop
```

`setup`은 새 private profile을 생성한다. 이미 설정한 profile을 덮어쓰지 않으며,
다시 실행할 때는 `setup`을 반복하지 않는다. 모든 명령은 `--home /absolute/profile`
또는 `SOC_AGENT_HOME`을 지원한다. `start --gui`도 사용할 수 있다.
기존 `start --gui --monitor total ...`, `continuous ...`, `analyze-offline ...`,
`native-recovery ...` 명령은 그대로 유지한다.

기본 입력은 기존 catalogue의 실제 PCAP이다. 입력 SHA, 실행 코드 Identity,
모델 SHA, Source 계약을 내부 검증한다. API 호출은 하지 않는다.
Replay 기본 Queue는 128개로 제한한다. 실제 기본 PCAP burst에서 Queue8은
Drop106건을 일으켰고, 수정 후 실제 CLI 재검증에서는 Drop0, RF/LR6, Incident3을 확인했다.
이 검증은 전체 PCAP의 모든 Flow 분석 완료를 의미하지 않는다.

별도 입력은 `setup --replay /absolute/file.pcap --ml-root /absolute/ML`,
명시적 설정은 `setup --config /absolute/config.json`을 사용한다.
기존 Runtime은 `setup --runtime /absolute/runtime`으로 연결한다.
`--authentication-runtime /absolute/auth-runtime`은 이미 초기화한 읽기 전용
Authentication Runtime을 GUI에 연결하며, 그 명령 자체로 Host 수집을 시작하지 않는다.

## Native 실행 권한

`setup`은 Root 설치나 운영 권한 부여가 아니다. 현재 Native profile은 상태·GUI·Stop
연결에 사용할 수 있지만, 소비된 시험을 다시 시작할 권한은 없다.

기존 승인 절차로 준비한 새로운 유효 검토 디렉터리는
`setup --native-review /absolute/new-review --home /absolute/new-profile`로 등록한다.
이 경로는 기존 고정 terminal Entry Point, 파일 SHA, Source allowlist, Session,
Namespace, R1, Root Scope와 실제 사용자 TTY·sudo 검증을 재사용한다.
승인 생성이나 모델 Action 자동 발급은 하지 않는다. 입력 SHA 복사는 요구하지 않는다.
현재 지원하는 review 형식은 기존 `soc-operations-approval-review-only:v1`이다.
임의 서비스 설치, 다른 Namespace 진입, DNS·API 권한 확대를 제공하지 않는다.

## 상태·Stop·GUI

`status`는 원자적 observation mirror를 사용하여 SQLite writer와 경합하지 않는다.
이 mirror는 실행 승인 자료가 아니다. `doctor`는 사전 검증 결과이며 모델 호출이 아니다.
실행 중 중복 Start, 바뀐 Source/설정/실행 파일, 소모된 Native review는 차단한다.
부분 Start 실패는 자신이 생성한 자식만 회수하고 원래 오류를 보존한다.

`stop`은 기존 제어 채널에 Stop을 요청하고 최종 Runtime Cleanup을 확인한다.
미승인 모델 입력이나 미처리 Queue는 삭제하지 않고 보존한다. Stop이 모든 보존 입력을
자동 승인·분석하는 것은 아니다. Root의 STOP ACK와 별도의 Root Audit Cleanup은
독립적으로 표시한다. 실패한 Cleanup을 정상으로 바꾸지 않는다.

GUI는 Root를 직접 실행하지 않는다. 최신 완료 보고서를 Audit·원본 Receipt와 대조하여
AI Analysis에 자동 표시한다. 실측 latency, 조사 단계, assessment, Capture Quality,
Host Authentication 이벤트를 표시하며 Native/Offline/Fixture와 SCRIPTED/REAL_API를
구분한다. GUI 종료는 외부 Collector나 Authentication Runtime을 종료하지 않는다.

## 통합 시험 전 남은 항목

- 2026-10-29 Native 시험은 53분대 receive timeout으로 종료되어 1시간 운영 통과가 아니다.
- 다음 시험은 새 Artifact/Scope 승인과 직접 사용자 인증이 필요하다. 자동 재실행하지 않는다.
- 실제 Native 시험 중 디스크 스트레스 회귀를 병행하지 않는다.
- TCX metadata 자체에는 DNS payload가 없다. 별도 승인된 DNS 수집 경로가 필요하다.
- DNS9 학습 추출 계약은 INCOMPLETE다. [상세](dns9-training-extraction-status.md)를 참고한다.
- Host 인증 로그 수집은 연결했지만 Host 인증 IF 모델 추론까지 검증한 것은 아니다.
