# Autonomous SOC Agent 최종 시연 Release

2026-11-04. 목표는 기존 실제 결과를 안정적으로 보여주는 연구·시연용 MVP다. 이번 작업은 새로운 Live E2E, 모델 추론 또는 API 실행이 아니다. 사용자의 최신 요청에 따라 별도 상단 `보존 결과 조회 / NOT LIVE` 배너는 제거했다. 기존 GUI의 원본 출처, SCRIPTED/REAL_API, 상태·오류 표시는 변경하지 않았다.

## 바로 실행

운영 저장소에서 다음 한 줄을 실행한다. sudo, SHA, Session UUID, API Key 입력은 필요하지 않다.

```bash
~/kdt-linux/autonomous-soc-agent/releases/evidence-demo-20261104/show-demo
```

GUI 창 닫기 또는 실행한 터미널에서 **Ctrl+C**로 종료한다. GUI가 종료된 뒤 같은 명령을 다시 실행하면 같은 증거를 재조회한다. 이 명령은 기존 `soc_agent.gui`의 정식 entry point를 사용한다. Live용 `soc-agent start --gui`를 몰래 Replay로 바꾸지 않았다. 이 시연에서 `soc-agent stop`을 호출하면 다른 프로파일에 영향을 줄 수 있으므로 사용하지 않는다.

화면별 시작 명령:

```bash
~/kdt-linux/autonomous-soc-agent/releases/evidence-demo-20261104/show-demo native
~/kdt-linux/autonomous-soc-agent/releases/evidence-demo-20261104/show-demo replay
~/kdt-linux/autonomous-soc-agent/releases/evidence-demo-20261104/show-demo api
~/kdt-linux/autonomous-soc-agent/releases/evidence-demo-20261104/show-demo authentication
```

하나를 닫은 뒤 다음 화면을 연다. 실행 전 파일 정합성만 확인하려면 같은 명령 뒤에 `--check`를 붙인다. 정합성이 깨지면 실행을 차단한다. 실패를 감추기 위해 manifest를 자동 재생성하지 않는다.

## 네 화면의 의미

| 화면 | 실제 증거의 실행 시점·성격 | 보여줄 수치·결과 | 이번에 실행하지 않는 것 |
|---|---|---|---|
| native | 2026-10-30 실제 Native, 실행 코드 c542398; 이후 GUI 검증은 별도 | Packet54, DNS Transaction3, Window3 VERIFIED, ELIGIBLE5/INCOMPLETE2, RF/LR8, Incident2, Task5, SCRIPTED, Audit | 새 Capture·DNS·RF/LR·LLM |
| replay | 2026-11-02 실제 PCAP Replay 1200.132초의 저장 결과 | 받은 PCAP record1035, packet619, RF/LR406, Incident203, SCRIPTED, Queue DONE203/PENDING4 | PCAP 재주입·미처리4건 재실행 |
| api | 2026-10-27 별도 PCAP 분석 시험 | RF/LR2, 실제 API Plan·Assessment2회, read-only Tool, Audit VERIFIED | 새 API·추론·비용 발생 |
| authentication | 2026-11-04 실패 Runtime의 기록 | STOPPED/DEGRADED, SOURCE_UNAVAILABLE, 수집0, IF NOT_INFERABLE | Host Journal·IF 실행 |

네 화면은 **서로 다른 시험**이다. 하나의 Session에서 전체 Live E2E가 성공한 것처럼 합치지 않는다. Native origin은 과거 입력의 출처이며 현재 수집 중이라는 뜻이 아니다. API 화면의 2회 역시 과거 호출 수다.

현재 API 결과의 승인 영수증은 원래 결과 디렉터리의 정확한 경로에 결합돼 있다. 원본을 복사해서 영수증을 수정하는 대신 원래 경로를 읽기 전용으로 참조한다. 이 Release는 해당 PC의 보존 Evidence와 고정된 Python 환경을 필요로 하며 다른 PC로 파일 하나만 옮기는 portable 배포본이 아니다.

## 5분 GUI 순서

1. **native / Dashboard**: 모델별 측정값, Prediction·Incident를 설명한다. 과거 시험의 실제 실행 결과임을 한 문장으로 말한다.
2. **Continuous**: Packet54·DNS3·ELIGIBLE5·Drop0·STOP ACK·Cleanup을 확인한다. PENDING/POISON, INCOMPLETE를 완료 처리하지 않는다.
3. **ELIGIBLE Incident 선택 → Inspect Selected Incident**: 실제 RF/LR8이 있는 보고서를 연다. 마지막 INCOMPLETE 보고서를 선택하면 Prediction이 없는 것이 정상이다.
4. **AI Analysis**: 선택한 보고서의 RF/LR·Evidence/Audit를 보여준다. 이 Native 회차는 조사를 별도 Continuous Task로 지연 처리했으므로 분석 보고서 자체의 Investigation `{}`는 저장 경로의 차이이며 새 결과를 채우지 않는다.
5. **Continuous 하단 또는 Investigation**: Task5의 SCRIPTED Plan·read-only Tool·Assessment, priority, revision, checkpoint, WAITING_HUMAN을 보여준다. WAITING_HUMAN은 Root 실행 승인을 얻었다는 뜻이 아니다.
6. 창을 닫고 **api** 실행: 실제 API Plan·Assessment 결과와 RF/LR2를 보여준다. `AI Analysis → Investigation / Evidence·Audit` 탭을 사용한다. Native 시험과 다른 PCAP 시험임을 말한다.
7. 필요 시 **replay**: 20분 PCAP 시험의 누적406 prediction을 보여준다. GUI의 최근 결과 목록은 제한된 일부이며 누적 수치와 다를 수 있다(현재64행).
8. 필요 시 **authentication**: 미완료 상태를 설명한다. 최신 단독 Host 읽기 진단 성공은 이 실패 Runtime의 READY나 IF 성공으로 소급하지 않는다.
9. 창 닫기/Ctrl+C, 재실행: GUI 종료·재연결이 원본 Audit·결과를 변경하지 않음을 보여준다.

`Start Service`, `Run Offline Job`, 모델/API 승인 버튼은 이 조회용 시연에서 사용하지 않는다. 조회 프로세스는 새 subprocess(정확한 읽기 전용 ldconfig 조회 제외), 네트워크/IPC 실행, 모델 역직렬화, 증거 파일 쓰기를 차단한다. 원본 SQLite는 `mode=ro`로 연다. 이는 데모의 추가 제한이며 production Policy Gate를 변경하지 않는다. 악성 코드용 OS sandbox라고 주장하지 않는다.

## Release 구성과 보존

- 위치: 운영 저장소 `releases/evidence-demo-20261104/` (기존 research-mvp 교체 없음).
- 기존 검증 Wheel: `59479b3738d71060823f57bb550bf75e488cc4a3a1d3a9afee180a9e7c2cc45e`.
- Production Source: a5441a9, 동일 682개 Source. 운영 코드·Native/Supervisor 바이너리 변경 없음.
- GUI용 Python package는 Wheel에서 독립 디렉터리에 추출했다. 개발 Worktree와 분리했다.
- Python/의존성은 기존 연구 Release의 venv를 사용하며 코드·native library·metadata hash를 고정했다. venv를 업데이트하면 조회 준비가 차단될 수 있다.
- `manifest.json`: 파일별 SHA, 원래 증거 경로, 네 view의 인자, 보호 범위. 사용자 수동 SHA 입력 없음.
- `view-state/`: GUI 임시 상태/Lock만 신규 저장. 원본 Session·Queue·Audit과 분리.
- 실행 프로파일·manifest·Wheel은 이번 검증 후 고정. Root 정책/승인 발급·예약 없음.
- Ledger81행, Root8경로 SHA·inode·mtime, 기존 설치·Rollback과 실패 로그 보존.

## 검증과 예비 경로

최종 GUI 네 view × 두 번(5·6회차), 실제 shell entry 기본 명령 두 번, PCAP 읽기/파싱 두 번을 실행했다. 상세 수치·원본 경로·검증 SHA는 [Final_Demonstration_Validation.json](Final_Demonstration_Validation.json)을 본다. 두 GUI 회차에서 정상 close, 작업 스레드 종료, desktop OS Lock 해제, 원본 Evidence 불변을 확인한다. 새 Native STOP ACK를 받은 것이 아니라 과거 ACK를 조회했고 **이번 GUI 소유 자원**의 종료를 검증한 것이다.

GUI/WSLg가 고장나면 같은 Release의 `screenshots/` PNG를 연다. 실제 GUI 검증에서 캡처한 화면이며 생성 이미지가 아니다. `screenshots/index.html`은 로컬 파일 링크만 사용한다. 발표 대본과 검증표는 `docs/`에 함께 둔다. 그래도 실행이 안 되면 새 Live 실행을 시도하지 말고 실제 Screenshot·결과표로 시연한다.

## 해결되지 않은 Live 운영 한계

- Authentication READY_TIMEOUT과 당시 SOURCE_UNAVAILABLE의 직접 원인은 UNKNOWN. 11월4일 별도 승인된 읽기 진단은 rc0/16건, 5.779초였다. 이는 당시 실패 원인의 확정이나 READY 성공이 아니다.
- 과거 Runtime Cleanup UNVERIFIED 유지. 현재 viewer 종료 성공과 구별한다.
- TCX 송신 공백·장시간 지연 근본 원인 UNKNOWN. 20분/1시간 Native 안정성 미완료.
- 실제 LLM Assessment 성공 회차와 Timeout/Usage UNKNOWN 회차가 함께 존재한다. 성공 하나로 다른 실패 이력을 없애지 않는다.
- 실제 Host Authentication IF 전체 E2E, DNS9 원본 입력 계약, 전역 Kernel Cleanup 미검증.
- 연구·시연용 MVP이며 상용 무인 운영 안정성을 검증하지 않았다.

전체 Live 재개에는 새 Binding의 유효한 독립 승인, 이전 Runtime 잔류/소유권 검사, 사용자 Scope·sudo 인증, 봉인된 RF/LR·IF 작업별 승인과 정확한 Incident·API 비용 승인이 필요하다. 이 시연 Release는 그러한 권한을 발급하지 않는다.
