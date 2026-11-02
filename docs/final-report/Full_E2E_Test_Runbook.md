# 전체 통합시험 Runbook

## 이번 야간 작업의 실행 경계

실제 Root 설치, TCX, DNS 트래픽, Native 모델 Action, 외부 API, Host 로그 수집, 실행 예약, 기존 영수증 소비를 수행하지 않는다. 비권한 테스트의 합격을 실제 Native/API E2E 합격으로 바꾸지 않는다.

## 다음 시험의 단일 검토

| 권한 | 제안 범위 | 실제 실행 조건 |
|---|---|---|
| A | 기존 Namespace `net:[4026532232]`, lo/Ingress, 총 600초, 순수 수집 목표 360초 | 최신 정책·Source·Root·Session·Lease·Ledger/R1, 직접 Scope·sudo |
| B | 현재 봉인된 ELIGIBLE RF/LR 작업, 누적 최대 16회 이하 | 작업별 Action/Schema/Fingerprint/Provenance 대조와 명시적 인간 검토 |
| C | 같은 Native Incident의 Plan·Assessment, 최대 2회, retry 0, 요청 20초, 출력 4096토큰 | 정확한 Evidence Revision·Provider/모델·가격·예상 비용, 인간 API 승인 |

사용자의 상한 20회/$1은 강제 소진 목표가 아니다. 기존 APIRunAuthorization 구현의 최대 2회를 유지한다. 다음 검토안의 비용 상한은 사용자 상한 이하이며, 실사용 전 현재 Provider와 비용 제한 가능 여부를 확인해야 한다. 야간 작업에서 가격이나 가용성의 실제 API 검증을 수행하지 않았다.

A 자원: Collector 128MiB/CPU25%, Runtime 512MiB/CPU50%, Queue32, Runtime 저장량 점검256MiB, Root Audit 점검64MiB. Helper/TCP/dnsmasq는 고정 unit의 기존 제한을 유지한다. 점검 상한은 디스크 quota가 아니다.

트래픽은 기존 검토의 로컬 TCP 최대4연결, DNS UDP2/TCP1만 제안한다. 정확한 주소·포트·페이로드·간격의 새 검토 Binding이 없으면 생성하지 않는다. DNS9와 Host Authentication live는 포함하지 않는다.

## 전경 실행

1. 새 미소비 패키지의 `doctor`와 `start --preview` 결과를 확인한다.
2. 정책 갱신과 R1·Root·Native 결정을 독립적으로 기록한다. 제안 파일 생성은 승인 아님.
3. 사용자 Scope 확인 후 직접 sudo 인증한다.
4. `soc-agent start --gui`를 최대 1회 실행한다.
5. READY 전에는 트래픽을 만들지 않는다.
6. 실제 Window/Attestation/ELIGIBLE 후 GUI에서 B 작업들을 검토한다.
7. 실제 Incident/Revision이 준비되면 C exact 입력을 검토하고 기존 bounded runner만 실행한다.
8. GUI 종료·재연결 후 Backend 유지 여부를 확인한다.
9. `soc-agent stop`으로 종료하고 별도 증거로 Cleanup을 판정한다.

## 성공/실패

필수 GUI 값: Packet, DNS, Window/Attestation, Eligibility, RF/LR·Latency, Incident, Task, Plan/Tool/Assessment, API Usage 또는 UNKNOWN 이유, Queue/Drop, STOP ACK/Cleanup. 값이 없으면 해당 항목 미검증 또는 실패다. 과거 Prediction을 새 Session 값으로 합산하지 않는다.

실패 시 최초 오류·발생 단계·실제 자식 종료 코드와 후속 Cleanup 오류를 분리한다. Native 자동 재실행과 API 자동 재시도는 금지한다. 글로벌 Kernel Cleanup, 20분·1시간 안정성은 이번 성공 범위에 포함하지 않는다.

## 현재 장비의 실제 명령

```bash
cd ~/kdt-linux/autonomous-soc-agent
export PATH="$HOME/.local/bin:$PATH"
hash -r
soc-agent doctor
soc-agent start --preview
# 아래는 사용자가 새 정확한 Scope/R1을 검토하고 직접 인증할 때만 실행
soc-agent start --gui
```

별도 터미널에서 `soc-agent status`, `soc-agent stop`. 기본 profile과 Session은 이미 미승인 상태로 생성했다. 최초 Collector STOPPED·수집0은 실행 전 상태이며 성공이나 장애로 판정하지 않는다. B/C 검토는 GUI의 실제 준비된 작업에 대해서만 한다. 이번 준비 과정에서는 위 non-preview start를 실행하지 않았다.

현재 트래픽 Binding: TCP listener127.0.0.1:18080, client18081/18082, request `SOC-CONTINUOUS-PROBE/1\n`, response `SOC-CONTINUOUS-OK/1\n`; Helper최대2회/연결4개. 인증 READY와 DNS 완료 후, 새 generation180초 조건과 기존 내부35초 간격,Root330초 cutoff를 유지한다. DNS는127.0.0.53:53,Native-0516.localhost 고정 wire 질문과 query IDc201/c202/c203,UDP2/TCP1,기존 dnsmasq A응답 검증만 사용한다. wire 바이트와 실제 대소문자는 새 Scope JSON의 고정 hex를 기준으로 한다.

자원 범위 보충: DNS Helper512MiB/CPU10%, TCP Helper64MiB/10%, dnsmasq64MiB/10%를 유지한다. 현재 Native scope의 Window 길이는180초다. GUI와 별도 Host API helper가 Native Runtime unit의 cgroup 상한 안에 있다고 주장하지 않는다. C의 실제 실행 제한은 독립 API 승인·비용·호출·Token·Timeout 계약이다.
