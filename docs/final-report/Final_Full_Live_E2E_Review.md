# Final Full Live E2E — 단일 검토 / BLOCKED

**현재 전체 Live 실행을 승인 요청할 준비가 완료된 상태가 아니다.**
IF 실행 route/Native 입력 계약/IF GUI 작업 승인 연결이 미완료다. 승인만 추가해
해결되지 않으며 일부 기능의 시험을 전체 성공으로 대체하지 않는다.

## 최신 정확한 Binding

- 코드 dd81305 / 동결 Git `fdfb15cddf281fef0b061f980ed0d5c25806ff2e`
- Source SHA `958f1ba8d1907d26ec513d69920bf5f55bd2d31435f26169dba838933a49a776`
- Wheel SHA `2640b8772f44a7766773cc013f594afe9429eea69bd03cedbf605126c94b1f58`
- 새 Runtime Session `ce6aeeeb-940f-4600-a107-92155e2b05b1` (실행·승인·예약 없음)
- Namespace net:[4026532232], lo/Ingress, Ledger81 보존
- Native 패키지 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/final-full-live-validation-prep-20261103T095545Z/candidate/native/approval-package-final.md`
- Native 패키지 SHA `8d8ff205973f52ea5218bffcb6e151638477059807ff63776c2fe9e4c9a1814d`
- Root Manifest SHA `78a490033212ec2f64a37fa00f0d0533982581a4cb3722c7aa380daf33f5b876`
- Root 제안3변경/5검증; 실제 변경0

[정확한 패키지 전문](evidence/final-full-live-validation-20261103/blocked-approval-package.md)
에는 Root8경로별 기존/제안 SHA와 Git/Source/Session/Release/Namespace/Scope/Ledger
Binding, 정책 만료, Human 결정 범위가 담겨 있다. 실행 승인이 아니다.

## 권한별 상태

| 범위 | 제안 상한 / 계약 | 현재 |
|---|---|---|
| 사용자 관리 Release Update | 검증 Wheel, 기존 설치기 --update, 이전 버전 보존 | PREPARED_NOT_AUTHORIZED_NOT_EXECUTED |
| Root/Native/DNS/R1 | 1회, 전체600초/수집360초목표, TCP4/UDP DNS2/TCP DNS1 | PENDING |
| Host Authentication | UID1000 read-only, auth/authpriv-or-sshd,420초, 새Session | PENDING_EXACT_ACTION |
| Network RF/LR | 봉인 ELIGIBLE/Attestation VERIFIED/Schema/Fingerprint/Provenance,2 Job/16추론,GUI 개별결정 | PENDING_ACTUAL_INPUT |
| Authentication IF | 승인된 Host 계약·Package·완결Window·독립정확Action | **BLOCKED_ROUTE_CONTRACT_GUI** |
| 실제 API | 동일Session 실제Incident/Revision, gpt-5-mini,2회/$0.05/20초/4096출력/재시도0 | PENDING_EXACT_INPUT_AND_CURRENT_PROVIDER_COST_CHECK |

Collector128MiB/25%, Runtime512MiB/50%/Tasks32(Host child 포함 공유), DNS512MiB/10%,
TCP/dnsmasq64MiB/10%,Queue32,Runtime저장점검256MiB/RootAudit64MiB. hard disk quota로
확대 해석하지 않는다. 기존 2초/5초/600초 계약을 유지한다.
정확한 Journal selector는 Unit allowlist와 다르며 접근권한을 확대하지 않는다.
Key·원문Payload·민감한Host원본은 전송/로그 대상이 아니다. 기존가격핀의예약상한
$0.046384는 최신모델/가격확인 전 실제비용보장으로사용하지 않는다.

R1에는 과거 Program1145/Heartbeat/TCX송신공백/일반디스크시간경계 원인UNKNOWN,
과거FAILED/false/Runtime·GlobalCleanup UNVERIFIED, 새결합자원부하미검증을 명시한다.
소유권 불명 잔류자원은 승인된 읽기전용 검사 후 해결 전 Native를 시작하지 않는다.
과거 Cleanup을 소급 VERIFIED로 변경하지 않는다.

## 정확한 CLI / Home

진단 후보 CLI는 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/final-full-live-validation-prep-20261103T095545Z/use-review-profile.sh`가 선택하는
`/home/geonug/kdt-linux/autonomous-soc-agent/releases/research-mvp/.venv/bin/soc-agent`다. Home은 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/final-full-live-validation-prep-20261103T095545Z/candidate/operator-home`이다.
실제 기본 `~/.local/bin/soc-agent`는 여전히 이전 설치 Wheel을 실행한다.
기존 만료/소비된 default Home의 실행 영수증을 새 프로파일로 가져오지 않았다.

```bash
cd /home/geonug/kdt-linux/autonomous-soc-agent
source /home/geonug/kdt-linux/autonomous-soc-agent/.git/final-full-live-validation-prep-20261103T095545Z/use-review-profile.sh
soc-agent doctor
soc-agent start --preview
```

예상 결과는 Host 읽기 승인 누락으로 BLOCKED이며 Root/Capture/예약 false다.
개발자가 이 차단을 없애기 위해 승인 파일을 위조하지 않는다. 패키지 안의
`authentication-collection-proposal.json`은 Action **제안**일 뿐이다.

기존 사용자 설치기의 Update 실행 계획은 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/final-full-live-validation-prep-20261103T095545Z/release-update-plan.json`에 있다.
명시적 Update 승인 전 설치·symlink 변경을 하지 않았다. IF 차단 해제 및 정확한
독립 승인 후에만 `soc-agent start --gui`, `soc-agent stop`을 사용한다.
사용자에게 SHA나 Session UUID 수동 입력을 요구하지 않는다.

## 내일 아침

기존 정책 상한 2026-11-04 10:21:57 KST / 입장 최소75분이다.
09:06:57 KST 이후에는 이 상한으로 실행할 수 없다. 이후 실행은 상위 정책의
명시적 갱신과 새 최종 Binding 검증이 필요하다. 자동 갱신/예약/실행은 없다.

## 수행 전 필수 해제 사항

1. ‘새 기능 개발 금지’와 충돌하는 최소 IF 연결 보완 허용 범위 확정.
2. Host store→IF Worker→Incident 및 IF 작업별 정확한 GUI 승인 연결 검증.
3. IF Host 입력/학습·추론 계약과 Package의 사용 범위 검증; UNKNOWN은 실행 금지.
4. 검증 Release Update와 필요 시 정책 갱신으로 최종 Binding 확정.
5. 새 Root/Native/DNS/R1/Host 승인, 사용자 Scope 직접 확인·sudo 인증.
6. 실제 생성된 Model 입력·Incident/API 입력/비용은 기존 계약대로 별도 GUI 확인.
7. 실패 시 자동 재실행 없이 최초 오류·Sequence·STOP ACK·Helper·Durable Cleanup 보존.

[검증 보고서](Final_Full_Live_E2E_Validation.md)와
[Portable 증거](evidence/final-full-live-validation-20261103/verification.json)를 함께 검토한다.
