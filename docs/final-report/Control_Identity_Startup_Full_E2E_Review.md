# Control Identity Startup 복구 후 Full Live E2E 검토 — 실행 승인 아님

이 문서는 기존 만료 정책·소비 영수증을 갱신하거나 권한을 부여하지 않는다.
수정본의 정확한 Git/Source/Wheel/Root Manifest/Session/DNS Session/Namespace/Ledger
Binding은 함께 제공하는 machine-readable identity 및 Root8 표를 따른다.
실제 Root·Native·Host·모델·API 실행은 이번 개발 작업에서 수행하지 않는다.

## 독립적인 인간 결정 범위

| 결정 | 제안 한도 / 필수 계약 |
|---|---|
| 검증된 사용자 Release Update | 새 검증 Wheel·Manifest, 기존 사용자 설치기 --update, 이전 버전 보존. Root 설치와 별개 |
| 새 상위 정책 | 이전 입장 만료 2026-11-04 09:06:57 KST 유지. 새 정책 유효기간/정확한 Source·Scope 명시적 승인 필요 |
| Root·Native·DNS | 1회, 전체600초, 순수수집360초 목표, 기존 net:[4026532232] lo/Ingress, 고정 Root8만 검사/백업·승인 변경 경로만 교체 |
| R1 | 과거 Program1145/TCX 송신 공백/Heartbeat/CPU·Scheduling 인과관계 UNKNOWN, 과거 FAILED/false/Cleanup UNVERIFIED, 일반 디스크·tmpfs 시간 경계 실패 기록 보존 |
| Host Authentication 읽기 | 기존 UID 권한, 기존 Journal selector, 새 Session, 420초 상한, 설정·정확한 Collection Action 승인. ACL/그룹/서비스/Root 확대 금지 |
| Network RF/LR | 최대16추론·최대2개의 실제 봉인 job. ELIGIBLE/Attestation VERIFIED/Schema/Fingerprint/Provenance와 GUI 작업별 결정 |
| Authentication IF | 최대1추론. 기존 연구용 IF Manifest/Model SHA, 공유 Feature 계약, 실제 완결 Window/Revision, 정확한 GUI 작업별 결정. 미래 입력 승인 없음 |
| 실제 LLM API | 동일 Session의 실제 Incident/Revision에 Plan+Assessment 합계 최대2회·$0.05·요청당20초·출력4096토큰·자동 재시도0. 기존 Provider/모델, 사용 직전 가격·사용 가능 여부 및 예약 상한 검증 |

A/Host/RF-LR/IF/API 승인은 서로 대체하지 않는다. 단일 CLI나 한 화면에서 검토했다는
이유로 다른 작업 권한을 자동 생성하지 않는다. IF 승인 범위를 request에서 생략하면
IF 한도는 0이다. 예약·실행·영수증 소비를 이 문서로 시작하지 않는다.

## 트래픽과 자원

TCP는 기존 로컬 `127.0.0.1:18080`, client `18081/18082` 고정 Helper 두 번,
최대4연결 제안이다. DNS는 기존 `127.0.0.53:53` 로컬 공급원 UDP2/TCP1이다.
Namespace 안의 외부 연결·Host 인증 트래픽 생성·임의 포트/페이로드 변경은 제외한다.
Host 읽기 승인은 로그인 시도를 생성하는 승인이 아니다. 실제 인증 이벤트가 없거나
후속 이벤트가 Window 종료+lateness를 증명하지 못하면 IF 0건/미완결을 보고한다.

Collector128MiB/CPU25%, Runtime512MiB/50%/Tasks32이며 Host child는 Runtime 자원을
공유한다. DNS Helper512MiB/10%, TCP Helper·dnsmasq 각각64MiB/10%를 유지한다.
Continuous Queue32, Host queue 제안32, Host batch16/worker batch32/poll2초,
기존 Source Store capacity4096를 구분한다. Runtime 저장량 점검256MiB/Root Audit64MiB는
디스크 hard quota가 아니다. 기존 2초/5초 stale 및 전체 Deadline을 늘리지 않는다.

## IF 연구 범위

기존 `authentication_anomaly_iforest` 1.1.0, 5개 Feature, 300초 UTC 계정 Window,
frozen scaler/profile, normalized threshold0.95를 재사용한다.

- Model SHA `a1e42f399d3ddaaf876753e0a2e1f3a2a9ad1956e1ed82ce99e5abdb02becc7a`.
- Manifest SHA `aabeb76277534d9300f70699dfddb84214720add607ef1d17b4c0e34e084b5f6`.
- Collector의 `pam-failure` 이름은 선택된 추가 parser profile을 나타낸다. 실제 기존
  parser는 SSH Accepted/Failed와 sudo PAM failure를 지원한다. 임의 PAM session,
  모든 Host 인증 방식의 완전성을 주장하지 않는다.
- 기술적 Feature/Package parity와 실제 Host 분포에서의 탐지 성능은 별개다.
  연구용 synthetic 학습 Artifact이며 실제 Host 성능은 UNVERIFIED다.
- 원본 NOT_INFERABLE/DECLARED_UNATTESTED를 수정하지 않는다. 추가 adapter가 정확한
  retained source/완결 Window를 재검증한 뒤 별도의 Model Action을 요구한다.
- GUI는 Window 시작/종료/witness/accepted record 수/Feature 값/Revision/모델 계약을
  표시한다. No/취소는 영수증을 만들지 않는다. 발급 후 범용 철회 기능은 없으며
  기존 Stop을 사용한다. 이미 수행된 추론을 취소했다고 보고하지 않는다.

## 실행 전후 기준

1. 정확한 Release/Source/Artifact/Root8/Session/Namespace/Ledger 및 정책 유효기간 검증.
2. 이전 Cleanup 미검증/잔류 소유권은 승인된 읽기 전용 경로로 별도 확인. 현재 없음과
   과거 Cleanup 성공을 구분한다. 소유권 불명 자원이 있으면 시작하지 않는다.
3. 사용자 직접 Scope 확인·sudo 인증. 실제 Host 읽기와 모델/API는 독립 조건 확인.
4. Collector READY, Control heartbeat, TCX Sequence·IPC/CPU Throttling, Window·Queue·
   Drop·Source Gap·Data Progress·GUI 연결/재연결을 관측한다.
5. 실제 생성된 모델 작업과 Incident만 GUI에서 확인한다. 미승인/불완전 입력을 추론하지 않는다.
6. TCX STOP ACK, Helper CLOSED·Counter·ACK, Host child ACK/exit/queue drain,
   Root 소유 Cleanup, Runtime Cleanup, Audit flush를 독립 검증한다.
7. 실패 시 자동 Root·Native/API 재실행 없이 최초 오류와 후속 Cleanup 오류를 분리한다.

실제 Native·Host·RF/LR·IF·LLM·GUI가 같은 Session에서 연결되고 Cleanup까지 입증된
경우에만 FULL_LIVE_E2E_VERIFIED를 부여한다. Fixture/Mock/SCRIPTED 결과는 대체할 수 없다.
이번 결과와 정확한 CLI/Binding은 최종 검증 절에서 확정한다.

## Startup 수정본의 실행 전 추가 조건

새 소스는 Control Identity를 초기화 완료 전에 STARTING으로 게시한다. UID·Source authority·
Runtime 단일 lock·PID identity 검증은 유지한다. STARTING은 Collector READY 또는 모델/API
실행 허가가 아니다. 초기화 완료/실제 수집/STOP ACK/Cleanup을 각각 확인한다.

과거 8초 Export 실패의 정확한 CPU/IO 원인은 UNKNOWN으로 남긴다. 기존 8초 Assertion과
2초/5초 계약을 바꾸지 않았다. 일반 디스크 회귀의 추가 Heartbeat Sequence 표본 수 실패는
성공으로 덮어쓰지 않는다. 최종 회귀 표와 미해결 항목을 RCA 문서/검증 JSON에서 확인한다.
전체 회귀가 남아 있으면 실제 Full Live E2E 준비 판정은 PARTIALLY_READY다.

설치된 manager current는 자동 변경하지 않았다. 개발 검증 소스와 설치 Release를 구분한다.
새 Binding은 이전 승인/영수증과 별개이며, 이 문서를 실행·정책 활성화 권한으로 사용하지 않는다.
새 상위 정책·Root/Native/DNS/R1·Host 읽기·RF/LR·IF·실제 API의 독립 승인이 필요하다.
이전 정책의 2026-11-04 09:06:57 KST 만료를 연장된 것으로 취급하지 않는다.

실제 실행은 Source/Artifact/Session/Root8/Lease/Ledger, 충분한 유효기간,
잔류 소유권/이전 Cleanup 검토, 사용자 Scope 직접 확인과 직접 sudo 인증 후에만 가능하다.
RF/LR/IF는 실제 봉인된 입력, API는 실제 Incident/Revision/당시 가격·예약액을 GUI에서
확인한다. API 사용 가능 여부/가격은 실제 호출 직전에 검증하며 이번 비권한 작업에서는
확인된 것으로 표시하지 않는다. 승인 전 root/capture/traffic/model/API/예약/소비는 0이다.

최종 기계 검증 Binding·Root8 표·정확한 preview 명령은 후보 생성 후 아래에 고정한다.

## 새 고정 후보

- Code `b7505cabd08b0a431652796ee087c81f00643475` / Source682 SHA `82c97502caef2b6a73f31dfbd8265e4d41278f9f490cda15e9d9ab160e033ec0`.
- Wheel `1241ef4b97ee3e59740a33eda795f1c71ecc60cc60e9d6dfb38a255a1f02a043`.
- Root Manifest `db4a73fe7e4e313bf5b8a4c3edb506e86e25befcb1640de963d65a0c02e29552`.
- Runtime `b26080ac-9cf3-4114-959f-f0c40b91271e`.
- 검토서 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/control-startup-rca-20261104T012138Z/candidate/native/approval-package-final.md`.
- 판정 PARTIALLY_READY. 실제 권한 실행/정책 활성화0.

[최종 회귀/UNKNOWN/명령](Control_Identity_Startup_RCA.md)과 [고정 패키지 전문](evidence/control-startup-20261104/approval-package-final.md)을 따른다.
문서 설명의 후속 추가는 고정 패키지의 SHA나 실행 권한을 변경하지 않는다.
