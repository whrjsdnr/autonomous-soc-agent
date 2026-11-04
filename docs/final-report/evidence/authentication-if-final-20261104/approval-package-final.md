# Authentication IF 통합 후 전체 Live E2E 검토 — 실행 승인 아님

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

## 최종 고정 Binding — 모두 PENDING, 실행 아님

```json
{
  "git_commit": "a481b985ec0ba5cbc64c07a57f076ca8600513ea",
  "git_tree": "d3e3deccd5010c1ce6a398cbdd8689a32f650e07",
  "code_identity": "f7b294cf7f6cacbb092ed8bcc15d26b48cbb06777613bdbc620945a77b93cd75",
  "source_sha256": "d905668834aaf5f8bb254f4ee53e7561c77f8ef5bd39fcce7a48c9284109f6c3",
  "source_file_map_sha256": "fa2de1f29e1bd25f91e491fecca39f60b506949cb350eff640e03dabb224f5c6",
  "wheel_sha256": "6a3551706d46455d11ff9c760e194851b8c4aae5189e524dff21db396e4d048f",
  "runtime_session": "4dbd9113-929e-48fb-aeb6-309935b25015",
  "root_file_map_release_identity": "74a3e098ea87b05a77ce5a469d8b678879233efc7aea3a18f518a744f96bc287",
  "expires_at": "2026-11-05T00:09:35.912778+00:00",
  "namespace": {
    "dev": 4,
    "host": "net:[4026531833]",
    "inode": 4026532232,
    "internal_check": "NOT_PERFORMED_NO_PRIVILEGED_ENTRY",
    "lease_sha256": "24b1102b173985056043d3727121c40b4c57fe71f7486affcc32e8718d105c9e",
    "target": "net:[4026532232]"
  },
  "ledger": {
    "batch3_native": 1,
    "batch3_root": 9,
    "campaign_native": 4,
    "campaign_root": 12,
    "chain": "VERIFIED",
    "rows": 81,
    "sha256": "07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae",
    "unresolved_native_reservations": [],
    "unresolved_root_reservations": []
  },
  "model_action_review": {
    "automatic_grants": false,
    "existing_exact_job_contract": true,
    "max_eligible_per_job": 8,
    "max_jobs": 2,
    "max_model_invocations": 16,
    "models": [
      "quality",
      "edge"
    ],
    "operator_reviews_already_sealed_jobs_only": true
  },
  "authentication_model_action_review": {
    "exact_sealed_window_gui_approval": true,
    "host_distribution_validation": "UNVERIFIED_RESEARCH_MODEL",
    "manifest_sha256": "aabeb76277534d9300f70699dfddb84214720add607ef1d17b4c0e34e084b5f6",
    "max_model_invocations": 1,
    "model_sha256": "a1e42f399d3ddaaf876753e0a2e1f3a2a9ad1956e1ed82ce99e5abdb02becc7a",
    "source_assurance": "DECLARED_UNATTESTED_SUPPORTED_SSHD_FINAL_AND_SUDO_PAM_FAILURE"
  },
  "api": {
    "approved": false,
    "automatic_calls_from_start": false,
    "calls": 2,
    "cost_limit": "0.05",
    "provider": "EXTERNAL_API_AFTER_EXACT_INCIDENT_REVISION_APPROVAL"
  }
}
```

새 정책 유효기간은 제안이며 설치된 만료 정책을 갱신한 것이 아니다. 입장 최소75분을 유지한다.

| Root target | Mode | Current SHA | Proposed SHA | inode | mtime_ns |
|---|---|---|---|---:|---:|
| /etc/systemd/system/soc-continuous-collector.service.d/trial-limit.conf | VERIFY_ONLY | 4b36f322ef409220bfd1c5bae7ef30b36022caf40f85a2f812b9c2a47f46a002 | 4b36f322ef409220bfd1c5bae7ef30b36022caf40f85a2f812b9c2a47f46a002 | 2451423 | 1793612680535955501 |
| /etc/systemd/system/soc-continuous-tcp-trial.service | VERIFY_ONLY | c78030d783a01e03cf3a2ab2df41df14889cb748bde1ed4d7d8068dc30cc4f4b | c78030d783a01e03cf3a2ab2df41df14889cb748bde1ed4d7d8068dc30cc4f4b | 2084939 | 1793357834000244581 |
| /etc/soc-agent/continuous-installation.json | CHANGE | d2d56ba8b9b7185a365db763f75a7a20c0c6eea1794e0b25e40de4a57284a359 | beea58bbdfb90ae6eabff2f94fbfb85458265f480d240c95c234f184c5320b3a | 2722101 | 1793689596433375459 |
| /etc/systemd/system/soc-operations-runtime.service | CHANGE | 02d4644162cbadba5dabdfbf2b8daa5e52fa7c8b02b32a3efd9f731b308a4ec2 | afcbb77dcbd1b0066de31f5df9bd99b9d4f893738bee0868a4e99d43558bf717 | 2722103 | 1793689596460969203 |
| /etc/systemd/system/soc-continuous-dns.service | CHANGE | 1fa70b4c29e5b841fec12e9512d35aede2c810ef6675992255f34bfd272a7e5b | 87a21a94ca6fb2913b34fedccb9a43faca9626c104e73c52fd25b960252904aa | 2722105 | 1793689596484502986 |
| /etc/systemd/system/soc-continuous-dnsmasq.service | VERIFY_ONLY | 1f7a36c1767089c38c4328324f74d4e68dc33a1804173adcc988657ecf5ec55f | 1f7a36c1767089c38c4328324f74d4e68dc33a1804173adcc988657ecf5ec55f | 2084947 | 1793357834080175596 |
| /usr/lib/soc-agent/continuous/service.py | VERIFY_ONLY | 075dba6a3a8570baad587add5047ed3722e159b5ce2baba7e4addf1b0a35e6b9 | 075dba6a3a8570baad587add5047ed3722e159b5ce2baba7e4addf1b0a35e6b9 | 2722109 | 1793689596669204080 |
| /etc/systemd/system/soc-continuous-dns.service.d/trial-deadline.conf | VERIFY_ONLY | 61257ee34448f64716b75b4e97f5e619a2d3866ed7461ca89919d966e259cad9 | 61257ee34448f64716b75b4e97f5e619a2d3866ed7461ca89919d966e259cad9 | 2084951 | 1793357834117147432 |

Backup proposal: `/var/lib/soc-agent/continuous/backups/authentication-if-final-20261104T000307Z-if-final`. 생성/설치/교체 없음. Root Manifest SHA `fa40b29b7c03a902180baf1100b899a3fdf844894e1e2d86ecd0e3ebfc274fc9`.

전체 회귀의 시간 경계 실패가 남아 있으므로 FULL_LIVE_E2E 실행 준비 완료를 선언하지 않는다. 새 정책/설치/Host/모델/API 승인만으로 회귀 실패가 해결됐다고 간주하지 않는다.
