# Reliability 안정화 후 Full Live E2E 검토 — 실행 승인 아님

이 문서는 기존 승인을 갱신하거나 실행 권한을 부여하지 않는다. 새 Source·Artifact·Session은
이전 만료/소비 영수증과 별개다. 실제 실행·예약·Root 설치·모델·API 호출은 수행하지 않는다.
정확한 고정 Binding과 Root8 표는 최종 검증 뒤 생성하는 단일 패키지를 따른다.

## 독립적인 인간 결정

| 항목 | 제안 범위와 조건 |
|---|---|
| 검증 Release 선택/Update | 검증 Wheel·Source·Dependency·Manifest, 기존 사용자 설치 경로, 이전 Release 보존. 이번에 기존 manager를 자동 교체하지 않음 |
| 새 상위 정책 | 기존 2026-11-04 09:06:57 KST 만료 유지. 새 유효기간은 제안이며 명시 승인 전 활성화하지 않음. 입장 최소75분 |
| 사전 잔류 검사 | 과거 Cleanup 미검증/불명 소유권은 기존 검토된 읽기 전용 검사 경로로 확인. 현재 없음과 과거 성공을 구분. 이번 작업에서는 권한 검사 미수행 |
| A Root·Native·DNS | 1회, 전체600초/순수수집360초 목표. 기존 net:[4026532232]·lo/Ingress, 고정 Root8 검증/백업 및 Manifest의 변경 경로만 교체 |
| R1 | 과거 Program1145·TCX 송신 공백·Heartbeat/CPU·I/O 인과 UNKNOWN, 과거 FAILED/false/UNVERIFIED 보존. 현재 비권한 통과를 과거 Native 성공으로 확대하지 않음 |
| Host Authentication | 기존 UID의 읽기 전용 Journal selector만, 같은 Parent Session의 소유 child, 최대420초. 별도 정확한 Collection Action 승인. 그룹/ACL/서비스/Root 권한 확대 없음 |
| R2 고정 DNS | 기존 한 개 소유 Helper의 로컬 UDP2/TCP1, 고정 dnsmasq 서비스·namespace·capability만. 별도 인간 결정 PENDING |
| B Network RF/LR | 최대2개 봉인 작업/작업별 최대8개 ELIGIBLE 입력/합계16추론. 실제 봉인 Network14 ELIGIBLE/Attestation VERIFIED/Schema·Fingerprint·Session·Window·Flow 일치 후 GUI 작업별 승인 |
| B Authentication IF | 최대1추론. 실제 완결 Host Window/Revision/accepted source·Package·Schema·Fingerprint 검증 및 GUI 작업별 승인. 미완결/UNKNOWN 차단 |
| C 실제 LLM | 동일 Session의 실제 Incident/Revision에 Plan+Assessment 합계2회/$0.05, 요청당20초/출력4096토큰/재시도0. 기존 Provider·모델·선택 env-file, 사용 직전 가격·예약 상한 확인 |

하나의 화면/문서에서 검토해도 권한을 서로 대체하지 않는다. 미래 입력의 자동 승인,
API 모델 자동 교체, DNS9, 방화벽/계정/서비스 변경, 운영 승격은 포함하지 않는다.
실제 Read-only Tool만 실행하며 LLM 출력은 제안이다. Usage 누락/Timeout 비용은 UNKNOWN이다.

## 트래픽·자원·저장량

- TCP `127.0.0.1:18080`, client `18081/18082`, 기존 고정 Helper 두 번/최대4연결.
- DNS 기존 로컬 dnsmasq `127.0.0.53:53`, UDP2/TCP1. Namespace 외부 연결 금지.
- Host selector `SYSLOG_FACILITY=4`, `SYSLOG_FACILITY=10`, `+`, `_COMM=sshd`.
  실제 인증 시도나 Host 트래픽을 만드는 승인이 아니다.
- Collector128MiB/CPU25%; Runtime512MiB/50%/Tasks32; Host child는 Runtime 자원 공유.
- DNS Helper512MiB/10%; TCP Helper·dnsmasq 각각64MiB/10%.
- Continuous Queue32; Host Queue32/batch16/worker batch32/poll2초; Source capacity4096.
- Runtime 저장량 점검256MiB/Root Audit64MiB는 hard disk quota가 아니다.
- 준비·설치·READY·수집·STOP·Drain·Cleanup을 합쳐600초. 순수600초를 보장하지 않는다.

기존 PENDING2/POISON1·Ledger81행·원본 Audit·설치·Rollback·실패 증거를 보존한다.
새 Session 결과를 과거 결과에 합산하지 않는다. 미처리 Queue를 처리 완료라고 보고하지 않는다.

## IF와 실제 입력의 한계

기존 authentication_anomaly_iforest 1.1.0, 5 Feature/UTC300초 계정 Window/60초 lateness,
frozen preprocessing 및 threshold0.95를 유지한다.
Model SHA a1e42f399d3ddaaf876753e0a2e1f3a2a9ad1956e1ed82ce99e5abdb02becc7a,
Manifest SHA aabeb76277534d9300f70699dfddb84214720add607ef1d17b4c0e34e084b5f6.
기술적 입력 parity와 실제 Host 분포의 탐지 성능은 별개이며 연구용 synthetic 학습의 한계를
유지한다. 원본 DECLARED_UNATTESTED/NOT_INFERABLE 상태를 덮어쓰지 않는다.
실제 이벤트·완결 Window가 없으면 IF0건/미검증을 보고한다.

## 실행 전후 필수 조건

1. Git/Source/Artifact/Root8/Dependency/Model/Session/Release/Namespace Lease/Ledger 자동 검증.
2. 사전 잔류 소유권·과거 미검증 Cleanup의 독립 위험 판단. 불명 자원이 있으면 실행 금지.
3. 새 정책·각 독립 승인·충분한 유효기간·사용자 Scope 직접 확인·직접 sudo 인증.
4. Collector READY, TCX Sequence·송수신·CPU·IPC, Control Heartbeat·Data Progress,
   Packet/DNS/Host·Window·Attestation·Queue/Drop·GUI 연결/재연결 확인.
5. 실제 봉인 입력과 실제 Incident/Revision만 GUI에서 승인. SCRIPTED/Fixture를 실제 API로 표시 금지.
6. TCX STOP ACK, DNS CLOSED/Counter/ACK, Host exit/ACK·Reader Join, Queue/Audit Drain,
   Root 소유 Cleanup·Runtime Cleanup의 독립 증거 확보. Exit0만으로 VERIFIED 금지.
7. 실패 시 자동 Native/API 재실행0. 최초 오류와 후속 Cleanup 오류 분리, 증거 append-only.

Full Live 성공은 실제 Native·Host·모델·LLM·GUI·Cleanup이 같은 Session에서 검증된 경우에만
판정한다. 이번 비권한 회귀·Fixture 결과로 FULL_LIVE_E2E_VERIFIED를 선언하지 않는다.

최종 판정·정확한 명령·고정 Binding은 검증 종료 후 아래에 추가한다.

## 비권한 최종 상태와 승인 유효기간 제안

운영 코드067d36a, 네 환경의 관련 회귀 각각910 PASS·Authentication 보충123 PASS·
read-only 조사/수집34 PASS, Native·Supervisor·Wheel 세 빌드 해시 일치다.
이전 같은 운영 코드의 고부하 구간 Heartbeat/종료 지연 근본 원인은 UNKNOWN이다.
따라서 총 준비 판정은 **PARTIALLY_READY**이며, 안정성 미해결 위험을 숨기거나 자동 수용하지 않는다.
설치된 manager의 이전 Release를 자동 교체하지 않았다. 새 코드 선택/Update와 모든 독립
인간 승인은 PENDING이다. 실제 Root·Native·Host·모델·API는 실행하지 않았다.

새 검토안의 고정 만료 제안은2026-11-05 09:09:35.912778 KST다. 활성 정책이 아니며,
입장 최소75분을 적용하면2026-11-05 07:54:35.912778 KST 이전에 조건 검증이 끝나야 한다.
기존 만료 정책이 연장됐다는 뜻이 아니다. 승인 시점에 기간이 부족하면 실행할 수 없다.

API 제안은 기존 OpenAI/gpt-5-mini 설정을 유지한다. 검토 파일의 단가는
2026-11-03의 과거 참조이며 이번에 현재 가격·계정 사용 가능성을 확인한 것이 아니다.
60000 입력 토큰 예약/4096 출력 상한/요청2회의 과거 단가 예약액은$0.046384다.
이 금액을 실제 청구액이나 현재 확정 비용으로 보고하지 않는다. 호출 전에는
현재 Provider·가격·가용성·고정 Incident/Revision·$0.05 한도를 다시 검증해야 한다.
자동 재시도/모델 교체/재계획 API 호출은0회다.

## 최종 고정 Binding — 모두 PENDING, 실행 아님

```json
{
  "git_commit": "067d36a65962518adc89191d8980f2096389d45a",
  "git_tree": "4c68054d6dc9883bf3c9a1d79e2ac876070d0af2",
  "code_identity": "5350eba62fd0ffe43aebf453e498c07772a0971a1aaeccd3f0c0b302bd057b8a",
  "source_sha256": "701afdbf945bfde6496b6f79fe6cb21045c17487cee6826eb54671563e754e8a",
  "source_file_map_sha256": "a689442082ffd9f44916d055b421efec6aee6efe5fa1dea73b7f6a71e43cd580",
  "wheel_sha256": "6e42d89adbb1909f42aae2861b26472b221bdabb9746ea1cb79c7c46c8acf1f1",
  "runtime_session": "c1f2c795-642b-4c38-b60a-6217922f9db6",
  "root_file_map_release_identity": "b3cda497fc8423ca24efd5ead9ac00148c2b962e8e903d938c6c4cdf9487ea0b",
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
| /etc/soc-agent/continuous-installation.json | CHANGE | d2d56ba8b9b7185a365db763f75a7a20c0c6eea1794e0b25e40de4a57284a359 | 6e66d66df1fedbcf27474c18299316ba7dfbf37938fe4c8866d6d68f60657e65 | 2722101 | 1793689596433375459 |
| /etc/systemd/system/soc-operations-runtime.service | CHANGE | 02d4644162cbadba5dabdfbf2b8daa5e52fa7c8b02b32a3efd9f731b308a4ec2 | 89f87efcbe4343b65738de2a0cf54fd7903335ff40a2129103ee518a88468a02 | 2722103 | 1793689596460969203 |
| /etc/systemd/system/soc-continuous-dns.service | CHANGE | 1fa70b4c29e5b841fec12e9512d35aede2c810ef6675992255f34bfd272a7e5b | 2886a1d201a459a1bb1d830f3295b8fd1ef61d3cae835282373d2f4e154146b1 | 2722105 | 1793689596484502986 |
| /etc/systemd/system/soc-continuous-dnsmasq.service | VERIFY_ONLY | 1f7a36c1767089c38c4328324f74d4e68dc33a1804173adcc988657ecf5ec55f | 1f7a36c1767089c38c4328324f74d4e68dc33a1804173adcc988657ecf5ec55f | 2084947 | 1793357834080175596 |
| /usr/lib/soc-agent/continuous/service.py | VERIFY_ONLY | 075dba6a3a8570baad587add5047ed3722e159b5ce2baba7e4addf1b0a35e6b9 | 075dba6a3a8570baad587add5047ed3722e159b5ce2baba7e4addf1b0a35e6b9 | 2722109 | 1793689596669204080 |
| /etc/systemd/system/soc-continuous-dns.service.d/trial-deadline.conf | VERIFY_ONLY | 61257ee34448f64716b75b4e97f5e619a2d3866ed7461ca89919d966e259cad9 | 61257ee34448f64716b75b4e97f5e619a2d3866ed7461ca89919d966e259cad9 | 2084951 | 1793357834117147432 |

Backup proposal: `/var/lib/soc-agent/continuous/backups/full-reliability-stabilization-20261104T021605Z-final`. 생성/설치/교체 없음. Root Manifest SHA `eff4955904540be7ca0679ccb971ff839c4e06b8b0f94fe5aaaaecb625908186`.

최종 회귀 및 미해결 UNKNOWN은 별도 검증 JSON을 따른다. 비권한 준비 통과는 실제 Live 성공이나 실행 권한이 아니다. 모든 독립 승인은 PENDING이다.

## 실제 선택 프로파일과 명령

Canonical 실행 검토서는 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/full-reliability-stabilization-20261104T021605Z/final-verified/candidate/native/approval-package-final.md`다.
이 문서는 그 검토안의 사본과 사용 설명이며, 변경된 문서가 실행 승인을 자동 갱신하지 않는다.
Source682개·Git067d36a·Root8·새 Session `c1f2c795-642b-4c38-b60a-6217922f9db6`·Ledger81행을 내부 검증한다.
설치된 과거 manager Release는 바뀌지 않았다. 다음 명령은 새 후보 프로파일을 명시적으로
선택하며 SHA/UUID를 사용자에게 요구하지 않는다.

```bash
cd /home/geonug/kdt-linux/autonomous-soc-agent
source /home/geonug/kdt-linux/autonomous-soc-agent/.git/full-reliability-stabilization-20261104T021605Z/final-verified/use-review-profile.sh
soc-agent doctor
soc-agent start --preview
soc-agent status
```

실제 확인 결과 doctor=0/PREFLIGHT_ONLY_NO_INFERENCE, preview=1/BLOCKED/
AUTHENTICATION_EXACT_HUMAN_APPROVAL_REQUIRED, status=0이다.
root_executed=false/capture_started=false/reservations_created=false다.
이 차단은 새 Host 수집 승인이 없어서 발생하며 정책을 우회하여 없애지 않았다.

새 정책·Release Update·Root/Native/DNS/R1/R2·Host 정확한 승인과 Scope/sudo 인증을
충족한 뒤에만 기존 진입점 `soc-agent start --gui` 및 `soc-agent stop`을 사용할 수 있다.
봉인된 Network/IF 작업과 실제 Incident/API 입력은 각각 GUI에서 독립 확인한다.
API 실제 가용성·가격 확인과 비용 강제도 호출 전 조건이다. 이번에 위 실제 시작/종료는 실행하지 않았다.
