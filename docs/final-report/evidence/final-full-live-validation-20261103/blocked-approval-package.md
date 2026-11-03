# Final Full Live E2E — BLOCKED / 미승인 검토 패키지

이 패키지는 실행 승인이 아니다. Root·Native·DNS·Host Journal·모델·API 실행0, 영수증발급/소비0, 기존설치변경0. FULL_LIVE_E2E_VERIFIED=false.

## 실행 승인을 받아도 해제되지 않는 차단

1. Managed Authentication은 LinuxMonitor READ_ONLY 자식으로 수집·규칙·상태·Cleanup을 관리하지만, 그 source-store Window를 메인 IF inference job으로 보내지 않는다.
2. authentication_admission.observation은 현재 입력계약 미검증과 정확한 IF Action 요구를 반환하고 predictions=0을 유지한다. 실제 Host IF→Prediction→Incident→메인 SOCRuntime 경로는 검증/연결 완료가 아니다.
3. agent_review.pending_models는 kind=tcx_analysis만 선택한다. 기존 RF/LR GUI 승인창은 Authentication IF 승인을 대신하지 않는다.
4. IF fixture package의 내부 SHA/Feature 검증은 실제 Host 학습·추론 계약/배포 승인이 아니다. Authentication packages는 빈 값이다. 실제 Host에서 완결된 300초 Window가 확보될지도 미검증이며, 임의 로그인/실패 이벤트를 생성하지 않는다.

이번 작업의 ‘새 기능 개발 금지’에 따라 해당 경로/승인 기능을 새로 구현하거나 Gate를 제거하지 않았다. 아래 A/B/C/D를 지금 승인하더라도 전체 성공 준비가 완료되는 것은 아니다. IF 경로 및 계약 검증 이후 정확한 최종 승인 범위를 확정해야 한다. 일부 기능만 실행하고 전체 성공이라고 보고하지 않는다.

## A — Root·Native·DNS·R1: PENDING

최대1회/동시1개, 순수수집360초 목표, 설치·시작·종료·정리 포함600초 절대상한. 기존 net:[4026532232], lo/Ingress, 기존 Namespace 재사용만, 생성/삭제/Host Namespace 변경 없음.
TCP127.0.0.1:18080/client18081·18082, 고정공급원2회/최대4연결. DNS127.0.0.53:53 dnsmasq UDP2/TCP1. 기존 고정payload·간격 유지, Collector READY 전 트래픽0, 외부Namespace 연결0.
Collector128MiB/CPU25%, Runtime512MiB/CPU50%/Tasks32, DNS512MiB/CPU10%, TCP·dnsmasq64MiB/CPU10%, Queue32. Authentication 자식과 journal 명령은 Runtime 자원을 공유하고 추가 자원을 부여하지 않는다. Runtime저장량점검256MiB/RootAudit64MiB는 hard quota가 아니다.
기존 2초/5초 Timeout 및600초 Deadline 유지. TCX STOP ACK·Window Seal/Attestation·Helper CLOSED/Counter/STOP ACK·Root/Runtime/Authentication 소유 Cleanup과 Durable 기록 필수. Exit0만으로 VERIFIED 불가. 전역Kernel Cleanup은별도 UNKNOWN.
R1: 과거Program1145·Heartbeat·TCX송신중단원인UNKNOWN, 과거FAILED/false/ACK·Runtime·GlobalCleanup UNVERIFIED, 일반디스크 과거시간경계실패원인UNKNOWN 보존. 실제서비스CPU cgroup/디스크/추가Authentication 자식과모델의결합자원사용은새Live에서미검증. 현재잔류Root자원읽기전용검사도별도권한후수행한다.

## B — Network RF/LR: PENDING EXACT SEALED JOB

실제 봉인·Capture Attestation VERIFIED·Network14 ELIGIBLE·Schema/Fingerprint·Session/Window/Flow Provenance 검증 후 기존 GUI에서 작업별 독립 승인. 최대2 Job/총16추론. 미래입력/미승인작업/INCOMPLETE/UNKNOWN 자동승인0. 같은Session Prediction→Incident를 실제 결과로 확인한다.

## C — 실제 LLM: PENDING EXACT INCIDENT/REVISION

동일Native Session의 실제Incident·고정Evidence Revision 대상으로 OpenAI/gpt-5-mini Plan+Assessment 최대2회/$0.05, 요청20초/출력4096토큰/재시도0, read-only tool만. 기존 private .env의Key를요청Worker만읽고출력하지않는다. 계정모델사용가능성은인증Probe없이UNKNOWN. 기존가격핀 input$0.25/output$2.00 per1M와입력최대60000/요청 가정의예약상한$0.046384는이전검토의값이며최신가격확인전실행권한으로사용하지않는다. 가격·Provider·모델·토큰·전송최소화·비용상한을실제호출전재검증한다. 실제GUI입력/비용확인전호출0. Timeout/Usage누락은비용·결과UNKNOWN; 모델자동교체/자동재요청0. SCRIPTED와실제API는구분한다.

## D — Host Authentication 읽기: PENDING EXACT ACTION

기존journalctl의 auth/authpriv-or-sshd selector만: SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 + _COMM=sshd. 이는 정확한 systemd Unit allowlist가 아니다. 일반UID1000의기존읽기권한만 사용하고sudo/그룹/ACL/서비스설정변경없음. 접근권한미검증이며실제읽기는승인전수행하지않는다.420초상한·READ_ONLY·새Session소유자식·기존두규칙threshold5/3은제안/미검증. 초기필터Journal의과거항목도수집될수있으므로수집시각과이벤트시각을구분한다. 로그인/공격이벤트생성없음. Parser는원본Message/주소/계정을다운스트림보존하지않고정규화·가명값/증거Digest·Cursor를새Session에보존한다. 저장/Retention은기존계약대로이며기존PENDING2/POISON1은재처리/삭제/이관하지않는다.
authentication-collection-proposal.json은기존GovernedExecutor용정확한Action 제안만이다. authentication-collection-approval.json은없으며승인기록을발급하지않았다. 수집승인은IF/LLM/Root권한이아니다.

## E — Authentication IF: BLOCKED, NOT APPROVABLE BY EXISTING RF/LR GUI

승인된Host배포Package/Native학습·추론Parity/완결입력/정확한IF Action/GUI 처리경로가필요하다. 기존Fixture NumericForest 모델SHA a1e42f399d3ddaaf876753e0a2e1f3a2a9ad1956e1ed82ce99e5abdb02becc7a는배포승인을의미하지않는다. 추론한도/입력은현재승인될수없으며실행0을유지한다. 이차단을숨기고전체E2E를시작하지않는다.

## Binding — 새Session, 실행/승인 없음

```json
{
  "git_commit": "fdfb15cddf281fef0b061f980ed0d5c25806ff2e",
  "git_tree": "dd9ce68e55845ffd3e19c78530668ffb13dec65f",
  "code_identity": "9964f1eae5a14bb405e2a78a3f506dbeeac44e492aca243f08281ce41123d2e8",
  "source_sha256": "08d0c9f2d81dd3bb8bc526a2b3540c49817d7d95578e45a9bae6396c95c9d6c9",
  "source_file_map_sha256": "c087262d4c87b07e9fffe4be55b4f288bc72bf3e6a5504d8e7dc90842a93c1e9",
  "wheel_sha256": "2640b8772f44a7766773cc013f594afe9429eea69bd03cedbf605126c94b1f58",
  "runtime_session": "ce6aeeeb-940f-4600-a107-92155e2b05b1",
  "root_file_map_release_identity": "8270c5d0f22e93db864575f193a47b56589c2fe761d86797bd9e207419937790",
  "expires_at": "2026-11-04T01:21:57.665314+00:00",
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
  "authentication_attachment": {
    "actual_host_collection_authorized": false,
    "authentication_if_authorized": false,
    "collector": "EXISTING_LINUX_AUTHENTICATION_COLLECTOR",
    "duration_seconds": 420,
    "full_live_e2e": "BLOCKED_NOT_APPROVABLE_AS_COMPLETE_E2E",
    "host_selection": [
      "SYSLOG_FACILITY=4",
      "SYSLOG_FACILITY=10",
      "+",
      "_COMM=sshd"
    ],
    "if_dispatch": "INTEGRATION_MISSING",
    "if_native_training_parity": "UNVERIFIED",
    "lifecycle_managed_by_start": true,
    "mode": "MANAGED_READ_ONLY_CHILD_PENDING_EXACT_HOST_APPROVAL",
    "runtime": "/home/geonug/kdt-linux/autonomous-soc-agent/.git/final-full-live-validation-prep-20261103T095545Z/candidate/native/future-runtime/authentication",
    "thresholds": {
      "assurance": "PROPOSED_UNVALIDATED_NOT_OPERATOR_APPROVED",
      "multiple_accounts": 3,
      "repeated_failures": 5
    }
  }
}
```

## Root8경로 — 변경 제안3 / 검증전용5

- VERIFY_ONLY `/etc/systemd/system/soc-continuous-collector.service.d/trial-limit.conf`: `4b36f322ef409220bfd1c5bae7ef30b36022caf40f85a2f812b9c2a47f46a002` → `4b36f322ef409220bfd1c5bae7ef30b36022caf40f85a2f812b9c2a47f46a002`
- VERIFY_ONLY `/etc/systemd/system/soc-continuous-tcp-trial.service`: `c78030d783a01e03cf3a2ab2df41df14889cb748bde1ed4d7d8068dc30cc4f4b` → `c78030d783a01e03cf3a2ab2df41df14889cb748bde1ed4d7d8068dc30cc4f4b`
- CHANGE `/etc/soc-agent/continuous-installation.json`: `d2d56ba8b9b7185a365db763f75a7a20c0c6eea1794e0b25e40de4a57284a359` → `bb5d292989e433421b337b0ddbe688793e2bcf9d7ab66d43f3dd7ad50f7414a3`
- CHANGE `/etc/systemd/system/soc-operations-runtime.service`: `02d4644162cbadba5dabdfbf2b8daa5e52fa7c8b02b32a3efd9f731b308a4ec2` → `5626ed312100da13a5b0579c4cc960f4872a528d8f758f50e8bc4b73b3900e4d`
- CHANGE `/etc/systemd/system/soc-continuous-dns.service`: `1fa70b4c29e5b841fec12e9512d35aede2c810ef6675992255f34bfd272a7e5b` → `62a82c6a0610b4843a056455ca38768a41c2a4c6d4db720acf95a97388eb80cf`
- VERIFY_ONLY `/etc/systemd/system/soc-continuous-dnsmasq.service`: `1f7a36c1767089c38c4328324f74d4e68dc33a1804173adcc988657ecf5ec55f` → `1f7a36c1767089c38c4328324f74d4e68dc33a1804173adcc988657ecf5ec55f`
- VERIFY_ONLY `/usr/lib/soc-agent/continuous/service.py`: `075dba6a3a8570baad587add5047ed3722e159b5ce2baba7e4addf1b0a35e6b9` → `075dba6a3a8570baad587add5047ed3722e159b5ce2baba7e4addf1b0a35e6b9`
- VERIFY_ONLY `/etc/systemd/system/soc-continuous-dns.service.d/trial-deadline.conf`: `61257ee34448f64716b75b4e97f5e619a2d3866ed7461ca89919d966e259cad9` → `61257ee34448f64716b75b4e97f5e619a2d3866ed7461ca89919d966e259cad9`

## 고유 Rollback 제안 경로

`/var/lib/soc-agent/continuous/backups/final-full-live-validation-prep-20261103T095545Z` (생성/교체하지 않음).
