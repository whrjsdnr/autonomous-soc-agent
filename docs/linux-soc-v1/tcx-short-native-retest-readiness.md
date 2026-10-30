# TCX Timeout 수정본 짧은 Native Packet·DNS 재시험 준비

2026-10-30. 판정: **PREPARED / PENDING_FRESH_SCOPE_APPROVAL**.
이번 작업은 기존 운영 코드 `68209cf`와 최종 회귀/보고 `2674a90`의 실환경 검증 준비다.
새 기능·승인/예산 시스템을 개발하지 않았다. Root·sudo·Namespace 진입·TCX·DNS 트래픽·
모델·API·실행 예약·영수증 발급/소비·기존 Ledger 쓰기를 수행하지 않았다.

## 정확한 Binding과 하나의 검토 패키지

검토서: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-short-native-review-20261030T055230Z/review/approval-package-final.md`.
통합 요청서: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-short-native-review-20261030T055230Z/review/approval-request-final-v2.json`.
Identity: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-short-native-review-20261030T055230Z/final-artifact-identity.json`.
운영 Source가 동일한 HEAD의 독립 Git archive/export와 동결 worktree를 새로 만들었다.
아래 Git은 동결 Source의 Git이다. 이 준비 보고서의 별도 문서 Commit과 혼동하지 않는다.

| 항목 | 값 |
|---|---|
| 동결 Git | `2674a90464a1750e0765c32ce42c3f0dd224bb5b` |
| Git Tree | `4acfcc5b85b867f50d41e59093d3ea4d4a8950f6` |
| Source canonical digest, 668개 | `9f2bf1ae660979bb224c8807415985ca572a13f256c90348a2137874c9758b96` |
| Source archive | `ea5ab06dc2b975c373be96baaabc4c106eac0a80b8217320bea6b88ea619e90f` |
| Wheel | `b7f0504cecce4388fdee8d3699a554daa80213de20c19f7791d02ef115838ed6` |
| Root Manifest | `d86e20cc53ae0ba250e3a9a8df8f1c3eeb4dd7df4075788621373295e0ce58a0` |
| 요청서 SHA | `2e55e954ca50c08f3a2e5efb01291f54bd0a6b1bc014d0ea2232ce33c1a11a83` |
| 패키지 SHA | `98fee2d3c0ea0cfe8f8bdc573b0a3af0940f1107125175b62467db9c11279f2f` |
| Runtime Session | `9bb83cf2-eeea-47a1-8fc6-0311e91c32f1` |
| DNS Session | `91c76fd4-c159-43d9-b3da-7caaa6fc4202` |
| Release | `0.6.3` |
| Ledger | 81행 / `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` |
| Host / Target | `net:[4026531833]` / `net:[4026532232]` |
| Interface | `lo / Ingress` |

SHA는 기존 CLI가 자동 대조한다. 수동 입력은 없다. 기존 Source/Native/Wheel 재현 결과를 재사용했다.
Native6개·Wheel의 두 빌드 SHA가 일치하고 Source668개/패키지 Python619개가 현재 동결 Source와 같다.
Phase D의 과거 Manifest/Bundle/Execution Image 승인이나 소비된 Session을 재사용한 것이 아니다.
새 Runtime은 `STOPPED / cleanup NOT_STARTED / collection_live=false`이며 승인·Capture가 아니다.
초기 heartbeat_stale=true와 DNS 미수집 상태는 아직 시작하지 않았기 때문이다.

## 비권한 검증 결과

- 운영 Entry Point `soc_agent.cli setup --native-review` → `CONFIGURED_NOT_STARTED`.
- `doctor` → `PREFLIGHT_ONLY_NO_INFERENCE`, Source/설치본/모델 Registry/의존성 읽기 검사 PASS.
  `readiness=BLOCKED`는 Host에서 Target 내부 권한 check를 수행하지 않았기 때문이다.
  Doctor의 일반 Lease WARN과 별개로 **review-bound start Preview에서는 Lease SHA/boot/dev/inode가 검증**됐다.
- `start --preview` → `PREVIEW_ONLY_REQUIRES_DIRECT_SCOPE_R1_AND_SUDO`.
  Target 미진입·Root0·Capture0·예약0·자동재시도false, Ledger chain81행 VERIFIED.
- `status` → 초기 STOPPED. 기존 실행의 데이터나 Cleanup을 새 Session의 결과로 표시하지 않는다.
- 새 고정 coordinator 비권한 검증 **11 PASS**. Root 서비스/권한 경계만 모의하고
  실제 SHA·소스·설치본·Ledger·Lease·새 Session Binding은 기존 verify_contract에서 대조했다.
  인간 결정은 메모리 Fixture뿐이며 영수증/Scope 확인 파일을 만들지 않았다.
- 실제 Unix IPC를 쓰는 Timeout/저장지연/STOP ACK/진단 Seal/오류 보존 회귀: Workspace **16 PASS**,
  이번 HEAD의 독립 Export **16 PASS**. Kernel/패킷/DNS Live 시험이 아니다.
- 완료된 전체 Workspace·Export 각각 고유1172건 결과 및 Native6개·Wheel 재현 검증은 재사용했다.
  이전 전체1158 PASS/Fixture14 FAIL 후 수정14 PASS 이력을 지우거나 단일 전체1172 PASS로 바꾸지 않았다.
- coordinator11건 실행에서 기존 공용 pytest 임시 디렉터리 정리 경고49건이 있었다.
  기존 임시 자료를 삭제하지 않았고 테스트 실패는0이다. 새 집중 회귀는 전용 basetemp를 사용했다.
- 상세 로그·`verification-summary.json`은 위 증거 디렉터리에 있다.

## 수신·영속 쓰기와 실패 종료 경로

Native retain/applied는 기존 `storage` 직렬화/to_thread·취소 join 경로를 사용한다.
독립 IPC reader가 느린 SQLite/fsync 때문에 소비자와 함께 막히는 경로를 분리했다.
기존5초 envelope 생존 제한과 무트래픽 control heartbeat·monotonic 측정을 유지한다.
Native retry0·Producer 재사용 차단·실패 배치 tail 격리를 확인했다.

실패 시 최초 오류 → reader join → 동일 인증 채널 STOP1회 → 최대5초 bounded drain →
인증 ACK/진단 Seal 저장 → FD 종료 → Runtime Cleanup Audit → Queue/Audit flush 경로다.
늦은 Seal은 진단용이며 정상 Feature/모델 Queue로 전달하지 않는다.
ACK 누락·Binding/epoch/counter/clock 검증 실패면 UNVERIFIED다. 후속 Cleanup 오류가 최초 오류를 덮지 않는다.
이것은 비권한 경로 검증이며 실제 수정본 STOP/ACK/Seal/Cleanup VERIFIED는 아직 얻지 않았다.

## 검토할 시간·트래픽·자원 Scope

- **서비스 최대600초**. Root admission 기준500초 Owner STOP, 570초까지 Drain, 나머지 Cleanup 계획.
  정상 경로 목표 약8~10분이며 순수 Capture600초를 보장하지 않는다.
  **기존 coordinator에는 전체 프로세스 강제 종료 timer가 없어 전체 정리까지의 절대600초 보장은 없다.**
  기존 개별 명령 timeout과 정리 경로를 재사용한다. 엄격한 전체600초 승인으로 해석하면 실행 불가다.
  승인 시 서비스 제한/실제 Capture 시간/전체 Root 정리 시간을 구분해야 한다. 늦은 정리를 성공 시간으로 숨기지 않는다.
- Collector128MiB/CPU25%/Tasks4, Runtime512MiB/CPU50%/Tasks32/UID1000 Cap0.
  Queue32, Runtime 저장 점검256MiB, Root Audit 점검64MiB, 사전 여유1GiB.
  저장 점검은 hard filesystem quota가 아니다. Collector Window180초·회전4000 callbacks 유지.
- TCP: listener127.0.0.1:18080, client18081/18082. 고정 요청/응답을 유지한다.
  최대2 helper/4연결, 새 generation·최소180초 기동 간격, helper 내부35초 간격.
  TCX/DNS READY와 DNS probe 완료 후 첫 helper,380초 이후 새 기동 금지. 포트 대체/외부 연결 없음.
- DNS: 기존 dnsmasq127.0.0.53:53, native-0516.localhost IN A, UDP2/TCP1만.
  고정 ID/payload SHA, TCP close 이후35초 lateUDP·45초 관측 유지.
  DNS Helper UID1000·개방 뒤Capability0, dnsmasq는NET_BIND_SERVICE만 사용. 외부 DNS/Host 인증 없음.
- Root 고정7경로 백업/설치. **실제 내용 변경4개**: Collector trial-limit, 설치 정책 JSON,
  Runtime unit, DNS unit. 나머지 TCP/dnsmasq unit·Root service.py는 동일 bytes다.
  기존 coordinator는 동일3개도 고정 Manifest의 백업/교체 절차에 포함한다.
  Root 실행 bytes/Capability 확대·서비스 enable·추가 패키지·Host 설정 변경은 없다.
- 단일 시험1회, 자동 Native/Root 재실행0. 포트 충돌/권한/무결성/내부 check 실패 시 후속 Capture 중단.

## 승인과 필수 성공 증거

새 정확한 Source·7경로 Manifest·Session·Release·Target·Ledger에 대해 Root 설치/진입·서비스 제어,
Native Capture, TCP/DNS 트래픽/Helper, R1 잔여 위험을 한 번에 검토한다. 내부 영수증은 기존 계약으로 독립 검증한다.
현재 모든 인간 결정은 PENDING이며 기존 R1·소비된 승인·240초/1시간 실행 권한을 승계하지 않았다.
상위 만료는 **2026-10-30 17:36:32.192496 KST**. 기존 보수적3900초 입장 여유를 유지하므로
**16:31:32 KST 이전**에 Scope 확인·인증·최종 검증을 완료해야 한다. 만료/Binding 변경 시 실행하지 않는다.

필수 실환경 증거는 다음과 같다.

1. TCX 이벤트 수신·실제 Runtime Window 생성·정상 Seal·Attestation·Flow Eligibility.
2. DNS UDP2/TCP1 거래3개 및 provenance/Audit/GUI.
3. monotonic heartbeat, IPC sequence/epoch/counter, last_receive/last_validated, handoff Queue·Drop.
4. DNS Helper CLOSED·최종 Counter·STOP ACK·durable cleanup.
5. TCX STOP 요청·인증 ACK·진단/정상 Seal 구분, reader/FD 종료.
6. Queue/Audit Drain·Root-owned cleanup·Runtime cleanup을 독립 확인. Exit0만으로 성공 판정하지 않는다.
7. 최초 오류·실패 함수/행번호·실제 child exit와 후속 오류를 분리 보존한다.

**모델 Action은 이번 승인에서 제외**한다. 봉인된 ELIGIBLE 작업의 Schema/Fingerprint/Session·Window·Flow를
기존 Action 계약으로 별도 승인한 뒤에만 RF/LR를 실행한다. 미승인 상태의 모델/Prediction/Incident0은 의도된 제한이다.
DNS9·외부 LLM/API도 제외한다. GUI는 수집·Window·상태·오류·Cleanup만 실제 새 Backend에서 확인한다.

과거 Native24·DNS3·Root93.187초·Runtime Seal0·TCX ACK/Runtime Cleanup UNVERIFIED와
5.253945855초 Root heartbeat 공백의 정확한 syscall/scheduling/I/O 원인 UNKNOWN을 보존한다.
기존 Helper/Root 소유 정리 VERIFIED는 해당 시험 Scope에만 유효하며 과거 전역 Cleanup을 소급 승격하지 않는다.

## 실제 사용 명령

아래 조회/Preview는 비권한이다. 경로를 줄이기 위한 셸 변수는 SHA나 승인 값이 아니다.

```bash
cd /home/geonug/kdt-linux/soc-one-command-runtime
SOC_SHORT_HOME='/home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-short-native-review-20261030T055230Z/agent-home'
.venv/bin/soc-agent doctor --home "$SOC_SHORT_HOME"
.venv/bin/soc-agent start --preview --home "$SOC_SHORT_HOME"
.venv/bin/soc-agent status --home "$SOC_SHORT_HOME"
```

정확한 새 패키지 승인 후 사용자 터미널에서만 다음을 실행한다. **이번 준비 작업에서는 실행하지 않았다.**

```bash
.venv/bin/soc-agent start --gui --home "$SOC_SHORT_HOME"
```

기존 CLI가 Scope/R1 yes → 사용자 직접 sudo → 내부 check → 새1회 시험으로 연결한다.
중단은 다른 터미널의 `soc-agent stop --home "$SOC_SHORT_HOME"`이고, GUI 종료만으로 Collector를 종료하지 않는다.
비밀번호/TTY 입력/API키를 기록하지 않는다. 실패하면 자동 재실행하지 않는다.
짧은 시험의 실제 ACK·Seal·Helper/Root/Runtime Cleanup이 성공한 뒤 새1시간 통합 Scope를 준비한다.
현재 판정은 준비 완료/새 Scope 승인 대기이며, 실환경 OPERATIONS_VERIFIED가 아니다.
