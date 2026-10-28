# Autonomous SOC Agent — Native E2E Execution Path Stabilization

## 판정

코드 경로 통합 완료 / 비권한 사전 검증 PASS. 남은 작업은 정식 정책·실행 승인, 승인 후 이미지 재생성 및 실환경 검증이다. 추가 코드 수정 없이 기존 CLI에서 진행할 계약을 구현했다. 실제 Root·Native·DNS·컨테이너·LLM API 실행은 수행하지 않았다. 승인 영수증 발급·소비, 실제 실행 예약·예산 변경도 0건이다.

`READY_FOR_NATIVE_E2E` 최종 판정은 아래 준비 검증과 승인 상태를 구분한다. 현재 실제 Namespace 이미지는 정책이 없는 Guarded Review Artifact이며 실행 Gate는 `BLOCKED / ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED`이다. Root 진입·Controller·Docker 분석의 실환경 동작은 PENDING이다. 이것을 Native 검증 성공으로 간주하지 않는다.

## Namespace Controller RCA와 운영 경로

기존 실행 실패는 Root/Supervisor/Controller가 같은 Namespace에 있어야 한다는 계약과 Host에서 시작한 Controller의 충돌이었다. 이 검증을 삭제하지 않았다. 기존 Namespace 생성 Lease와 실제 inode를 재사용하는 DNS 전용 Root Launcher에, DNS 진단 후 일반 사용자 Controller로 전환하는 고정 경로를 구현했다.

1. Host의 일반 사용자 CLI에서 Source·Artifact·Lease·정책·최신 Ledger·Root 예산을 검증한다.
2. 직접 Scope 확인 후에만 기존 `ROOT_DNS_DIAGNOSTIC` 예약을 생성하고 새 sudo 인증을 받는다.
3. 기존 최소 권한 DNS Worker가 전용 Namespace의 UDP2/TCP1·35초 관측·45초 종료·Socket Cookie·Cleanup을 검증한다.
4. 승인된 Root 프로세스가 held nsfs FD로 같은 Namespace에 진입한다. 외부 Interface·Route, inode/device/boot 변경은 거부한다.
5. UID/GID/saved ID를 원 사용자로 내리고 E/P/I/A=0을 확인한다. 원 계정이 이미 보유한 Docker 그룹만 유지한다. Namespace 생성·삭제·Host 서비스 변경은 하지 않는다.
6. Host Coordinator가 PID·UID·Namespace를 대조하고 Root 진단만 Append-only로 정산한다. Controller는 정산 ACK와 Ledger 무결성이 확인되기 전에는 다음 단계로 진행하지 않는다.
7. Namespace 안의 일반 사용자 Controller가 **정산 후 Ledger에 결합된 새 Native 요청**을 검증한다. 기존 `native-recovery check`가 통과한 경우에만 기존 `execute`를 호출한다. Scope 직접 확인·별도 새 sudo·R1/R2·예산 예약 계약은 유지한다.

이는 단일 Root 승인의 승계가 아니다. DNS/Controller Root 진단 1회와 Native 설치·Capture는 독립적인 승인·OS 인증·정산을 사용한다. Root 진단 이후 Ledger가 바뀌므로 이전 Native 승인 요청을 재사용하지 않는다. 일반 Controller가 나중에 별도 sudo 인증을 할 수 있도록 원 bounding set과 NNP=0을 유지하며, DNS Worker의 bounding set=0 / NNP=1 계약은 바꾸지 않는다. 이 차이와 sudo private PTY의 원 사용자 소유권 복구는 새 Launcher Scope에 명시했다.

`namespace_controller`는 고정된 기존 CLI 요청만 허용한다. Shell·임의 argv·다른 Namespace·다른 실행 Artifact를 받는 범용 Root Launcher가 아니다. 기본 정책은 비활성이며 현재 실제 영수증을 만들지 않았다.

## Docker·DNS Sidecar RCA

Phase D의 Root Supervisor는 live-Zeek 컨테이너를 실행하지 않는다. 기존 경로는 Root의 제한된 Packet Copy를 일반 사용자의 Offline Zeek 분석 컨테이너로 전달한다. 그런데 사용하지 않는 Root Docker API 연결 및 Host daemon Namespace 일치 검사가 필수로 실행돼 격리 Namespace 준비를 막고 있었다.

Phase D Root 경로에서만 불필요한 daemon 연결을 제거했다. 이 경로의 START_ZEEK는 명시적으로 거부한다. 별도로 승인되는 기존 live-Zeek 경로의 daemon 버전·Namespace·컨테이너 소유권 검증은 유지한다.

분석 컨테이너는 기존의 pinned image / `--pull=never` / `--network=none` / cap-drop ALL / ordinary UID / read-only / no-new-privileges / bounded memory·CPU·PID·output·Cleanup 계약을 그대로 사용한다. Host 네트워크 공유나 새 Capability를 추가하지 않았다. 현재 Host에서 pinned Docker image의 읽기 전용 조회는 통과했다. 컨테이너 시작은 수행하지 않았다.

TCX/Root 프로세스의 256MiB·CPU20s와 기존 Zeek 분석 컨테이너의 별도 512MiB 제한은 서로 다른 기존 계약이다. 합산 256MiB로 검증됐다고 보고하지 않는다. 실제 실행 승인 Scope에도 이 구분이 필요하다.

전용 Namespace의 DNS responder는 Root 인증 후, TCX 권한 FD가 생기기 전에 시작한다. responder READY는 2초로 제한하고 실패하면 소유 자식을 닫는다. 분석 Deadline 10초, responder 최대 60초, R2 TCP close+35초·약45초 STOP은 각각 별도 기준을 유지한다. 서로 연속한 소유 TCP listener의 TIME_WAIT 재바인딩을 위해 SO_REUSEADDR을 사용하며 SO_REUSEPORT나 기존 listener 채택은 허용하지 않는다.

## 실제 수정한 운영 코드

- `namespace_controller.py`, `namespace_controller_engine.py`: 기존 Root-only 진단·Ledger·claim·Scope 검증 재사용, Namespace 진입 후 일반 Controller, 정산 ACK, 최신 Native 요청, 소유 Source·인터프리터 검증.
- `namespace_runtime.py`, `namespace_runtime_engine.py`: exact Namespace/Lease/Root Manifest/Source/Dependency/UID/GID에 결합된 최대24시간 build-policy 검증. 실제 Root·Native·트래픽 권한은 부여하지 않는다. Root에서 실제 sudo UID/GID를 재검증한다.
- `supervisor.py`, `phase_d.py`, `supervisor_startup.py`, `unified_image.py`, `recovery_policy.py`: Namespace 정책이 없으면 기존 Preview guard 유지. 유효한 별도 승인 후에는 동일 Builder로 Namespace 운영 이미지를 생성할 수 있다. Source 검증과 실제 현재 Namespace 실행 검증은 분리하고, 실행 시 동일 Namespace 검증은 유지한다.
- `supervisor_engine.py`: Phase D의 불필요한 Root Docker 의존성 제거, responder 생명주기·READY·Cookie·실패별 Cleanup 연결.
- `r2_diagnostic.py`: 기존 Host Scenario는 변경하지 않고, Namespace policy SHA를 필수로 갖는 별도 IsolatedScenario를 추가했다. Host 승인은 새 Scope에 사용되지 않는다.
- `offload_session.py`, `dns_copy_engine.py`, pinned stdlib DNS Probe: 실제 승인 Namespace를 사용하며 responder와 Packet Copy Socket Cookie를 대조한다. Probe plan은 소스를 실행하지 않고 AST에서 복원·해시한다.
- `ebpf_native/application.py`: network-only setns 이후 Host sysfs를 인터페이스 증거로 읽던 결함을 socket ifindex 조회로 수정했다.
- `dependencies.py`: 비어 있는 Source 파일 검증만 명시적으로 허용하는 옵션을 추가했다. 실행 파일·의존성의 기존 nonempty 기본 검증은 유지한다.
- `root_operations.py`: 기존 ROOT_DNS_DIAGNOSTIC과 4회 예산 내에서 새 정확한 Controller Scope를 검증한다. 새로운 예산 이벤트·환급·소비 영수증 재활성화는 없다. 정책/작업 승인자의 일치도 검증한다.

기존 명령만 확장했다: `native-recovery prepare --namespace-config <JSON> --namespace-config-sha <SHA>` 및 `prepare/check/execute --namespace-controller-file <JSON> --namespace-controller-sha <SHA>`. 새 실행 명령이나 승인 프레임워크를 만들지 않았다. 실제 JSON CLI에서 발견한 Path 복원 오류를 수정하고 회귀 테스트를 추가했다.

## Native AI·Incident·LLM·Audit

Capture는 전용 Namespace, AI·LLM 조사는 Host의 일반 사용자 후처리 경로로 분리한다. 외부 Route가 없는 Namespace에서 LLM API를 호출하도록 만들지 않았다.

Native TCX 결과 → Capture/Clock/Flow 재판정 → Network14 → 별도 exact retained-analysis action 승인 → 실제 RF/LR → Evidence Fusion → Incident → 조사·Audit의 기존 경로를 재사용한다. `soc-agent analyze-offline`이 저장 결과의 SHA·Namespace·Session·Release를 검증한다. 적격 벡터가 없거나 모델 Schema/승인이 맞지 않으면 추론을 차단한다. 새로운 데이터에 대한 Medium action 승인과 실제 API 사용 권한은 Capture 승인으로 대체하지 않는다.

실제 PCAP 정상 사례는 RF/LR CLASS_0/CLASS_0 → NORMAL, 이상 사례는 CLASS_1/CLASS_1 → UNKNOWN_ANOMALY → SCRIPTED 읽기 전용 조사·평가·Audit로 재검증했다. 적격 TCX FIXTURE는 실제 RF/LR의 불일치 결과를 기록하며 Native 성공으로 분류하지 않았다. 현재 테스트의 실제 LLM 호출은 0회다. 기존 실제 API 2회 E2E의 저장된 plan·tool·evaluation·Incident·Audit·Usage 영수증만 다시 검증했다.

과거 실제 Native 후보는 여전히 INCOMPLETE4 / UNKNOWN5 / ELIGIBLE0이며 모델·LLM 호출은 0이다. P02·P03은 INCOMPLETE, Native P04 ELIGIBLE0을 유지한다. DNS Transaction 수집과 DNS9는 별도이며 DNS9 학습 추출 계약 부족으로 추론은 계속 INCOMPLETE/BLOCKED다. Native AI·운영 승격은 승인하지 않았다.

## 비권한 검증

최종 수정본 Workspace **1,707 PASS (348.14s)**, 독립 Export **1,707 PASS (352.72s)**. 신규 Namespace 경로 집중 테스트 **30 PASS**. Ruff·Format·Diff PASS. Source **1,767개** 일치. Supervisor Stage/A/B **26/26**, Controller Launcher Stage/A/B **2/2**, Wheel **682 entries / byte-identical**. 실제 Kernel 권한 실행이 없는 범위에서 검증했다. 임시 Ledger·모의 syscall·가짜 승인·Fake Namespace는 테스트 전용이며 실제 Root·Namespace 진입·Native 증거가 아니다.

기존 테스트를 삭제하거나 assertion을 약화하지 않았다. 새 TCP listener 옵션을 검증하도록 기존 socket fixture를 확장했고, 원래의 Host Scenario 거부·FD Cleanup assertion을 유지했다. Namespace 정책/Source/UID/SHA 오류, Docker 미가동·legacy Namespace 불일치, Phase D live-container 거부, Worker READY/STOP 오류, 정산 전 실행 차단, 승인 누락, Scope 거부, Git 확인 중 변경, Source 변조, 기존 정책/예산/Replay/Checkpoint 회귀를 검증했다.

## 보존·예산·실환경 대기

실제 Namespace inode 4026532232, Host net:[4026531833] 유지. Lease·inode/device/boot는 읽기 전용으로 확인했다. 내부 lo/route/socket-cookie 및 Controller/Docker/Supervisor의 실제 동작은 PENDING이다.

Ledger 26행과 SHA 7f61dbdcd8e589e40f8b11d405a435c4057223ab6738005984abbd5902b59c5f, 보호 파일112개, 실제 Native 증거55개, 설치9개·Rollback9개, 다른 작업 트리의 기존 사용자 변경을 대조했다. 기존 FAILED / safe_for_next_attempt=false / Program1145 원인 UNKNOWN / 과거 EVIDENCE_INCOMPLETE 및 Root·Native UNKNOWN은 보존한다.

Campaign Native4/10·Root5/10, Batch3 Native1/2·Root2/4 유지. 계획상 DNS/Controller 진단 Root1회 후 Root6/10·Batch3 Root3/4이며, 별도 Native 설치가 필요하면 Root1회와 Native1회를 추가할 수 있다. 실제 비용은 기존 Ledger 계약과 release 교체 필요 여부를 다시 검증한다. 오늘 예약·영수증 소비·Root 인증·Capture·DNS·컨테이너 시작·API 호출은 모두 0이다.

## 남은 승인 순서

1. 현재 Source/Root Manifest/Dependency/Lease에 결합된 Namespace build-policy 인간 승인. 현재 Review 이미지의 guard는 해제하지 않았다.
2. 승인된 정책을 넣어 기존 prepare로 운영 Artifact 재생성 후 새 SHA 확정. 이전 SHA/영수증 승계 금지.
3. 새 DNS/Controller Launcher에 대한 기존 Root policy 활성화·정확한 ROOT_DNS_DIAGNOSTIC Scope/예산 승인 및 사용자 직접 확인·sudo.
4. Root 진단 정산 후의 최신 Ledger에 대해 새 R1 UNKNOWN 위험 수용, R2 트래픽, Root/Native exact SHA 승인 요청 발급·검증. Namespace Controller에서 비소비 check가 통과한 경우에만 직접 Scope 확인·새 sudo로 최대1회 실행.
5. 실제 Raw 결과를 Host의 기존 분석 CLI에 전달. ELIGIBLE일 때만 exact 모델 분석 승인으로 RF/LR을 호출하고, 실제 이상이 관측됐을 때 승인된 API 조사로 이어간다. 정상 결과를 공격으로 바꾸지 않는다.

오늘 이 승인 절차나 입력 대기 터미널을 시작하지 않았다. Namespace·VS Code·서비스를 종료하지 않았다. Native 자동 재실행은 금지한다.

## Artifact SHA 및 Git

아래는 현재 정책 미승인 상태의 **Guarded Review Artifact**이다. 정책 영수증을 포함하면 실행 이미지 SHA가 달라지므로 승인 후 재생성·exact SHA 재승인이 필요하다. 현재 SHA를 운영 실행 승인으로 승격하지 않는다.

| 식별자 | SHA256 |
|---|---|
| Source Snapshot | `f898540a9a9ce4e9afc6381393ce842e949b415830cc89303e688ddb573d893c` |
| Capture Manifest | `ae64e96d3694542ca562c24011e5a9990094c2421c8b5583fdc5feab9139fe9d` |
| Supervisor Execution Image | `f7ba740cec4e098aa2fb56ffb921859cd8c247a3e560b8dcd2a7cc1b57bfc7ae` |
| Root Manifest | `b345fe558b34fcf547b37e807533b5ff474e834fb74246fee84ae11e2ff22866` |
| DNS/Controller Manifest | `c9b7633c663bdc7ff7e836725473fe5b2a0e41d279c42e2ceeff1f5780d7af5c` |
| DNS/Controller Image | `c6a956dec87b48530ad05fc48ee8bd17fe1f35ecd29f0f5ebcb37fe86d5210a7` |
| AI/CLI Wheel | `e64070fdb0e615072215786579f99bf8f889f64d067e7d4d230a0247c29b714d` |
| Runtime Dependency Identity | `e387709bafde9db7df6978b4f0d5a18a3f7a807ead408530b3a95325bfdb5cf4` |
| Runtime Source Bundle | `419c1fb5d6c45195e0c7ca37503e9e3ed213fbe76470731fc601b1dcfc091499` |

검증한 코드 Commit: `f2197bf5b6850bed9a908c3b7802c3f03ed103ec`

Code Tree: `650f40d5eb825d5821579a052855d59278b55d20`

후속 보고서 전용 Commit은 구현 bytes와 Source Snapshot을 바꾸지 않는다. 실행 승인 Binding에는 최종 HEAD·Tree를 다시 기록한다. `artifact-identity.json`, `controller-binding-proposal.json`, `approval-readiness-package.json`, `final-git-verification.json`이 최종 검토 기준이다. 승인 패키지는 영수증이 아니며 결정은 PENDING이다.

현재 Runtime은 zlib ubuntu2.3 보안 업데이트를 유지한다. Python build interpreter는 cpython3.12.14이며 libbpf1 1.3.0-2build2, libelf1t64 0.190-1.1ubuntu0.1을 기록했다. 이전 Runtime/Artifact SHA를 재사용하지 않았다.

Private evidence: `.git/native-ai-execution-path-20261028-1/` (공통 원본 저장소). Source·테스트 로그·빌드별 SHA·구현 중 실패 자료·검토 패키지를 보존했다. Wheel에서 기존 분석 CLI 검증과 비소비 readiness도 확인했다. Secret scan은 실제 키 값을 출력하지 않고 수행했다.

## READY_FOR_NATIVE_E2E 최종 판단

**코드·비권한 준비 검증은 완료했다.** Controller·Docker 경로의 확인된 구현 결함은 수정됐고, 실행 전 추가 개발을 전제로 남긴 경로는 없다. 다만 현재 Artifact는 정책 미승인 guard 상태이며 `native-recovery check`는 승인 미확보로 BLOCKED를 반환한다. 따라서 **실제 실행 가능한 Artifact라는 의미의 READY_FOR_NATIVE_E2E는 아직 선언하지 않는다.** 정책·새 SHA·R1/R2·Root/Native 승인을 확인한 뒤 실제 실행 준비 상태를 재판정한다. Controller·Docker의 실환경 동작은 PENDING이며 P02·P03·P04와 별개다.

Git Push는 보고서 Commit 후 remote HEAD 일치로 확인하며, 실제 실행을 시작하는 터미널이나 사용자 인증 요청은 생성하지 않는다.

## 2026-10-28 10:09 KST 최종 승인 사전 검증

최종 검토 코드 HEAD `773fbed2dd8dd41c8b13e21174f98b8c4b06dcc0`, Tree `7db4bf948f4c46f6cadc7da1880848d6304a085c`의 Source1767개와 설치·Rollback 각9개를 재검증했다. 보호 증거112개·과거 Native55개와 Ledger26행도 불변이다. Namespace lease/inode4026532232와 Host4026531833을 확인했으며 내부 진입은 하지 않았다. Runtime dependency Identity는 기존 핀과 일치한다.

기존 CLI `native-recovery check`의 현재 결과는 `BLOCKED / ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED`이며 reserved=false, executed=false다. 이번 요청은 실행 승인을 대신하지 않으므로 정책 영수증을 발급하지 않았다. Root·Native·DNS·API·예약·승인 소비는 모두0이다. Campaign Native4/10·Root5/10, Batch3 Native1/2·Root2/4를 유지한다.

단일 승인 검토 자료: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/native-ai-final-approval-20261028T010926Z/approval-package.md`. 기계 검증 요청서 `approval-package.json` SHA256 `b600018fd45498b48d9598fb941e33c1876b797d71d87170c72a6631a1a26a70`. 현재 필요한 결정은 정확한 Namespace 빌드 정책 Binding의 활성화뿐이다. 정책 영수증 포함 후 이미지 SHA가 변경되므로 현재 Guarded SHA의 실행 승인은 요청하지 않는다. 비권한 재빌드 후 새로운 SHA·Session·Scope로 Root DNS/Controller 승인을 요청하고, 그 정산 이후 최신 Ledger에 맞춘 R1/R2·Root 설치·Native 승인을 독립 검증한다.

현재 검토 Session `a9ac5504-15f8-402d-bf5e-a3416c0ee77b`, Release0.6.3. 정확한 모델 분석 입력은 Capture 이후에만 확정 가능하며 기존 MEDIUM 분석 승인을 생략하지 않는다. 실제 이상에 대한 API 계획·평가의 최대2회 호출 제한을 유지한다. Native E2E·Controller·Docker 실환경은 PENDING이며 READY를 선언하지 않는다. 코드 변경은 없어 기존 Workspace/Export1707 PASS·재현 빌드 증거를 재사용했다.

## 2026-10-28 Isolated Namespace Supervisor 정책 승인 적용

승인자 조건욱(프로젝트 소유자 및 정책 승인권자)의 이번 명시적 `APPROVED_WITH_CONDITIONS` 결정을 기존 `SOC_NAMESPACE_SUPERVISOR_BUILD_POLICY_V1`의 제한된 `APPROVED` 영수증으로 기록했다. Root·Native·트래픽 권한은 모두 false다. 새 승인 체계나 정책 우회 코드는 추가하지 않았다. 정확한 원 요청서 SHA `b600018fd45498b48d9598fb941e33c1876b797d71d87170c72a6631a1a26a70`와 Source·Runtime·Lease·Root Manifest Binding을 대조했다.

- 승인 시작: `2026-10-28T10:12:06+09:00`
- 승인 만료: `2026-10-29T10:12:06+09:00`
- 정책 영수증 SHA256: `1124b26ef851fdcebaac26739a6411b8c119e17029bebf9a5a8a42b86f021c98`
- 영수증 파일: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/approved-namespace-supervisor-20261028T011206Z/namespace-policy-receipt.json`
- 인간 결정 근거: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/approved-namespace-supervisor-20261028T011206Z/human-approval-reference.json`
- 정책 활성화: **승인 Binding의 비권한 빌드에 적용 완료**. 실행 권한 부여 없음.

요청서 검토 Artifact의 Git은 `773fbed2dd8dd41c8b13e21174f98b8c4b06dcc0`이며 기록 당시 HEAD `ae1003f6d6c86aa29cdf862e64b159561f3b715d`와의 차이는 본 보고서뿐임을 검증했다. Source Snapshot 1767개는 모두 동일하다. 새 Artifact 실행 Binding은 보고서 Commit 후 최종 HEAD·Tree로 별도 고정하며 과거 실행 영수증은 재사용하지 않는다.

### Ledger 및 예산

기존 Campaign writer의 잠금·체인·fsync 경로를 사용해 `NAMESPACE_SUPERVISOR_BUILD_POLICY_ACTIVATED_V1` 이벤트를 Append-only로 1건 기록했다. 기존 26행 bytes는 변경되지 않았으며 현재 27행이다. 이벤트에는 원 요청서 SHA·정책 SHA·인간 결정 근거 SHA·정확한 Binding 및 실행 권한 없음이 연결돼 있다. 동일 요청/정책 Binding Replay와 오래된 tip은 쓰기 전에 거부되며, 검증 과정에서 추가 이벤트나 예약은 생성하지 않았다.

Campaign Native4/10·Root5/10, Batch3 Native1/2·Root2/4 유지. 예산 환급·확대·이전 영수증 재활성화 없음. **기존 Root 추가 배정 영수증 만료는 2026-10-28T15:47:27+09:00**이며 이번 정책의 새 만료 시각으로 연장되지 않는다. 만료 이후에는 기존 한도 재평가와 필요한 인간 예산 승인이 별도로 필요하다.

### 신규 Artifact Identity

| 항목 | SHA256 |
|---|---|
| Source Snapshot | `f898540a9a9ce4e9afc6381393ce842e949b415830cc89303e688ddb573d893c` |
| Capture Manifest | `ee628c615265f9ac4efa7f665adbd9e7a6956999ccbbcc65356b0c332311f8dc` |
| Runtime Source Bundle | `419c1fb5d6c45195e0c7ca37503e9e3ed213fbe76470731fc601b1dcfc091499` |
| Supervisor Execution Image | `cf9c0a765ba3a4fdd86c0bb39ea53446103d10d48191a5d708a0395a6ce246e9` |
| Root Manifest | `b345fe558b34fcf547b37e807533b5ff474e834fb74246fee84ae11e2ff22866` |
| Runtime Dependency Identity | `e387709bafde9db7df6978b4f0d5a18a3f7a807ead408530b3a95325bfdb5cf4` |
| DNS/Controller Manifest | `d9c2af66828cf35e9a09ce6a65e0084b1d4cb6bbdeff09acbae414f44c3b4181` |
| DNS/Controller Image | `8eddb1b052b4eba310640e186a3c78ecf736f73c2d3c41259b4fb8e45233659e` |
| RF model | `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` |
| LR model | `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882` |

승인 영수증이 Supervisor image에 포함됐고 preview=false 및 계약 `SOC_PHASE_D_NAMESPACE_V1`을 검증했다. CLI prepare 상태는 `RUNTIME_APPROVED`, executed=false다. 정책 영수증 때문에 Manifest/Image가 변경됐다. Source Bundle·Root Manifest는 동일 입력이므로 동일 SHA이며 이 사실이 실행 승인 승계를 뜻하지 않는다. Runtime과 RF/LR 모델 bytes·기존 seal 계약도 재검증했다. 실제 모델 추론이나 API 호출은 수행하지 않았다.

### Source·Export·Stage 및 재현성

- Workspace 관련 회귀: **90 PASS, 105.15초**.
- 독립 Export 관련 회귀: **90 PASS, 103.77초**.
- 대상: Namespace runtime/controller, operational recovery, Root operations. 전체1707 PASS는 이전 변경본의 기존 결과이며 이번 전체 회귀로 다시 수행한 수치가 아니다.
- 승인된 Supervisor Stage/A/B: **26/26 동일**.
- DNS/Controller Stage/A/B: **2/2 동일**.
- 독립 Export의 Source1767개와 Workspace·원 핀 일치. Stage 검증은 기존 `validate_preparation`을 사용했고 실제 Namespace 진입을 대신하지 않는다.
- 정책 만료·다른 Namespace Binding·MOCK 승인자·Root/Native/트래픽 권한 확대를 거부했다.
- Ruff check PASS, Format1426개 PASS, Git Diff Check PASS.
- 기존 사용자 변경, 보호 증거112개·과거 Native55개·설치/롤백 각9개·Namespace lease/inode4026532232 보존.

### 비소비 check와 남은 승인

Host `net:[4026531833]`에서 기존 CLI `native-recovery check` 실행 결과는 **BLOCKED / PHASE_D_COLLECTOR_SCOPE_MISMATCH**다. reserved=false, executed=false. 이전 `ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED` guard는 해소됐으나, 현재 프로세스가 승인 대상 Namespace 내부가 아니므로 실제 실행 검증은 차단되는 것이 맞다. CLI가 환경 검사에서 먼저 멈추므로 R1/R2 검증을 통과했다고 주장하지 않는다. 별도의 비권한 준비 검증으로 정책·Source·Runtime·Artifact 무결성을 확인했다.

다음 요청서는 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/approved-namespace-supervisor-20261028T011206Z/next-approval-request.json`에 준비했다. DNS/Controller Root 정책·정확한 실행 승인(UDP2/TCP1, Root1·Native0)이 먼저 필요하며, 그 작업의 정산 후 최신 Ledger에 맞춘 새로운 R1 위험 수용 및 R2·Root 설치·Native 최대1회 승인이 필요하다. 실제 적격 데이터가 나온 뒤 모델 분석에 필요한 기존 exact-input 승인도 유지한다. 실제 이상에 대한 API 사용은 최대2회 및 별도 실행 범위 확인을 유지한다.

실제 Root·sudo·Namespace 진입·DNS·Native·TCX·컨테이너·LLM·예약·예산 소비는 모두0. 기존 FAILED·false·Program1145 UNKNOWN·과거 예약 EVIDENCE_INCOMPLETE/Root UNKNOWN/Native UNKNOWN은 변경하지 않았다. P02/P03 INCOMPLETE, P04 Native ELIGIBLE0, Native AI·DNS9·운영 승격 BLOCKED 유지. 정책 포함 빌드는 완료했으나 **실환경 실행 승인은 대기 중이며 READY_FOR_NATIVE_E2E를 선언하지 않는다**.

상세 영수증·Ledger 전후·Stage/이중빌드 핀·회귀 로그·새 Artifact/Git Identity는 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/approved-namespace-supervisor-20261028T011206Z`에 보존했다.

## 2026-10-28 Namespace Scope 최종 RCA 및 실행 승인 준비

관측 시각 `2026-10-28T01:18:45.575135+00:00`. 검토 HEAD `688431402bc2ad5b0ca2680142dcf3523363c52b`, Tree `367fffdf7cf246b4c3726c65101ae70864db5698`와 Artifact 핀 일치. CLI→`readiness`→`phase_d.validate`→`_validate`의 Collector Scope 조건8개를 개별 대조했다. **현재 프로세스의 Namespace 불일치만 true**이며 DNS Manifest/base/Image/Source/Scope/baseline image 및 TCX program 불일치는 모두 false다. 현재 Host4026531833에서 Controller 진입 전에 검사해 발생한 오류이며 Session·Release Binding 불일치로 판정된 것이 아니다. R1 승인 검증 이전에 중단하므로 R1을 통과한 것으로 보고하지 않는다.

Source1767개·Manifest/Bundle/Image/Root Manifest·정책 영수증·Runtime·Controller 소스와 인터프리터 핀·Namespace lease/nsfs device4/inode4026532232·boot Identity·설치/롤백 각9개를 재검증했다. 기존 `validate_preparation`은 비권한 준비 검증으로만 사용했으며 실행 경로의 Namespace 검사를 변경하지 않았다. 비소비 CLI check는 `PHASE_D_COLLECTOR_SCOPE_MISMATCH`, reserved=false/executed=false를 재확인했다.

**Namespace 내부 검증은 승인된 Root 진입 전까지 PENDING**이다. 내부 lo/Route/Socket Cookie를 관측하지 않았고 Host sysfs나 Synthetic으로 대체하지 않았다. 기존 `isolated_dns_engine.enter_namespace`가 held nsfs FD·inode/device·setns 후 Identity·lo ioctl·내부 Route·Socket Cookie를 검증한다. 기존 Launcher는 실제 DNS 진단을 포함한 `ROOT_DNS_DIAGNOSTIC` 뒤 일반 UID Controller를 시작하므로, 별도의 정확한 Root 정책·Root 실행·UDP2/TCP1 트래픽 승인이 필요하다. 이를 읽기 전용 조회 권한으로 간주하지 않았다.

단일 검토 패키지: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/native-ai-scope-review-20261028T011845Z/approval-package.md`, 정확한 Binding JSON: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/native-ai-scope-review-20261028T011845Z/approval-package.json`. 현재 승인 가능한 DNS/Controller Session은 `c6ab7675-4e0b-48dc-9bd0-b2dbbfece784`, Release `0.6.3`, Scope SHA `a8938d22ace0b31ecdcb44fc106e286eae9acea72b9026369b5f0b5de48dd21a`다. 이 작업은 Root1·Native0이며, 후속 설치 최대1회는 별도 Root 작업이다. Root DNS 정산 후 최신 Ledger와 새 Native Session을 사용해 R1 위험 수용·R2·Root 설치·Native 최대1회 승인을 검증해야 한다. 아직 미정인 Native Session에 임의 값을 부여하거나 최종 실행 승인을 요청하지 않는다.

Campaign Native4/10·Root5/10, Batch3 Native1/2·Root2/4 유지. Ledger27행 SHA `b4ada4ea2f79d424b33d451ee3581e599b75523e7cf109b28027c54104e3e619` 불변. Root 추가 배정 만료2026-10-28T15:47:27+09:00, 빌드 정책 만료2026-10-29T10:12:06+09:00이며 서로 연장되지 않는다. Root·sudo·setns·DNS·Native·TCX·컨테이너·LLM API·예약·예산 소비·영수증 소비 모두0. 기존 Namespace·VS Code·사용자 변경·설치·Rollback·FAILED/false/UNKNOWN 보존.

구현 변경이 없으므로 기존 Workspace/Export90 PASS·재현 빌드 증거를 유지하고 이번 작업에서는 오류 조건·핀·비소비 CLI를 재검증했다. 실제 Namespace 내부 검사·R1/R2·Root/Native 승인이 남아 있으므로 **실제 Native E2E는 BLOCKED**이며 READY나 VERIFIED를 선언하지 않는다.

## 2026-10-28 승인된 Root DNS/Controller 실제 실행 결과

**Namespace/DNS Root 작업은 SUCCEEDED, 이후 일반 사용자 Controller 단계는 실패하여 전체 작업은 PARTIALLY_VERIFIED**로 분리한다. Native E2E 성공을 의미하지 않는다. 승인자 조건욱의 명시적 결정과 요청서 SHA `cd52896572acbfee0f85da94df0eaf85c408951f8fc6539a05579e1be3ad6231` 및 실행 Git `a6157e8bfe4acb6e3aa4c8accf27f64991eba8f3`/Tree `50f6b7f89d4b4ab1e40f90e4952606c7c4c44625`, Session `c6ab7675-4e0b-48dc-9bd0-b2dbbfece784`, Release0.6.3, Scope SHA `a8938d22ace0b31ecdcb44fc106e286eae9acea72b9026369b5f0b5de48dd21a`를 검증했다. 정책과 실행 결정은 독립 영수증이며 기존 Root Governance/CLI와 Campaign writer를 재사용했다.

- 정책 영수증 SHA: `3f4b0d9be1a6c0614658334709a2ff99af741cef5c4896a224b1205700475d24`
- 실행 영수증 SHA/Attempt ID: `fa4cf30b728b9352bc8467afc0013223510b1f97c3fd2ed6c6047f23d964fda9`
- 유효기간: `2026-10-28T10:22:44+09:00` ~ `2026-10-28T15:47:27+09:00`. 기존 예산 만료에 맞춰 24시간보다 짧게 제한했다.
- 비소비 Controller check: CHECKED_NOT_RESERVED. 사용자 전용 Windows Terminal에 Scope를 표시한 뒤 기존 CLI에서 직접 yes와 sudo 인증을 받았다. Codex가 확인 입력이나 비밀번호를 대신 제공하지 않았고 인증 입력은 기록하지 않았다.
- Ledger: Root 정책 활성화 후28행, Scope 확인 후29행 예약, START_INTENT30행, STARTED31행, SUCCEEDED32행. 기존27행 bytes 불변. 승인된 정책 추가 이벤트와 Root 상태 이벤트 외에 예약/실행을 추가하지 않았다.

### 실제 Namespace·DNS 증거

Root 인증01:23:52.905 UTC, Root 정산01:24:37.963 UTC. 기존 SOC net:[4026532232] 및 Host net:[4026531833] 유지. 내부 인터페이스는 ifindex1 lo만 있고 ioctl lo_up=true다. IPv4 Route는0건이며 IPv6는 lo 행만 존재한다. Worker baseline Socket은 승인된53번 UDP/TCP listener 각1개이며 tcp6/udp6는 없다. Host VS Code Socket과 외부 인터페이스/경로는 내부 Snapshot에 없었다. Host 서비스나 Namespace를 변경하지 않았다.

Socket Namespace Cookie는 READY·Worker baseline/after·Controller READY에서 **`9722000000000000`**로 일치한다(원본8바이트 hex). Root Controller는 UID/GID1000으로 자격을 내리고 READY를 출력했다. 실제 Python Controller main의 정상 기동과는 분리한다.

127.0.0.53:53에서 **UDP2회·TCP1회 Query/Response exact wire 검증**을 통과했다. 실제 Application monotonic timestamp(ns):

| 교환 | 송신 | 응답 |
|---|---:|---:|
| UDP1 | 492208859381366 | 492208862052640 |
| TCP | 492208862127607 | 492208864520135 |
| UDP2 | 492243864824441 | 492243865146114 |

TCP application close492208864536326ns, 추가 UDP까지 **35.000288115초**. Worker baseline→after **45.001890812초**. 이는 Application DNS 시나리오 시간이며 Kernel Capture Window·Flow Timeout·P02/P03 증명이 아니다.

Worker 완료·종료 및 listener FD 닫힘이 확인됐다. UDP 소켓 잔류0, TCP는 state06/inode0의 커널 TIME_WAIT1건으로 살아 있는 소유 FD 누수와 구분한다. 이후 최소 권한 Controller entry가 같은 Namespace/Cookie를 재검증했다. Root one-use claim은 Replay 방지를 위해 보존한다. 기존 Namespace 삭제/재생성 없음. DNS Sidecar 분석은 NOT_STARTED이므로 실제 분석 Deadline10초를 검증했다고 주장하지 않는다. Capture·DNS9 추론도 수행하지 않았다.

### 후속 Controller 오류 및 비권한 RCA

Root DNS/entry 정산은 SUCCEEDED이나 최종 CLI는 exit2였다. 정확한 stderr는 사용자 터미널에 표시되고 비밀번호 보호를 위해 TTY transcript를 수집하지 않았다. 승인된 동일 `interpreter -I`와 고정 import를 Host 일반 UID에서 실행해 **ModuleNotFoundError: pydantic**을 재현했다. 기본 Python의 canonical 경로를 사용하면서 기존 venv의 site-packages가 사라지는 구성 결함이다. import 실패는 Source/Scope 승인 검사보다 먼저 발생한다. 실환경 traceback 원문 확인 전에는 후속 오류의 다른 가능성을 완전히 배제하지 않는다.

비권한 최소 수정 검증으로 별도의 `ordinary-controller-runtime-candidate`를 표준 venv(symlinks=False, with_pip=False)로 만들고 기존 프로젝트 의존성 경로를 연결했다. 같은 -I/fixed import가 exit0, CONTROLLER_IMPORT_READY를 반환했다. 다운로드·설치·Root·Namespace 진입 없이 검증했으며 canonical executable 검사나 승인 조건을 완화하지 않았다.

**후보 환경은 미승인·미승격 상태**다. 새 Interpreter/context/dependency Identity와 Controller Image·Scope를 확정하고 별도 승인받기 전에는 사용하지 않는다. 기존 실행 이미지/영수증/Native Source1767개는 변경하지 않았다. Root·DNS를 재실행하지 않았으며 실패 결과를 수정하지 않았다. 현재 Native 실행 준비는 여전히 BLOCKED다.

### 예산·Replay·보존 및 후속 조건

Campaign Root **6/10**, Native **4/10**. Batch3 Root **3/4**, Native **1/2**. Root DNS 하위배정 **1/1 소진**, Root 설치 하위배정은1회 남는다. 남은 설치용 Root를 Controller DNS 재실행에 자동 사용하지 않는다. 추가 Controller entry가 필요하면 새 정확한 Artifact와 별도 예산/실행 범위 승인부터 검토해야 한다. 예산 만료2026-10-28T15:47:27+09:00는 유지한다.

소비된 Root 승인에 대한 비소비 check는 ROOT_APPROVAL_REPLAY, 같은 정책 활성화 반복은 ROOT_POLICY_ACTIVATION_REPLAY로 거부됐다. Ledger SHA `e7779f7315f9d3d71c9f91d0846bc4254dfc60217c84ae2be0534501763d567d`/32행, 이전 prefix·체인·보호112개·과거 Native55개·설치/rollback 각9개·기존 사용자 변경 무결성 확인. 새 Native 예약·설치·TCX·Capture·모델·LLM API·보안 대응은0. 소유 자원 검증을 전역 cgroup Cleanup 검증으로 확대하지 않았다. 기존 FAILED·false·Program1145 UNKNOWN·과거 UNKNOWN 예약은 그대로다.

후속 Native에는 Controller 환경 결함의 정식 구성 반영과 새 Binding, 최신 Ledger/새 Session의 인간 R1 위험 수용, 정확한 R2·Root 설치·Native 승인이 필요하다. P02/P03 INCOMPLETE, P04 Native ELIGIBLE0, Native AI·DNS9·운영 승격 BLOCKED 유지. 상세 영수증·실제 증거·RCA와 후보 검증은 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/approved-root-dns-controller-20261028T012244Z`에 보존했다.

## 2026-10-28 개발 예산 단순화 및 Controller Python 복구


현재 상태: 코드·비권한 검증 완료 / **정책 비활성**. 본 문서는 승인 영수증이 아니다.

## 변경된 계약

기존 Campaign/Batch 예산 파일·한도·사용량·Ledger를 그대로 유지한다. 명시적인 `development_session_sha`가 없는 요청은 기존 경로이며, Source/운영 승인 규칙과 고정 한도를 계속 적용한다.

`SOC_ISOLATED_DEVELOPMENT_METERING_V1`은 별도 인간 승인 후 기존 `native-recovery reassess --root-governance-file ... --root-governance-sha ...` 경로로만 활성화할 수 있다. 승인자·인간 결정 SHA·새 Session UUID·Namespace creation lease/origin·기존 Budget/Baseline Identity·보안 구현 fingerprint·검토된 정확한 Artifact 목록·최대24시간 유효기간을 요구한다. 활성화는 기존 체인에 이벤트1건을 추가할 뿐 실행 권한을 부여하지 않는다.

활성화된 정책을 실행별 승인 영수증이 정확히 참조할 때에만 개발 Namespace의 Campaign/Batch/Root 하위계수 한도를 OBSERVE_ONLY로 처리한다. 기존 사용량은 그대로 더해 기록하며 환급/초기화하지 않는다. 동시 실행·미종결 예약·Replay·오래된 Ledger·기존 FAILED/false/UNKNOWN·인간 R1·R2·Root/Native 승인·Scope yes·OS 인증은 유지한다.

범위는 기존 전용 Namespace `net:[4026532232]`와 고정 lo/Ingress, 300초/4096events/Queue32/256MiB/CPU20초 및 기존 Admission50ms/Clock10ms/Checkpoint16KiB/DNS10초 계약이다. 새 Namespace 생성/삭제는 개발 계측 예외 대상이 아니다. Root Install/DNS 및 Native/R1 실행 경로에 연결했다. Native 실행은 기존 R1 adapter를 사용하며 legacy admission을 우회하지 않는다.

승인된 세션에서도 승인되지 않은 새 Artifact를 자동 등록·실행하지 않는다. 검토된 목록(최대16개)과 실행별 exact SHA 영수증을 요구한다. 보안/권한 코드 fingerprint, Namespace lease, 자원·Scope가 바뀌면 거부하며 새 인간 검토를 요구한다. 이번 구현은 예산 재배정 반복을 제거하는 정책이고, 실행 권한을 자동 발급하거나 Root 승인 자체를 생략하는 정책이 아니다.

## Controller 수정

실제 Python `/home/geonug/kdt-linux/autonomous-soc-agent/.git/development-session-controller-20261028T020154Z/controller-python/bin/python`

실제 prefix `/home/geonug/kdt-linux/autonomous-soc-agent/.git/development-session-controller-20261028T020154Z/controller-python`

pydantic 2.13.5, origin `/home/geonug/kdt-linux/autonomous-soc-agent/.git/development-session-controller-20261028T020154Z/controller-python/lib/python3.12/site-packages/pydantic/__init__.py`.

기존 .venv의 import closure를 격리된 venv로 복사하고 canonical executable·pyvenv.cfg·의존성124개 파일을 고정했다. Runtime manifest SHA `c87a778581e6096f4a9f06b800ea61ae72d7181716f595d59ecdac6fbc689c0c`. 외부 .pth link 후보 환경을 실행에 재사용하지 않았다. 시스템 Python 설치·pip·다운로드 없음.

공개 API를 유지한 lazy export 및 local_events의 event-model 지연 import로 Controller 시작 시 추론 라이브러리를 불필요하게 로드하지 않는다. Controller/기존 CLI Entry Point를 -I/-B, 256MiB/CPU20초에서 실제 import 검증한다. Host check/execute와 Scope 확인 직후 예약 전에 검증하며 Root Launcher도 기존 자원 제한·exact grant 확인 뒤, claim/DNS worker 이전에 고정된 runtime 파일을 검증한다. missing runtime/변조/미승인 .pth injection은 차단한다. 실제 setns/권한 전환 재실행은 수행하지 않았다.

## Artifact / 활성화 순서

현재 산출물은 GUARDED_REVIEW_ONLY_NOT_EXECUTION_AUTHORIZED다. Source 변경 때문에 기존 Namespace/build/Root/Native 영수증을 재사용하지 않았다.

- Source 94d19bd3e62da7f2433b9c5cee2b3593b11b5e203472f1a0d0f47d604314c4fe
- Manifest b515d8922f430e4004eac67aad8db53bf9d6000d89f180dabd2ff551bc218c42
- Bundle 3fc2e1f4e9343868e5a7cffa9e8b854bb7f50db3f530f3c2757c2d2931e2c76c
- Supervisor image aca9c1daa51b21b6268f6e3ef1cefaf56d1bddc388faf7fcb0f89dde474d5bbf
- Root manifest 55081beed93ca263dc95069eb4a53a771405fdf7132eefc1b89e55f623b7b4a1
- Controller manifest 82d67465cc2d8bd5eee07ff99c6775bb192185e38081159f39e624495a33af8e
- Controller image a32d1c469903e52f81fc4ee980f8542573a02b06e6102b50f98a0a50a30a58f1
- Wheel b3a8561650eb6c1e42c3bf099fc3aeb8701390b2cefe196136a4f2af63d627e0
- 보안 구현 fingerprint 0d89cf882eb63718ff7eb4faec2f332ec68d35aae91d6c65bfbab83f5e7479ef

새 Namespace 빌드 정책의 정확한 Source/Root/Runtime Binding을 검토하고 정책 포함 운영 Artifact를 확정한 뒤 개발 계측 정책의 정확한 Artifact 목록을 승인해야 한다. 미리 알 수 없는 미래 SHA를 승인된 값으로 채우지 않는다. 기계 검토 자료는 approval-preparation.json 및 development-policy-schema.json이다. 이후 최신 Ledger의 R1/R2·Root/Native 실행 승인을 별도로 확인한다. 정책 활성화와 실제 실행은 이번 작업에 포함되지 않았다.

## 검증 및 보존

새 집중 사례24개를 포함해 최종 Source에서 Workspace **1973 PASS/23 SKIP(485.44초)**, 독립 Export **1973 PASS/23 SKIP(473.01초)**. 추가 모델 사례의 초기 실패는 사라진 예전 /tmp 경로였고, 테스트가 지원하는 환경변수로 기존 공식 Artifact/추론 Python을 명시했다. Root 파일 검증 순서의 최종 수정 후 전체 선택 회귀를 양쪽 모두 다시 통과했다. Assertion/skip/기존 테스트를 약화하지 않았으며 최초 실패 로그를 보존했다. Windows/NTFS 등23건은 SKIP다. 모델 사례는 precomputed Fixture Feature + 실제 공식 predictor이며 Native Packet 검증이 아니다.

Supervisor Stage/A/B26/26, Controller canonical JSON 입력 Stage/독립2빌드2/2, Wheel684 entries 동일. Ruff/Format/Diff PASS. 초기 private in-memory Controller dict의 key 순서가 실제 canonical CLI 입력과 달랐던 비교 실패는 보존했으며, 동일 승인 입력 파일을 재로드해 비교했다. Source를 바꾸거나 실패한 산출물을 승인된 것으로 대체하지 않았다.

Ledger32행 SHA e7779f7315f9d3d71c9f91d0846bc4254dfc60217c84ae2be0534501763d567d bytes 불변. Campaign Native4/10·Root6/10, Batch3 Native1/2·Root3/4. 기존 Root 추가배정 만료2026-10-28T15:47:27+09:00 불변. 보호112개·과거 Native55개·설치/롤백 각9개·사용자 변경·Namespace inode4026532232 보존. 새로운 정책 활성화/예약/Root/DNS/Native/LLM API 모두0. 과거 FAILED/false/Program1145 UNKNOWN 및 UNKNOWN 예약은 유지한다.

## 남은 실제 검증

새 정책의 인간 활성화, 정책 포함 새 Artifact 승인, 최신 R1/R2/Root/Native 권한 및 사용자 Scope/sudo가 필요하다. Controller 실환경 권한 전환은 재검증 대기이며, P02/P03 INCOMPLETE·Native ELIGIBLE0·Native AI/DNS9/운영 승격 BLOCKED는 유지한다. 현재 상태를 실제 Native E2E VERIFIED/READY로 선언하지 않는다.

## 2026-10-28 개발 세션 정책 승인 적용 검증


승인자 조건욱(프로젝트 소유자 및 정책 승인권자)의 APPROVED_WITH_CONDITIONS 결정을 기록했다. 접수 기록 2026-10-28T11:17:25.631004+09:00, 24시간 종료 2026-10-29T11:17:25.631004+09:00. 이는 인간 결정 접수 기록이며 활성화 영수증이 아니다.

현재 적용 상태: BLOCKED_INCOMPLETE_ARTIFACT_BINDING. 개발 계측 영수증 미발급, 활성화 이벤트 미기록. 검토된 Git b05b20cc740057c742a90675d0f3250217f9bb51 / Tree d04f3722c285ca8963183cc540aa7d14911ddc51 및 원 승인 자료를 변경하지 않았다.

## 정확한 미충족 항목

원 approval-preparation.json의 development_metering.artifacts는 배열이 아니라 `HUMAN_REVIEWED_FINAL_OPERATIONAL_ARTIFACT_IDENTITIES_REQUIRED; CURRENT_BUILD_IS_GUARDED`다. 기존 DevelopmentPolicy는 최소1개 최대16개의 정확한 Artifact 배열을 요구한다. 원 review-package.md는 새 Namespace 빌드 정책 승인 → 정책 포함 운영 Artifact 확정 → 개발 계측의 최종 목록 승인을 명시한다. 현재 승인은 개발 횟수 계측 정책에 한정되어 별도 Namespace 빌드 정책을 활성화하지 않았다. 현재 guarded 목록으로 바꾸거나 미래 SHA를 임의 승인하지 않았다. 이는 코드 결함으로 인한 차단이 아니므로 운영 코드를 수정하지 않았다.

필요한 추가 결정: 원 승인 자료의 namespace_build_policy.binding과 정확히 일치하는 `SOC_NAMESPACE_SUPERVISOR_BUILD_POLICY_V1` 활성화 승인. 이후 정책 포함 재빌드 결과의 명시적 Artifact 목록을 개발 계측 정책에 결합해야 한다. 현재 개발 계측 인간 결정 자체를 취소하거나 미래 SHA에 확대 적용하지 않는다.

검토 요청 파일: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/development-session-approval-validation-20261028T111725+0900/missing-binding-request.json`

요청 SHA256: `55e9db242eb02759ea74d282cb81efe8c309140406825327a88dd2f056e4c979`

위 파일은 승인 요청이며 영수증이 아니다. Root/Native/DNS/LLM 실행 권한을 포함하지 않는다. Namespace Scope net:[4026532232], Session 3096eab3-609f-4ee3-890c-a99cb6ee5b0d, Release0.6.3; 현재 source/root/runtime/lease/ledger Binding을 JSON에 보존했다.

## 재검증

Source1772개와 독립 Export SHA 일치. 보호112개·과거 Native55개·설치9개·Rollback9개·사용자 변경 유지. Namespace lease/inode4026532232 검증, 진입하지 않았다. 고정 Controller Python -I/-B, 256MiB/CPU20초에서 CONTROLLER_IMPORT_READY, runtime manifest c87a778581e6096f4a9f06b800ea61ae72d7181716f595d59ecdac6fbc689c0c 검증. Root 사용자 전환의 실제 재검증은 PENDING.

비소비 기존 CLI check: ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED / BLOCKED, Source VERIFIED·Runtime BUILD_INTEGRITY_VERIFIED_ONLY. reserved=false, executed=false. Ledger32행 SHA e7779f7315f9d3d71c9f91d0846bc4254dfc60217c84ae2be0534501763d567d 불변. Campaign Native4/10·Root6/10, Batch3 Native1/2·Root3/4. 과거 보고의 Root5/10·2/4보다 실제 Ledger를 우선했다. 기존 Root 배정 만료2026-10-28T15:47:27+09:00은 연장하지 않았다.

정책 포함 신규 운영 Artifact는 생성하지 않았다. 현재 guarded Stage/A/B의 Supervisor26개·Controller2개·Wheel 바이트 일치를 다시 확인했다. 이는 기존 이중 빌드 재검증이며 이번 작업의 신규 이중 빌드 수행으로 보고하지 않는다.

- Source 94d19bd3e62da7f2433b9c5cee2b3593b11b5e203472f1a0d0f47d604314c4fe
- Manifest b515d8922f430e4004eac67aad8db53bf9d6000d89f180dabd2ff551bc218c42
- Bundle 3fc2e1f4e9343868e5a7cffa9e8b854bb7f50db3f530f3c2757c2d2931e2c76c
- Supervisor image aca9c1daa51b21b6268f6e3ef1cefaf56d1bddc388faf7fcb0f89dde474d5bbf
- Root manifest 55081beed93ca263dc95069eb4a53a771405fdf7132eefc1b89e55f623b7b4a1
- Controller image a32d1c469903e52f81fc4ee980f8542573a02b06e6102b50f98a0a50a30a58f1
- Runtime dependency e387709bafde9db7df6978b4f0d5a18a3f7a807ead408530b3a95325bfdb5cf4

새 예약·예산 소비·Root·Native·DNS·API 호출0. 기존 FAILED/false/UNKNOWN 및 DNS9 INCOMPLETE를 유지한다. READY_FOR_NATIVE_E2E를 선언하지 않는다. 빌드 정책/최종 Artifact 목록 확인 후 최신 R1 위험 수용, R2 트래픽, Root/Native exact 승인 및 사용자 Scope/sudo가 여전히 필요하다.

이번 승인 적용 검증의 집중 회귀: Workspace **54 PASS(77.85초)** / 독립 Export **54 PASS(77.72초)**. 개발 계측·R1 admission·Controller Python·Namespace 빌드 정책 테스트를 수행했다. Ruff PASS, Format1431개 PASS, Diff PASS. 운영 코드와 Source Snapshot은 변경하지 않았다. 이전 전체1973 PASS/23 SKIP 결과는 과거 기준선이며 이번 전체 재실행으로 집계하지 않는다.

## 2026-10-28 정책·Artifact Binding 순서 RCA 및 복구

상태: PREPARATION_IMPLEMENTED / GUARDED / 실제 Native E2E BLOCKED. 기존 승인 자료와 영수증을 수정하지 않았고 새 영수증·활성화·실행 예약은 발급하지 않았다.

최초 불일치: 기존 Namespace 영수증1124b26ef851fdcebaac26739a6411b8c119e17029bebf9a5a8a42b86f021c98은 2026-10-29T10:12:06+09:00까지 시간상 유효하다. 하지만 Root Manifest b345fe558b34fcf547b37e807533b5ff474e834fb74246fee84ae11e2ff22866 및 Source Bundle419c1fb5d6c45195e0c7ca37503e9e3ed213fbe76470731fc601b1dcfc091499에 결합돼 있다. 작업 시작 시 기존 Guarded55081be…/3fc2e1…부터 이미 불일치했다. 이번 수정본은 아래의42a17b…/37b7a2…이다. 현재 Namespace 설정 파일에는 policy_file/sha가 없으므로 prepare_binding은 policy=None으로 Guarded 이미지를 생성하고 check는 ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED를 반환한다. 기존 영수증을 직접 대조해도 NAMESPACE_POLICY_BINDING_OR_EXPIRY로 정상 거부한다. Namespace/Lease/Boot/Runtime 의존성/UID/GID/컨테이너 Scope는 동일하며, 만료·Ledger 변경이 최초 원인이 아니다.

기존 정책 계약은 SOC_NAMESPACE_SUPERVISOR_BUILD_POLICY_V1이다. 승인 검토 Git773fbed2dd8dd41c8b13e21174f98b8c4b06dcc0 / Tree7db4bf948f4c46f6cadc7da1880848d6304a085c, Sourcef898540a…였다. 정책 영수증 자체는 Git/Session/Release/Ledger tip/최종 Manifest·Image를 직접 포함하지 않는다. 이들은 별도 승인 요청서·Artifact·실행 영수증 문맥이며, 영수증 Binding의 실제 필드를 과장하지 않았다. 원 요청서의 빌드 전 Artifact와 정책 포함 빌드 후 Artifact도 서로 다른 단계다. 전체 원본과 단계별 값은 private binding-rca.json에 보존했다.

암호학적 순환 의존성은 없다. 개발 계측 영수증은 기존 Ledger의 별도 정책 이벤트이며 빌드에 포함되지 않으므로, 최종 SHA 검토 후 계측을 활성화해도 이미지 SHA는 다시 바뀌지 않는다. Namespace 빌드 정책 입력은 Source/Root/Dependencies/Lease/Namespace이고, 정책 영수증을 이미지에 포함하면 Image와 Phase D Manifest SHA가 바뀐다. 동일 Source·영수증만 다른 테스트에서 정책 입력·Bundle·Root Manifest는 그대로 유지됐다. 문제는 준비 코드가 이 두 단계를 구분하지 않아 개발 계측 artifacts에 최종 출력 자리표시자를 남긴 것이다. 승인 영수증을 Artifact 밖으로 제거하거나 SHA 검증을 완화하지 않았다.

결정적 순서: Source Freeze → 정확한 빌드 정책 입력 검토/인간 승인 → 고정 영수증 포함 빌드 → 최종 Artifact 목록 확정 → 개발 계측 및 R1/R2/Root/Native의 독립 결정 → 비소비 check → 사용자 Scope/sudo. 빌드 전 정책 요청과 빌드 후 Artifact 검토는 서로 다른 파일로 보존하며 원 요청을 덮어쓰지 않는다. 보고서 Commit 때문에 Git Binding이 다시 바뀌지 않도록 이번 단일 Commit 후 외부 artifact-identity.json에서 최종 Git/Tree를 고정한다.

실제 운영 코드 수정:

- namespace_runtime.build_review: 승인 전 확정 가능한 policy_input/input_sha와 이미 생성된 출력 SHA, Guarded/정책 포함 단계, 다음 작업을 분리한다.
- phase_d.prepare: 기존 Builder 결과에 위 검토 정보를 포함한다. 기존 이미지·Scope·승인 Validator와 실행 경계는 유지한다.
- development_session.prepare_artifact_review: 기존 validate_preparation으로 실제 출력 검증 후 정식 Artifact 배열을 만든다. Guarded 배열과 final_operational_artifacts=[]를 구분하고 활성화·실행은 허용하지 않는다.
- 기존 native-recovery prepare의 --review-git-commit/--review-git-tree로 실제 Artifact 목록을 출력한다. Git 문맥은 운영자 제공 값이며 실행 승인의 Git 검증을 대체하지 않는다. 이번 산출물은 Commit 후 실제 HEAD/Tree 및 Source pins와 대조한다.

현재 검증된 Guarded Identity (정책 포함 운영 이미지와 구분):

| 항목 | SHA256 |
|---|---|
| Source Snapshot (1772 inputs) | b1c473bd0dd2ab63635a8ecad01dca3dde2b9f88a43c59529ad6443c2f55e707 |
| Manifest | 0928e77f5800caddbcc2bfa799605f128d9cfebfd6256e319a0fee1af03805fd |
| Bundle | 37b7a2ce9bce6a7cea6c1ee40be7e9ca8a171ad4f59b73b2a04ece2306d50892 |
| Execution Image | 5e28b294594a373a7465f588a4b6fc23308ee18f3fa7e629e0dcb8df138f83be |
| Root Manifest | 42a17b24440b1267af3cec618c38955f57bd4dc75f7c34e1f9c4c2c3aaa5e2cc |
| Controller Manifest | 476610620b1784bd02bfec5c051531644ff72ff3b0154393ad61d9da0c375113 |
| Controller Image | fb1a39f1427b158bd5a3ce3512edfab493b3fd5793a86aa6d9fe7a6bc3607a24 |
| Controller Python Runtime | c87a778581e6096f4a9f06b800ea61ae72d7181716f595d59ecdac6fbc689c0c |
| Runtime Dependency | e387709bafde9db7df6978b4f0d5a18a3f7a807ead408530b3a95325bfdb5cf4 |
| Wheel | a4cf591ef517af7726973d53eda1c578f2cd863bf2ea6a5c4f0acd4eacbe085b |

정확한 Git Commit/Tree 및 실제 Artifact 두 개(Capture/Controller)의 개발 계측 배열은 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/native-ai-binding-recovery-20261028T022430Z/artifact-identity.json` 및 built-artifact-review.json에 기록한다. Source/Controller Runtime/실제 RF·LR 모델과 Feature Contract는 별도 provenance에 연결한다. 원래 승인 요청서의 자리표시자 문자열은 그대로 역사 자료로 보존하고 새 자료에서 실제 배열로 대체했다. 아직 존재하지 않는 정책 포함 Manifest/Image는 만들어 넣지 않았으며 final_operational_artifacts는 빈 배열이다. 이후 동일 helper를 재빌드 결과에 적용하면 확정된 배열이 생성된다. 이 도구가 자동으로 정책을 활성화하지 않는다.

검증: 집중75 PASS. Workspace **1974 PASS / 23 SKIP (472.51초)**, 독립 Export **1974 PASS / 23 SKIP (470.88초)**. 기존 Assertion/검증 기준 유지. 정책 포함 테스트 영수증은 임시 디렉터리의 UNIT TEST 전용이며 실제 승인에 사용하지 않았다. Replay·중복 승인·Ledger·미승인 차단 회귀 포함. Supervisor Stage/A/B26개·Controller2개 및 Workspace/Export Wheel684 entries 이중 빌드 동일. Ruff/Format1431개/Diff PASS.

비소비 기존 CLI check: Source VERIFIED / Runtime BUILD_INTEGRITY_VERIFIED_ONLY / ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED / reserved=false / executed=false. 실제 Namespace4026532232와 Lease, 보호112개·과거 Native55개·설치/롤백 각9개·사용자 변경 보존. Ledger32행 SHA e7779f7315f9d3d71c9f91d0846bc4254dfc60217c84ae2be0534501763d567d 불변. Campaign Native4/10·Root6/10, Batch3 Native1/2·Root3/4 유지. 기존 FAILED/false/Program1145 UNKNOWN/전역Cleanup UNVERIFIED/UNKNOWN 예약은 유지한다. Root/DNS/Native/실제 API 호출0.

남은 최소 인간 결정: (1) 새 Source/Root에 정확히 결합된 Namespace 빌드 정책 승인, (2) 해당 영수증으로 재빌드한 뒤 최종 SHA 목록을 결합하는 개발 계측 및 R1/R2·Root/Native 독립 승인. 실제 LLM은 별도 허용 범위 내 실제 이상이 있을 때만 호출한다. Docker/Controller 실환경 동작·P02/P03·Native ELIGIBLE 및 DNS9는 새로운 실제 증거 전까지 BLOCKED/INCOMPLETE를 유지한다. 이번 결과를 READY_FOR_NATIVE_E2E 또는 실제 Native VERIFIED로 선언하지 않는다.

## 2026-10-28 Namespace 빌드 정책 승인 적용 및 최종 Artifact

상태: BUILD_POLICY_ACTIVE / POLICY_EMBEDDED_ARTIFACT_PREPARED / EXECUTION_BLOCKED. 운영 코드 변경 없음. 승인된 Git83b8f94b5e5455009284094dae13f8d71da58c8b / Treeb331454c74dd860b9e2b4d4521ad25abe096fbaa에서 빌드했다. 이번 후속 변경은 본 보고서뿐이다. 실행 검토용 최종 Git/Tree는 보고서 Commit 뒤 외부 artifact-identity.json/next-approval-request.json에 고정하며, 승인된 빌드 Git과 문서만 바뀐 Commit을 분리해 기록한다. Source1772개 및 보안 구현 fingerprint는 불변이다.

승인자 조건욱, 프로젝트 소유자 및 정책 승인권자의 명시적 APPROVED_WITH_CONDITIONS를 AGENTS.md §33에 따라 기록했다. 원 Artifact 검토 요청서 SHA3301fddd5b155182dd9f72cfff09c2f59c071bc2536d844b396c55018e3a9013, 빌드 전 정책 요청서 SHA75c7c01de6134d11ee0dc2906b2e8b94efa51c5359d05706a7d6922e02b01132를 실제 파일에서 확인했다. Git/Tree/Source/Session ddd1cf2b-1f50-4157-8aca-8079a0f3ddff/Release0.6.3/Namespace net:[4026532232]/Lease/Root Manifest/최신 Ledger32행이 정확히 일치했다. NamespacePolicy는 기존 모델 및 check_policy를 재사용했고, 기존 Namespace 활성화와 동일한 NativeCampaign._locked hash-chain writer로 이벤트를 기록했다. 새로운 승인 체계나 실행 권한을 추가하지 않았다.

- Policy contract: SOC_NAMESPACE_SUPERVISOR_BUILD_POLICY_V1
- 정책 영수증 SHA256: f32f7fef42ada464194dd4fa642b3277429ca813d9baafee4ff80321c5c975b8
- 시작: 2026-10-28T11:37:33+09:00
- 만료: 2026-10-29T11:37:33+09:00
- 활성화 이벤트: 0d49a2f58ffaa3a11cb78759424797a9c53d9d2a488a5dd141a380133b5692db
- Root/Native/Traffic/API 권한: 없음. 개발 계측 활성화: 없음.

NamespacePolicy 결정 필드는 기존 계약의 APPROVED이고, 조건부 인간 결정과 정확한 원 요청서·Git·Session·Source 문맥은 영수증이 pin한 human-approval-reference.json에 보존했다. 기존 영수증을 수정하거나 재활용하지 않았다. 같은 요청의 재처리는 stale Ledger로 거부되며, 동일 Binding 중복 활성화도 기존 locked writer 안에서 거부하고 Ledger bytes 불변을 확인했다. 만료·Source·Namespace·Native 권한 확대·Mock 승인자 입력을 메모리에서 변형해 모두 거부되는 것을 확인했다. 추가 영수증 파일을 만들거나 실제 실행을 시도하지 않았다.

최종 빌드 SHA:

| 항목 | SHA256 |
|---|---|
| Source Snapshot | b1c473bd0dd2ab63635a8ecad01dca3dde2b9f88a43c59529ad6443c2f55e707 |
| Manifest | c57688c322246a575b256f63f6039b3a8f904c57ff4d19c457eba31e434bff13 |
| Bundle | 37b7a2ce9bce6a7cea6c1ee40be7e9ca8a171ad4f59b73b2a04ece2306d50892 |
| Execution Image | cbb668025963f79f447f84c7bed41cc4a0c2811508cb41f93fa83b91c8f3edd5 |
| Root Manifest | 42a17b24440b1267af3cec618c38955f57bd4dc75f7c34e1f9c4c2c3aaa5e2cc |
| Controller Manifest | 30f9c6a1b79e99a0c09acc7c24296c2d71ce961f6453999eac7f0932fb6cbe5f |
| Controller Image | 3daf85f88aa39ff330d00c828df44047a26d1c737e8b6a5463b8e513d7e0a2ce |
| Controller Python Runtime | c87a778581e6096f4a9f06b800ea61ae72d7181716f595d59ecdac6fbc689c0c |
| Runtime Dependency Identity | e387709bafde9db7df6978b4f0d5a18a3f7a807ead408530b3a95325bfdb5cf4 |
| Wheel (이전 동일 Source 빌드, 이번 신규 Wheel 빌드 아님) | a4cf591ef517af7726973d53eda1c578f2cd863bf2ea6a5c4f0acd4eacbe085b |

정책 영수증을 포함하면서 이전 Guarded Manifest0928e77f…/Image5e28b294…가 변경됐고 Controller Manifest47661062…/Imagefb1a39f1…도 새 target/경로를 반영해 변경됐다. Source/Bundle/Root Manifest/Runtime Dependency/모델 bytes는 그대로다. prepare 결과는 RUNTIME_APPROVED, build_review.artifact_stage=POLICY_EMBEDDED이며 이 상태를 실행 승인으로 취급하지 않는다. Supervisor 산출물26개와 Controller 산출물2개의 전체 파일 목록·SHA는 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/approved-namespace-build-20261028T023733Z/capture-build-verification.json` 및 controller-build-verification.json에 있다. Stage/A/B 독립 출력 비교뿐 아니라 frozen Source Export에서 같은 영수증으로 재빌드한26개/2개도 전부 일치했다.

고정 Controller Python -I/-B, 256MiB/CPU20초의 실제 import probe 및 pydantic2.13.5/고정 의존성124개 파일 검증 통과. 실제 Root 사용자 전환과 Namespace 내부 Controller 실행은 이번 작업에서 수행하지 않았다. Model Artifact는 RF53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603 / LR661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882를 실제 파일 및 manifest SHA·Feature Contract와 대조했으며, 세부 provenance는 model-verification.json/next-approval-request.json에 있다. 실제 Native 모델 추론 또는 LLM API 실행을 성공으로 보고하지 않는다.

비소비 check 구분:

- 빌드 정책·출력: 실제 영수증 포함 descriptor 검증과 validate_preparation 통과. Source/Bundle/Root/Dependencies·Source Export/Stage 무결성 검증 통과.
- Host CLI check: PHASE_D_COLLECTOR_SCOPE_MISMATCH / BLOCKED / reserved=false / executed=false. 정책 미활성 오류는 해소됐지만 Host net:[4026531833]에서 SOC net:[4026532232] Scope를 검증할 수 없다. 해당 check의 stages는 이 지점에서 전부 BLOCKED이며 개별 승인 검증 통과로 보고하지 않는다.
- 실제 SOC Namespace 내부 check: NOT_PERFORMED. 승인된 Root 진입이 필요하며 이번 승인에는 포함되지 않는다. setns/가짜 Namespace Identity로 우회하지 않았다.
- 개발 계측: PENDING_HUMAN_APPROVAL, 활성화 없음. 실제 Capture/Controller Artifact2개를 담은 final_operational_artifacts/artifacts 배열을 완성했다. 빈 목록이나 미래 SHA를 승인된 값으로 채우지 않았다.
- R1/R2·Root/Native: 새 Artifact와 최신 Ledger에 결합된 독립 승인 대기, Host check 이후 admission 검증은 미진행.

남은 단일 검토 패키지는 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/approved-namespace-build-20261028T023733Z/next-approval-request.json`이다. 개발 Namespace·Source·Runtime·Model·Session·Release·정확한 Artifact2개·개발 계측 fingerprint·최신 Ledger/예산을 연결했다. 개발 계측 정책은 실행 횟수를 OBSERVE_ONLY로 처리하되 기존 운영 한도·동시 실행 차단·exact SHA·R1/R2·자원 상한·Scope 확인/OS 인증을 유지하는 기존 계약이며, 이번 Namespace 승인으로 활성화하지 않았다. 새 인간 승인 후에도 실행별 exact 승인과 새 Ledger tip을 검증해야 한다.

기존 Controller 경로는 Root DNS/Controller 진입과 후속 Root 설치/Native 진단을 서로 다른 권한 작업으로 처리한다. 따라서 다음에는 현재 Controller Artifact에 대한 Root DNS/Controller 정책·실행 승인과 제한된 UDP2/TCP1 승인이 필요하고, 후속 진단에는 적절한 post-entry Ledger/Native Session에 결합된 R1 및 정확한 R2/Root 설치/Native 승인이 필요하다. 이번 Namespace 빌드 정책은 이 권한을 부여하지 않는다. Root legacy 배정의 기존 만료2026-10-28T15:47:27+09:00도 연장하지 않았다. 개발 계측 승인 또는 유효한 별도 예산 계약 없이 Root 잔여1회를 두 권한 작업에 자동 배정하지 않는다.

검증: Workspace 핵심 회귀 **202 PASS (212.68초)** / 독립 Export 핵심 회귀 **202 PASS (212.43초)**. Namespace/Source·정책·Replay·Ledger·Root Governance·Controller·Supervisor·Native→AI Adapter 회귀 포함, RUN_LIVE_LLM_TESTS=0. 이전 전체1974 PASS/23 SKIP는 과거 동일 Source 검증 결과이며 이번 전체 재실행으로 집계하지 않는다. Ruff PASS / Format1431개 PASS / Diff PASS. 테스트의 Fixture·Mock 검증을 실제 Native 실행으로 판정하지 않는다.

Ledger32→33행: Namespace 빌드 정책 활성화 이벤트1개만 append했고 기존32행 prefix를 보존했다. Ledger SHA 9ac01e558373418f52bad9bf365d232ed269c80410f7ea2eddb37a86a096babf. Campaign Native4/10·Root6/10, Batch3 Native1/2·Root3/4 불변. 실제 Namespace/Lease·Host·VS Code·보호112개·과거 Native55개·설치/롤백 각9개·사용자 변경 보존. 기존 FAILED/false/Program1145 UNKNOWN/전역Cleanup UNVERIFIED/과거 UNKNOWN 예약 보존. 예약·Root·Native·DNS·Docker·API 실행0. DNS9 학습 추출 계약 INCOMPLETE 및 실제 P02/P03/Native ELIGIBLE0은 새로운 Native 증거 전까지 그대로다.

## Deadline Native E2E attempt — 2026-10-28

**Native AI E2E: BLOCKED before Native reservation. Offline demonstration: VERIFIED within its offline scope.** No Native packet, ELIGIBLE Native feature, Native RF/LR prediction or Native Incident was generated in this attempt.

The owner approved the consolidated review JSON `e5f720dfc980de78e2cfd691be23a7a022d98e049ea062f6f7bffbb22a5688c4`. Existing CLI contracts were reused without adding policy, budget, Namespace or approval systems. An official ApplicationPlan generated fresh Controller Session `86c3d2be-ad06-4046-8dd9-71c9ab4775e4`; the previously consumed Session was not reused. Its two prepared files reproduced identically. Native Session remains `20fc3a6f-c645-4d7b-a59e-cbbde10649ea`, Release0.6.3, Namespace `net:[4026532232]`.

The separately approved development exact-artifact opt-in and Root-only policy were recorded, then the user confirmed Scope and authenticated in a private terminal. Root DNS/Controller entry succeeded once. Application DNS UDP2/TCP1 and ordinary UID/GID1000 Controller readiness were verified; listeners closed, only lo was present, and the Namespace was retained. These application observations do not establish TCX Capture Integrity or kernel Flow Completeness. No Root Release installation, Native Capture, TCX attach, Docker analysis or new LLM API call occurred.

The conditional human R1 decision was recorded only after actual Root success and settlement, against the actual resulting Ledger. New R1 receipt SHA `1fc0f79a53f17d680e46a3c1f97f4db56b099401cd25b6e65870fe49ceb4d462`; record `2515ea673db50384e4f901331d83a243e94962b9d2bcc698d6b0cf86384ab898`. The old R1 receipt remained immutable. Admission reservation preview passed without reserving. The ordinary Namespace Controller subsequently returned exit2; Ledger stopped at47 rows with no Native reservation. The terminal's exact final error text was requested and was not retained by collecting a password-bearing terminal transcript. No automatic retry or privileged re-entry occurred.

### Confirmed preparation defect and minimal correction

`operational_recovery.readiness` compared the failed historical run's Root Manifest `f5b54fbbac173e05ab6bfc246612d409d1dc966a9fcab5635daadea8c1117ab3` with the image's installed predecessor `a715e1aab17d25ce89d87ce320a8b16997cb3072d83956734126baa470a501a6`. These represent different releases and legitimately differ after the intervening installation. The guard deterministically returns `OPERATIONAL_PREVIOUS_ARTIFACT_BINDING` once this stage is reached. This is a confirmed code defect; attribution of the live exit2 to that exact printed error remains pending the terminal error text.

The correction independently verifies the current installation using existing `installed_release` file/dependency validation, or the existing `inspect_retained` contract for a recovery image, and compares that verified identity with the image's predecessor. R1 continues validating its original failed run, negative review and historical evidence. Changed, missing or damaged current installations remain blocked; no Namespace, SHA, Scope, R1/R2, resource, replay or human confirmation guard was removed. Four regression cases cover a distinct historical release and matching/changed/missing/damaged current installation, without reserving or invoking Root.

The source change invalidates the previous exact Source/Artifact approvals. No old receipt was used to activate or execute the corrected image. Any replacement build remains guarded until a fresh exact policy/build/execution review; no successful live Controller check or Native E2E is inferred from unit tests.

### Offline deadline demonstration

The existing saved real API E2E was reopened successfully: real stored PCAP → two actual RF/LR predictions → UNKNOWN_ANOMALY → historical real API plan/evaluation → governed read-only investigation → Incident/Audit. Result SHA remains `7b44630fbf54480dc911944b07260c9cfa6c629cdb1e6c88aaae5a7ad981b838`. This verification makes zero API calls and does not replay an old API authorization.

A new actual PCAP Flow0 replay produced two actual RF/LR predictions, `NORMAL`, `ELIGIBLE`, and `SOURCE_CONTINUITY_VERIFIED` with Incident/Audit persistence. Investigation mode is SCRIPTED and no investigation was necessary for NORMAL. Initial execution from the integration Worktree lacked the project-local inference Python; explicitly selecting the existing ML root fixed the invocation without installing packages or changing the pipeline. Both the initial failure and successful result were retained.

Demonstration script: common Git evidence directory `deadline-native-e2e-20261028T033152Z/demo-verify.sh`. It verifies the current normal replay result and historical real API result without Root, traffic, Capture or API calls. Evidence paths distinguish REAL_OFFLINE/REAL_MODEL and historical REAL_API from Native and Scripted scope. DNS9 remains INCOMPLETE pending its training extraction contract.

### Accounting and preservation

Ledger40 →47: two policy events, one Root-only reservation/progress/settlement sequence, and one new human R1 record. Campaign Native4/Root8; Batch3 Native1/Root5. Development counts are OBSERVE_ONLY, not refunded/reset. Native budget consumption and Native reservations in this attempt are zero. Original FAILED/false, Program1145 UNKNOWN, historical global Cleanup UNVERIFIED and the old EVIDENCE_INCOMPLETE/RootUNKNOWN/NativeUNKNOWN settlement remain unchanged. The existing Namespace, Host services, VS Code connections, installed release and Rollback were preserved.

Private evidence: `.git/deadline-native-e2e-20261028T033152Z/` in the common original repository. The approved pre-fix package and receipts remain separate from corrected source/build evidence under `recovery-fix/`. Native P02/P03/P04 and operational promotion remain unverified; automatic Native rerun is prohibited.

### Correction validation and guarded artifact

Related Workspace regression: 123 passed initially; one actual-model case failed because the integration Worktree lacked its default inference environment. That same case passed when `SOC_RESEARCH_VALIDATION_REPOSITORY` selected the existing original project's pinned environment. Independent Source Export, with that environment explicitly configured: **124 passed**, 121.41s. No test assertion or model was weakened. Ruff, formatting and diff checks passed. Temporary pytest cleanup emitted directory-not-empty warnings; they did not affect the regression results.

Final Source Snapshot (1,772 inputs): `ce7aaaf2750ceb5fe1db523f1db310f086de3ce7fa4da85cb2c275bd9e02e674`. Stage and two independent builds share a fixed real deployment path and match **26/26 files**. Initial builds at different deployment paths had different metadata paths; both are retained, and they are not counted as matching builds. Two wheels are byte-identical: `d753f42cd988187392176ff92e3de0d1dd2d687c54ff72e67eb0fd32e9f6926c`.

These are **guarded, unapproved replacement outputs**, not the previously authorized execution image:

| Identity | SHA256 |
|---|---|
| Manifest | `f572d299e2993f858f93681bf0c994553f561d4a5b380bb90c8a64401fc30617` |
| Bundle | `b0183470f1fd5c8edb99451fb49cd87e0742d1342dd0939666d505e202968023` |
| Execution Image | `2652e837078e907114411cae1362a11db6cb22f51fd166febbfb2a4ed77e72ea` |
| Root Manifest | `fdfff9f7ddd1668f0f8d390b09f00c25a9429ea5cfb9639b1323c02ef5511808` |
| Build policy input | `546c05d2bca466dc4490241587d455d51a39f131f9da397874cb4d8506edef33` |

No Namespace build policy receipt is embedded in these replacement outputs. Activation and policy-embedded output identities require a new exact human decision; the consumed Controller approval and prior exact Native/Source/R1 bindings cannot authorize the modified source. The actual Native attempt remains unstarted and is not automatically retried.

For the deadline, run the private `demo-run-normal.sh` for a fresh actual PCAP/model/Incident/Audit demonstration with no API; run `demo-verify.sh` to reopen both the fresh normal result and historical real API investigation. Live model replay and retained historical LLM verification are explicitly different scopes. Git source changes are limited to the operational installation-identity correction, its four regression cases, and this report.

## Deadline final preparation — 2026-10-28, corrected implementation 37f54a0

이번 작업은 코드 추가·정책 활성화·실제 실행 없이 수정된 준비 경로를 검증했다. `test_failed_release_is_independent_of_current_installation`의 네 경우가 모두 통과했다. Matching current installation은 과거 실패 Artifact와 달라도 준비 검증을 통과하고, 현재 설치본 변경·누락·손상은 차단한다. 이는 Mock 운영 composition 회귀이며 실제 Namespace 내부 check PASS를 의미하지 않는다. 현재 설치본은 기존 `installed_release()`로 실제 Root 소유 파일·의존성을 검증했고, 설치본 `a715e1…`과 과거 실패본 `f5b54f…`을 혼동하지 않았다.

Source1,772개·독립 Export·기존 guarded Stage/A/B와 Wheel·Namespace lease/inode·Controller Python entry·Runtime dependency·RF/LR 모델 핀을 다시 확인했다. Source Snapshot `ce7aaaf2750ceb5fe1db523f1db310f086de3ce7fa4da85cb2c275bd9e02e674` 및 위 guarded Artifact SHA는 변하지 않았다. 현재 Namespace inode4026532232/Host4026531833 유지. 내부 lo/routes/socket-cookie는 이번 작업에서 새 Root 진입으로 관측하지 않았다.

기존 비소비 CLI의 현재 결과는 `ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED / BLOCKED`, reserved=false/executed=false다. GUARDED 경로는 의도대로 실행 전 차단된다. 설치본 혼동 결함 수정 검증과 전체 Native 실행 준비 통과는 별도로 판정한다. Namespace 빌드 정책은 확정된 input binding `546c05d2bca466dc4490241587d455d51a39f131f9da397874cb4d8506edef33`에 대한 정식 승인을 먼저 요구한다. 그 영수증을 빌드에 포함하면 Manifest/Image가 바뀌므로, 아직 없는 policy-embedded execution SHA를 현재 guarded SHA로 대체하거나 승인 대상으로 제시하지 않는다.

모든 남은 결정은 common Git evidence `deadline-final-preparation-20261028T035111Z/approval-package.md`와 JSON 한 묶음에 정리한다. 현재 확정 가능한 Git/Tree/Source/Root Manifest/Namespace/build-policy input과, 정책 영수증 후 실제 출력으로 확정해야 할 개발 계측·Controller·R1·R2·Root 설치·Native 실행 Binding을 구분한다. 현재 필요한 승인 요청은 Namespace 빌드 정책이며 실제 Root/Native/DNS 실행 승인을 포함하지 않는다. 나머지 영수증은 실제 최종 Artifact 및 실행 전 최신 Ledger가 확보된 뒤 기존 계약에 따라 각각 검증한다. 원래 영수증을 변경·재사용하지 않는다.

Ledger47행과 SHA `0ba4e1a153752890bb8eb5827d47fa683d0674c79f518a84183719bba9b77453`는 불변이다. Campaign Native4/Root8, Batch3 Native1/Root5, OBSERVE_ONLY와 과거 집계 유지. 이번 작업의 Root·Native·DNS·예약·새 영수증·예산 소비·API 호출은 모두0이다. 기존 실패·false·UNKNOWN·설치/롤백·보호112개·Native55개·기존 사용자 변경을 보존했다. 새 Native 후보·모델 호출·Incident는 생성하지 않았다. P02/P03/P04 및 Native E2E는 BLOCKED/미검증을 유지한다.

Offline 시연 스크립트 두 개는 원본 SHA 그대로 보존했다. 저장된 실제 PCAP 정상 결과는 실제 RF/LR2개 추론/NORMAL/Incident·Audit의 재열기 검증을 통과했고, 기존 실제 API 조사 결과는 계획·읽기 전용 조사·평가·Incident·Audit의 별도 재열기 검증을 통과했다. 이번 검증의 모델 재호출·새 API 호출은0이다. 정상 결과의 SCRIPTED 설정과 역사적 REAL_API 결과를 구분하며 DNS9 학습 추출 계약 미확보 상태를 유지한다.


## Final approved Namespace build — 2026-10-28

정책 활성화와 영수증 포함 비권한 재빌드를 완료했다. 승인자 조건욱(프로젝트 소유자 및 정책 승인권자)의 명시적 `APPROVED_WITH_CONDITIONS`와 요청서 SHA `a41e944a90fa1dbb62bcda26e6dc56dd68e47c59182e8e12062cf2397553a45f`를 대조했다. 승인 시점 HEAD `b810d4d854f95363180b5258067c400dd58cfafe` / Tree `8e4d6e0b0580fcf52e4aee6d2829805e36ea041d`, Source `ce7aaaf2750ceb5fe1db523f1db310f086de3ce7fa4da85cb2c275bd9e02e674`, Root Manifest와 실제 lease/inode/Scope/정책 input Binding이 정확히 일치했다. 정책 영수증은 기존 NamespacePolicy validator와 기존 Campaign append-only writer로 검증·기록했으며 새 승인 시스템이나 운영 코드를 추가하지 않았다.

- 정책 영수증 SHA256: `c79c96e0eeaa9c771254350f9156166befb3c1588a060b686ce22754d9177c3c`
- 유효기간: `2026-10-28T13:45:18+09:00` → `2026-10-29T13:45:18+09:00`
- 정책 input binding SHA: `546c05d2bca466dc4490241587d455d51a39f131f9da397874cb4d8506edef33`
- Source 입력: 1,772개, Workspace/독립 Export 일치
- Namespace: net:[4026532232], Host: net:[4026531833]; 생성·삭제·재진입 없음
- Controller Session: `3a7a4abd-8e9a-49b4-9b80-97cbffbc9057`
- 다음 Native Session: `8fee2197-403f-4502-be63-f19d4b90df48` (기존 공식 ApplicationPlan에서 생성된 Identity만 준비, Application/실행 미시작)

### 최종 산출물 Identity

| 항목 | SHA256 |
|---|---|
| Supervisor Manifest | `5cc945c86feaf88a504c4501f1d99111bea9bfb2e33e160a60a80fe8ca9aa692` |
| Bundle | `b0183470f1fd5c8edb99451fb49cd87e0742d1342dd0939666d505e202968023` |
| Supervisor Execution Image | `db2cf46ab638bc2d532fa984787c853a66928752108a5111a45512d3e003516d` |
| Root Manifest | `fdfff9f7ddd1668f0f8d390b09f00c25a9429ea5cfb9639b1323c02ef5511808` |
| Controller Manifest | `2ebf685611886662e72af00742d491b938555fac86a1ea116a74539ba24a986b` |
| Controller Execution Image | `db5091a42322f341ba25724b877f3fc35d2093455a6b918b19d0094b0f075a08` |
| Runtime Dependency Identity | `e387709bafde9db7df6978b4f0d5a18a3f7a807ead408530b3a95325bfdb5cf4` |

실제 CLI `native-recovery prepare`가 `RUNTIME_APPROVED / executed=false`를 반환했다. Supervisor Preview=false 및 literal embedded Namespace 정책 영수증을 검증했다. 영수증 포함 전과 비교해 Manifest/Image는 변경됐고 Bundle/Root Manifest는 실제 동일함을 확인했다. 이 build permission은 실행 권한이 아니다. 변경된 출력에 과거 실행 영수증을 재사용하지 않았다.

Supervisor Stage/A/B **26/26개**, Controller의 실제 운영 CLI canonical JSON 입력 기준 Stage/A/B **2/2개**가 동일하다. 초기 Controller in-memory dict 입력 순서가 canonical JSON 순서와 달라 비교 실패한 산출물은 별도 보존했다. 기존 운영 CLI의 held canonical packet으로 Stage를 다시 준비해 독립 A/B와 전부 비교했고 소스나 정책·영수증은 변경하지 않았다. Workspace 및 독립 Export 핵심 회귀 각각 **95 PASS**(108.49s/110.13s), Ruff 전체 PASS, Format1,431개 PASS, Diff PASS다. 이전 같은 Source의 동일 Wheel `d753f42cd988187392176ff92e3de0d1dd2d687c54ff72e67eb0fd32e9f6926c` 두 개도 보존하며 이번 신규 빌드 비교는 Supervisor/Controller 범위다.

### 비소비 check와 승인 경계

Host 비소비 CLI 결과는 `PHASE_D_COLLECTOR_SCOPE_MISMATCH / BLOCKED / reserved=false / executed=false`다. `ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED` guard는 해소됐지만 Host4026531833과 SOC4026532232의 실제 Scope 차이를 우회하지 않았다. 별도의 비권한 준비 검증으로 정책·Source·Runtime·설치/롤백·Artifact 무결성을 확인했고, 실제 Namespace 내부 check는 Root 진입 권한이 없으므로 수행하지 않았다. Host check가 R1·R2·Root·Native 승인을 통과했다고 주장하지 않는다.

현재 설치본9개, Rollback9개, 보호112개, 과거 Native55개, 기존 사용자 변경과 lease를 보존했다. 고정 Controller Python runtime의124개 파일과 `-I/-B`·256MiB/CPU20s import 경로를 확인했다. 실제 UID 전환/Controller 재진입은 수행하지 않았다. 실제 RF/LR 모델 Artifact 핀도 유지하며, 신규 모델 추론과 API 호출은0이다.

Ledger47→48은 정책 활성화 이벤트1개뿐이다. 기존47행 prefix와 전체 해시체인이 보존됐고 같은 정책 요청의 replay가 차단됐다. Ledger SHA `43708020d4ae8c24fd4a909b3282ea9681f41d9b9dd22ca08ddff1bb72f5a0dd`, tip `e75fd3003fe52447297f4ba73dfa8e8343a6e8c3b4ac7078d3315e3e9d36a515`. Campaign Root8/Native4, Batch3 Root5/Native1 불변. OBSERVE_ONLY의 기존 집계는 초기화·환급하지 않았다. 실행 예약·Root·DNS·Native·sudo·컨테이너·LLM API 호출은 모두0이다. 과거 FAILED/false/Program1145 UNKNOWN/전역Cleanup UNVERIFIED/예약UNKNOWN 판정은 그대로다.

남은 항목은 **최종 정확한 SHA 목록에 대한 개발 계측 opt-in, 새 Root DNS/Controller 진입, R1 인간 조건부 위험 수용 및 admission amendment, Native R2 트래픽, Root Release 설치·Native 최대1회, 실제 ELIGIBLE 입력에 대한 RF/LR action approval**이다. 각 영수증은 독립 검증한다. 새 Root 진입이 실제 성공·정산된 후 마지막 실제 Ledger에 새 인간 R1 결정을 기록하며 미래 tip을 예측하거나 과거 영수증을 재사용하지 않는다. Source 변경 없이 실행 승인만 진행할 수 있도록 최종 출력과 Session/Release/Scope/자원/원본 위험/조건을 같은 private 검토 자료에 고정한다. Namespace 내부 check가 실패하면 실행하지 않으며 자동 재실행하지 않는다.

Private evidence: `.git/approved-deadline-namespace-build-20261028T044518Z/`. 최종 실행 승인 자료는 `next-approval-request.json`과 `next-approval-package.md`이며, 보고서만 반영한 후속 Git Commit/Tree를 별도로 고정한다. 정책 승인 입력 Git b810d4d와 이후 문서-only HEAD를 혼동하지 않는다. Source Snapshot은 동일하다. 실제 Native E2E/P02/P03/P04는 여전히 미검증이고 DNS9는 학습 추출 계약 미확보로 차단한다. Offline 실제 PCAP·RF/LR 결과와 역사적 실제 LLM 조사 결과 및 시연 스크립트 두 개를 보존했다.
