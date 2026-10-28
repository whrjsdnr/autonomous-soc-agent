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
