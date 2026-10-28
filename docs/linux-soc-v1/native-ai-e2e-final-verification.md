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
