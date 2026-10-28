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
