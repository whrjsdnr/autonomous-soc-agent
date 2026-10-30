# TCX Short Native Retest 전체 Deadline 복구 검증

2026-10-30. **비권한 Deadline 검증 완료 / 새8경로 Scope 확인·직접 인증 대기**.
이번 작업은 기존 Launcher의 전체 시간 제한을 보강한 실행 준비다. 새 승인/예산 시스템이나 Collector 기능을 만들지 않았다.
Root·sudo·Namespace 진입·TCX Capture·DNS 트래픽·모델/API·예약·영수증 발급/소비·기존 Ledger 쓰기0이다.

## 승인 조건과 적용 경계

사용자의 원본 조건부 승인은 `.git/tcx-short-native-review-20261030T055230Z/review/approval-package-final.md`를 대상으로 했다.
§4는 **"전체 실행 시간은 시작·정리·Cleanup을 포함하여 최대600초"**, 그리고 Artifact/Root Manifest 변경 시
기존 Binding 승인 재사용 금지를 요구한다. 원본에는 서비스600초만 있었으므로 실행하지 않았다.
그 원본 승인과 추가 "승인할게" 결정은 보존하며 새 Artifact의 자동 승인 영수증으로 전환하지 않는다.

기존7경로만으로는 DNS의 생성 unit 원문과 정확히 일치해야 한다는 검증을 유지하면서 별도의 job 제한을 넣을 수 없었다.
DNS base unit과 Helper 권한 계약은 그대로 두고, 고정 drop-in 하나와 그 부모 디렉터리만 추가하는 **새8경로 후보**로 확정했다.
새 정확한 Scope를 실제 사용자 TTY에서 검토·yes 확인해야 독립 영수증이 발급된다. 기존 소비된 영수증은 재사용하지 않는다.

## 수정한 실행 경로

`/home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-short-deadline-recovery-20261030T061425Z/review-final/execution/terminal.py`는 기존 Scope 확인·독립 결정 기록·foreground sudo 인증을 유지한다.
인증이 끝난 후에만 실제 실행 구간을 시작한다. 비밀번호/TTY 입력 기록은 하지 않는다.

1. 인증 후 기존 실행 부분을 `terminal-worker.py`로 분리했다. 기존 GNU coreutils9.4 `/usr/bin/timeout`이
   worker에 **590초 TERM / 추가5초 KILL**을 적용하고, 전체600초 중 종료 관측 여유5초를 둔다.
2. Root coordinator에도 독립 GNU timeout **530초 TERM / 추가30초 KILL**을 적용한다.
   Root 시작은 worker monotonic clock의15초 이내여야 하므로 Root driver 제한은575초 이내다.
3. 같은 monotonic clock을 고정된 hash-verified Root bootstrap에 전달한다. 늦거나 미래인 clock으로 입장할 수 없다.
   주요 service start 요청은50초 이전, TCP helper는330초 이전만 허용한다.
4. Collector·일반 Runtime·DNS 서비스 RuntimeMax420초. Owner STOP400초·Drain460초로 정상 종료 여유를 앞당겼다.
   수신 envelope 생존5초, Counter/Clock/epoch/Scope 검증, Native retry0은 바꾸지 않았다.
5. systemd 서비스는 Root child process group과 독립이므로 별도의 job/start/stop/cgroup 제한을 검증한다.
   `Restart=no`, `KillMode=control-group`, `SendSIGKILL=yes`와 유효 속성 불일치 시 **Capture 시작 전 차단**한다.
6. GNU timeout의 종료124/137/신호와 실제 Root 상태를 구분한다. 정상적으로 전달된 Root0/1/2/3만 실제 exit로 기록하고,
   Deadline 중 강제 종료라면 Root 실제 exit는 UNKNOWN으로 둔다. Root의 `sys.exit` 직전 기록도 계획된 exit이지 waitpid 증거가 아니다.

| 대상 | Job / Start / Runtime / Stop 제한 | 같은 clock 기준 설정 예산 |
|---|---|---|
| Collector | 15 / 15 / 420 / 10초 | 주요 서비스 최대560초 범위 안 |
| Runtime | 40 / 15 / 420 / 35초 | 요청50+job40+start15+runtime420+stop35 =560초 |
| DNS Helper | 15 / 15 / 420 / 10초 | DNS base unit + 정확한 drop-in |
| TCP helper | 90 / 90 / oneshot / 5초 | 요청330+job90+start90+stop5 =515초 |
| dnsmasq | 15 / 5 / 90 / 5초 | 주요 서비스 범위 안 |

TCP는 Type=oneshot으로35초 간격의 두 연결을 완료하므로 JobTimeout을15초로 줄이지 않았다.
실제 시스템의 `systemd.unit(5)` 설명으로 JobTimeout이 job에만 적용되고 unit 상태 자체를 바꾸지는 않음을 확인했다.
따라서 RuntimeMax/TimeoutStart/TimeoutStop/KillMode도 함께 확인한다. 외부 timer 하나만으로 서비스 종료를 주장하지 않는다.
인증 대기와 시험 종료 후 창을 닫는 Enter는 실행 구간 밖이다. 설치·Namespace check·서비스 시작·종료·Cleanup은 구간 안이다.

## 새 정확한 Binding

검토 패키지: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-short-deadline-recovery-20261030T061425Z/review-final/approval-package-final.md`.
기계 요청서: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-short-deadline-recovery-20261030T061425Z/review-final/approval-request-final-v2.json`.
전체 Identity: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-short-deadline-recovery-20261030T061425Z/final-artifact-identity.json`.

| 항목 | 값 |
|---|---|
| 동결 Git / Tree | `ed9b6db3e6b4dcb2f298f08df001442483895c9e` / `fac1385ee5e0f97284c6de23d2695434d2daf8e2` |
| Source canonical668개 | `9f2bf1ae660979bb224c8807415985ca572a13f256c90348a2137874c9758b96` |
| Source archive | `0fe180cf7f7782a7926db69ba51dece5587e03204322a2a533d33836cd0f085b` |
| Wheel | `b7f0504cecce4388fdee8d3699a554daa80213de20c19f7791d02ef115838ed6` |
| Root Manifest | `851e1396048693e3699c68a0afee7cbdde4a39d281e15df93837ff0dc22ee645` |
| 요청서 | `e488b074c6d4e9b76918c57eb3f490b5ab41183df9b53df3e2f3814d90a7a1e4` |
| 검토 패키지 | `3d8ca0fa441ec3eb93219fe66fa3f258a672b7e4f4a6f43ddcfa078464c84d7c` |
| Launcher execution pins | `86539befa7a35b3804f3bc95050e3a3947c99bd9e6ea193f39378aace3ecda59` |
| Runtime Session | `6d9f0d44-899b-4afa-b740-71d39ec95a19` |
| DNS Session | `6d67409b-fb91-4ffc-9a9c-7baaf4083700` |
| Release | `0.6.3` |
| Namespace·Interface | `net:[4026532232] / lo / Ingress`, Host `net:[4026531833]` |
| Ledger | 81행 / `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` |

운영 Source68209cf와 동등한 Source668개 및619개 Wheel Python 파일을 유지했다. 새로운 Native/Wheel 코드는 없다.
이미 검증된 Native6개·Wheel 이중 빌드 결과를 재사용하며, Runtime Root executable·BPF·provider bytes는 동일하다.
변경한 Artifact는 고정 Launcher·설정·그 Manifest/Session Binding이다. 이것을 Source 수정본이나 기존 승인 승계로 보고하지 않는다.
상위 정책 만료는2026-10-30 17:36:32.192496 KST이며 기존65분 입장 여유를 유지한다.
**16:31:32 KST 이전**에 최종 검증·Scope yes·sudo 인증이 완료되지 않으면 이 후보를 실행하지 않는다.

## Root 변경 범위

고정8경로 중 내용 변경7개 설정, Root service.py는 동일 bytes다. 기존 설치·Rollback을 보존한다.

- Collector의 기존 `trial-limit.conf`: Runtime420·job/start/stop 제한.
- TCP service: 기존 oneshot90초를 존중하는 JobTimeout90·SendSIGKILL.
- 설치 policy JSON: 새 exact Source/Scope/R1 검토 SHA.
- Runtime service: Runtime420·JobTimeout40·Start15·Stop35.
- DNS base service: 새 session/동결 Python, 기존 builder가 생성한 원문과 정확히 일치.
- dnsmasq service: JobTimeout15·기존 네트워크/권한/90초 한도 유지.
- 기존 `/usr/lib/soc-agent/continuous/service.py`: 내용 동일, 기존 Manifest 백업/교체 절차에 포함.
- **새** `/etc/systemd/system/soc-continuous-dns.service.d/trial-deadline.conf`:
  JobTimeout15·Start15·Stop10·SendSIGKILL/cgroup 명시. 고정 부모 디렉터리 하나만 새로 만든다.

새 경로/부모 ABSENT를 사전 확인하고, Root 소유·쓰기권한·symlink 검증 후 독점 생성한다.
임의 부모 생성/서비스 enable/추가 패키지/권한·Capability 확대/Host 서비스 변경은 없다.

## 비권한 검증

- 새 실제 GNU timeout soft/hard/정상 Exit2와 기존 post-auth Worker Entry Point, 늦은 Root/서비스 시작 차단,
  effective service 제한 불일치·신뢰할 수 없는 Root drop-in 부모 거부: Workspace **35 PASS**.
- 동결 Git의 독립 Export에서 같은 선택 **35 PASS**. 실제 권한 경계만 모의했으며 Kernel을 실행하지 않았다.
- 기존 fixed coordinator11개 assertion을 유지하면서 새8경로/Deadline Scope를 검증했다.
- `systemd-analyze verify --man=no`는 후보5개 unit과 Collector/DNS drop-in의 오프라인 구문 검증에서 Exit0.
  서비스 로드/활성화/재시작을 수행한 것이 아니다.
- 기존 CLI setup→doctor→start --preview→status 모두 통과. Lease SHA/boot/dev/inode·현재 Ledger chain·Source·모델 SHA를 읽기 검증했다.
  현재 Target 미진입, 내부 check는 승인 후 필요, Runtime STOPPED/Cleanup NOT_STARTED/모델 Action 미승인이다.
- **실제 일반 프로세스 590초 TERM +5초 KILL 시험**: 경과 **595.003136초**, GNU driver return-9,
  TERM을 무시한 자식 SIGKILL 및 하위 프로세스 회수 확인. 테스트 프로세스의 subreaper만 사용했고 Host 설정을 바꾸지 않았다.
  이것은 실제 wall-clock 경과를 측정한 비권한 시험이며 **Native 수집595초 성공이 아니다**.
- 최초 외부 테스트 discovery는 Main 저장소의 다른 pyproject/src를 선택하여 import 실패했다.
  올바른 worktree/Export의 pytest config와 절대 PYTHONPATH를 지정해 해결했고 운영 코드는 변경하지 않았다.
  준비 중 독점 Identity 파일 충돌도 기존 파일을 덮어쓰지 않고 별도 draft로 보존하여 최종 새 Store ID와 대조했다.
- 대상 Launcher3개와 시험 파일의 Ruff·format 검증 통과. 기존 전체1172건/환경 및 Native/Wheel 재현 결과는 재사용했다.

증거 디렉터리는 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-short-deadline-recovery-20261030T061425Z`다. 이전 패키지·Session·설치본·실패 로그·Ledger를 덮어쓰지 않았다.
최종 보존 SHA 수·새 영수증 부재는 `final-preservation-validation.json`을 기준으로 한다.

## 다음 실제 시험과 판정

새8경로·Deadline Binding의 정확한 인간 Scope/R1 확인 → 직접 yes/sudo → 내부 check PASS 후 최대1회다.
TCP4연결·DNS UDP2/TCP1의 고정 local-only 주소/포트/ID/페이로드를 그대로 사용한다.
모델 Action·DNS9·LLM/API·자동재실행·운영 승격은 제외한다.

필수 실제 증거는 TCX READY/Event, Runtime 정상Window/Seal·Attestation·Eligibility,
Heartbeat·Queue·Drop, TCX STOP ACK, DNS CLOSED·Counter·STOP ACK·durable cleanup,
Root-owned/Runtime Cleanup·Queue/Audit Drain·최초 오류/후속 오류/child exit다.
Deadline 도달·Exit0·현재 잔류 없음만으로 Cleanup VERIFIED를 만들지 않는다.
과거 UNKNOWN/FAILED/false·TCX ACK/Runtime/Global Cleanup UNVERIFIED는 그대로다.

현재 새 실환경 시도는0회다. 새 Scope/직접 인증 전에는 `BLOCKED_PENDING_DIRECT_SCOPE_AUTH`이며,
이 보고서는 Native OPERATIONS_VERIFIED 판정이 아니다. 실패하면 자동 재실행하지 않고 증거를 고정한다.

## 사용자 명령

```bash
cd /home/geonug/kdt-linux/soc-one-command-runtime
SOC_DEADLINE_HOME='/home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-short-deadline-recovery-20261030T061425Z/agent-home'
.venv/bin/soc-agent doctor --home "$SOC_DEADLINE_HOME"
.venv/bin/soc-agent start --preview --home "$SOC_DEADLINE_HOME"
```

새8경로 Scope를 확인한 후 실제 사용자 터미널에서만:

```bash
.venv/bin/soc-agent start --gui --home "$SOC_DEADLINE_HOME"
```

기존 CLI가 새 Manifest와 Scope/R1을 표시하고 yes·직접 sudo 인증을 요구한다. SHA를 입력하지 않는다.
다른 터미널의 `soc-agent status/stop/gui --home "$SOC_DEADLINE_HOME"`로 조회·중지·GUI 재연결이 가능하다.
GUI 종료만으로 Collector를 종료하지 않는다. 아직 시작하지 않았다면 Stop을 실행하지 않는다.
