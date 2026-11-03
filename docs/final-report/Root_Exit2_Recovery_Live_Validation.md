# Root Exit2 Recovery — 실제 읽기 전용 검사 및 Native 입장 상태

2026-11-03. 사용자가 `.git/root-exit2-retest-preparation-20261103T053700Z/native/approval-package-final.md`의 A/B/C/R1 및 선행 읽기 전용 검사를 승인했다. 실제 Root 읽기 검사만 수행했고, 아래 기록 시점에 Native 시험은 아직 시작하지 않았다.

## 실제 읽기 전용 검사

사용자가 별도 터미널에서 Scope를 확인하고 sudo를 직접 인증했다. 비밀번호/API Key를 프로그램이나 보고서에서 읽거나 기록하지 않았다.

- Namespace inode4026532232/dev4/Boot Identity 일치.
- 기존 Collector2079245·Runtime2079255·DNS Helper2079360 PID 없음. 5개 고정 서비스 cgroup.procs 비어 있음. 고정 Root Unix Socket 없음.
- 설치8경로 SHA/inode/mtime 모두 일치, 기존 Root 백업8개 SHA 일치.
- Root Audit8029행 체인/원본 prefix 보존.
- 대상 Namespace XDP/TC/flow_dissector/netfilter attachment 목록 비어 있음. 전역 BPF Link0/Map0. 프로그램11개는 systemd 이름의 cgroup_device/cgroup_skb metadata로 관측됐고 수정/삭제하지 않음. 전역 Kernel Cleanup VERIFIED로 확대하지 않는다.
- 대상 Namespace ss에는 승인된 TCP/DNS 포트의 잔류 Listener/Client가 없음. 조회 도구 자체의 netlink socket 관측과 실제 공급원 socket을 구분한다.

**현재 Snapshot 판정: NO_SCOPED_RESIDUAL_RESOURCE_OBSERVED. 과거 TCX ACK/Runtime Cleanup은 UNVERIFIED 그대로다.** 관측 이후 모든 시점에 잔류가 없음을 보장하거나, 과거 종료 절차가 성공했다고 소급하지 않는다.

### 검사 실패 이력도 보존

첫 검사0.590193초에 `/usr/sbin/bpftool` 래퍼의4개 BPF 조회가 Exit2였다. WSL kernel6.18.33.2-microsoft용 linux-tools를 찾지 못한 배포 래퍼 선택 실패이며 Kernel BPF 조회 결과가 아니다. 같은 검사에서 설치/백업/Audit/PID/Socket은 통과했다.

승인된 request의 `tools_readonly_pins`에는 실제 `/usr/lib/linux-tools/6.8.0-147-generic/bpftool` SHA가 이미 고정돼 있었다. 그 파일을 검증해 남은 동일4개 읽기 조회만 완료했다. 첫 비TTY `sudo -n`은 비밀번호 필요로Exit1, Root 실행0이었다. 사용자 터미널에서 직접 확인·sudo 인증 후 동일 고정 도구의4개 읽기 조회가 Exit0/0.047850초로 통과했다. 초기 실패 결과를 삭제하지 않았다. 패키지 설치·Root 파일 교체·서비스/Namespace/BPF 변경·Native/DNS/모델/API 실행은 이 검사에 없다.

원본 검사: `.git/root-exit2-retest-preparation-20261103T053700Z/readonly-inspection/`. [판정과 SHA](evidence/root-exit2-live-validation-20261103/inspection-settlement.json).

## Native 시작 전에 발견한 Scope 안내 결함

승인 원본 terminal.py가 여전히 “Root4개 변경/Collector service 포함” 및 “최근 owned Cleanup VERIFIED”를 표시했다. 실제 검토서·Manifest는3개 변경이고 직전 TCX ACK/Runtime Cleanup은UNVERIFIED다. **잘못된 Scope 안내로 확인받지 않도록 기존 후보의 Native는 시작하지 않았다.** 이 결함을 검토 패키지 준비 단계에서 잡지 못했다.

원본은 변경하지 않고 새 draft의 terminal.py에서두 print문을 수정했다.

1. Root 전체/변경 수를 현재 Manifest의 replacement 실제 SHA 비교로 계산.
2. 최신 TCX ACK와 Runtime Cleanup을 각각 request의 latest_failed_trial에서 읽고, 값이 없으면UNKNOWN. 다른 소유 범위 VERIFIED로 승격하지 않음.

실행권한/Timeout/권한체크/모델/API 한도 코드는 변경하지 않았다. **운영 Source30df74e·frozen Git3046260·모델·Native 바이너리는 불변**이며 Session/config/Entry Artifact만 새로 결합했다. 새 후보에 과거 승인 영수증을 재사용하지 않았다.

[변경 patch](evidence/root-exit2-live-validation-20261103/terminal-scope-display.patch), [print문만 실행한 회귀](evidence/root-exit2-live-validation-20261103/scope-tests.log):7 PASS/0.37초, no-live guard위반0. Root0/3/4/8개 변경 및 각 Cleanup 조합·누락·영역확대 금지를 검증했다. Launcher전체/Root/Native를 실행한 테스트가 아니다. 기존 운영코드883/883 회귀 및3방향 byte-identical 빌드는 변경 없는 Source에 적용되며 이번에 Native를 새로 실행했다는 뜻은 아니다.

## 수정 후보와 사용자 직접 확인

- 새 검토서: `.git/root-exit2-scope-display-recovery-20261103T055000Z/native/approval-package-final.md`.
- 새 Runtime Session: `9018e290-ce23-4874-89fc-4f03cf878320`.
- 전체600초/수집360초 목표, TCP4/DNS UDP2+TCP1, Root8경로 중3개 변경, 기존 자원/저장량/Queue32 유지.
- B는 실제 봉인 ELIGIBLE 작업의 GUI 독립 결정, 전체 RF/LR16회 이하. C는 같은 Native Session Incident/Revision의 GUI 독립 결정, 실제2회/$0.05/요청20초/출력4096/재시도0.
- 실제 `soc-agent start --gui --home <새 operator-home>`를 사용자 터미널에서 호출했다. Native 승인 원본과 다른 새 Binding을 명확히 표시하고, 사용자 직접yes를 **새 정확한 Scope/R1 결정**으로 기록한 뒤 sudo를 수행하는 기존 Entry Point다. 자동yes/승인영수증 발급/Native 실행은 하지 않는다.
- 기록 시점에는 scope-confirmed.json이 없고 **WAITING_DIRECT_USER_SCOPE_CONFIRMATION**. 원본 승인 Session의 Native도0회다. 새 Binding 확인 전에는 Collector 시작0/Packet0/DNS0/모델0/API0이다. 대기 중인 GUI를 실제 수집 성공으로 표시하지 않는다.

사용자 직접 실행 경로:

```bash
cd ~/kdt-linux/autonomous-soc-agent
releases/research-mvp/.venv/bin/soc-agent start --home /home/geonug/kdt-linux/autonomous-soc-agent/.git/root-exit2-scope-display-recovery-20261103T055000Z/operator-home --gui
```

이미 열어 둔 새 터미널이 이 명령을 실행 중이면 중복start하지 않는다. 현재 Scope/R1 prompt에서 직접 확인하고, 이후 sudo 및 실제 입력별 GUI 결정을 진행한다. 사용자가 취소하거나 정책/Binding/잔류 검증이 실패하면 실행하지 않는다. 실패 후 자동 재실행0.

## 실제 API 전 문서 확인

OpenAI Docs 지침으로 공식 [gpt-5-mini](https://developers.openai.com/api/docs/models/gpt-5-mini)와 [Deprecations](https://developers.openai.com/api/docs/deprecations)를 열어 확인했다. 입력$0.25/출력$2 per million, Structured Outputs지원, Deprecated/2026-12-11 종료예정이다. 모델은 자동교체하지 않는다. 계정별 가용성은UNKNOWN이며 인증probe0이다. 60000입력 예약/4096출력 기준2회 보수적 예약$0.046384로$0.05 이하이며 실제 입력·예약/잔여예산 검증은 요청 직전 기존 Adapter가 수행한다. Usage없음/Timeout은비용UNKNOWN이다. [문서 사전확인](evidence/root-exit2-live-validation-20261103/official-api-preflight.json).

## 이 기록 시점 판정

|항목|결과|
|---|---|
|현재 읽기 전용 자원 검사|제한 Scope 통과, 초기 도구·인증 실패 보존|
|Native / DNS / RF-LR / LLM / Orchestration|NOT_EXECUTED — 직접 Scope 확인 대기|
|GUI|창 기동; 실제 Native 데이터 표시/재연결은아직미검증|
|과거 TCX ACK / Runtime Cleanup|UNVERIFIED 유지|
|FULL_E2E_OPERATIONS_VERIFIED|선언하지 않음|

실제 시험이 시작되면 같은 Session의 원본 실행 증거로 별도 결과를 기록해야 한다. 현재 문서의 대기 상태를 실행 성공으로 해석하지 않는다.
