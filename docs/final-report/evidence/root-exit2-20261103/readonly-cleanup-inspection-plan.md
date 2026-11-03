# 현재 Cleanup 읽기 전용 권한 검사 준비 — 실행 미승인

아래 명령은 이번 작업에서 실행하지 않았다. 새로운 Root 검사 승인·직접 인증 전에는 실행하지 않는다. 기존 실행/검토 패키지나 영수증을 재사용하지 않는다. 이 문서는 승인 시스템·실행 예약·승인 영수증이 아니다.

대상은 기존 `/run/netns/soc-native-b3` / `net:[4026532232]`, 실패 Session `81660de4-5cb8-418a-ae46-520ba4b168c0`가 소유한 자원이다. 먼저 Namespace inode/dev/Boot ID·도구 경로/SHA를 기존 계약으로 검증한다. PID 조회는 StartTicks를 반드시 대조하며 다른 프로세스에 PID가 재사용됐으면 조사 대상에서 제외한다.

## 준비된 읽기 전용 명령·경로

- `/usr/bin/nsenter --net=/run/netns/soc-native-b3 /usr/sbin/bpftool -j net show`: 대상 Namespace TCX attachment 조회만. attach/detach 없음.
- `/usr/sbin/bpftool -j link show`, `/usr/sbin/bpftool -j map show`, `/usr/sbin/bpftool -j prog show`: metadata snapshot만. 소유권을 증명할 수 없는 전역 객체를 삭제/변경하지 않음. 전역 program ID 변화만으로 leak/cleanup 성공 판정 금지.
- `/usr/bin/nsenter --net=/run/netns/soc-native-b3 /usr/bin/ss -anep`: 대상 Namespace socket 조회만. 포트53/18080/18081/18082 및 이번 실행 inode/소유자와 대조. 연결/송신 없음. 도구 실제 존재/권한/SHA를 사전 검증해야 하며 없으면 자동 설치하지 않음.
- `/proc/2079245/stat`, `/proc/2079255/stat`, `/proc/2079360/stat`와 해당 `fd`/`ns` metadata: 각각 StartTicks `102295355` / `102295443` / `102295896` 일치 시에만 이번 프로세스로 취급. 현재 일반권한 Snapshot에서는 세 PID 모두 없음. 이는 과거 종료 절차 검증을 대신하지 않음.
- `/run/soc-agent-continuous/1000.sock`: 존재/UID/mode/inode와 소유 FD 조회. connect/send/삭제 없음.
- `/var/lib/soc-agent/continuous/1000.jsonl`: 필요한 후속 tail의 hash-chain·기존 prefix 검증. 원본 append/수정 없음. 원본이 Root-only면 권한 없이는 읽지 않음.
- `/var/lib/soc-agent/continuous/backups/candidate-final/`의 원 실행 `installed-1..8.json`에 열거된 정확한 백업 8개 SHA 조회만. 경로는 실제 원 증거의 backup 필드로 한정한다. 복원/교체/삭제 없음.

서비스 시작·중지·재시작, Namespace 생성/삭제, BPF 변경, Native Capture, DNS/TCP 트래픽, 모델/API 호출을 포함하지 않는다. 현재 잔류 자원 없음이 확인되어도 과거 TCX STOP ACK·Runtime Cleanup UNVERIFIED는 소급 변경하지 않는다. 현재 검사와 과거 종료 증거를 독립 보고한다.
