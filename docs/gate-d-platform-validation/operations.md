# 통제된 실행·운영 경계

운영 DB를 probe/테스트에 지정하지 않는다. Production CLI는 기존 recognized private
runtime을 재개할 수 있지만 진단 probe는 새로운 directory만 받아들이고 끝에 receipt를
의도적으로 변조하므로 해당 디렉터리를 재사용하지 않는다.

```bash
<installed-python> -I -m soc_agent.external_runtime --directory <fresh-private-data> --input <validated-events.jsonl> --external-features <validated-feature-rows.jsonl> --artifacts <trusted-artifacts> --native-python <validated-native-python> --profile SERVER
# 정상 종료 후 같은 CLI/입력 명령으로 실제 프로세스 재시작·Resume 검증
```

Linux Desktop / Windows 11은 DESKTOP을 사용한다. Windows SERVER는 지원하지 않는다.
Top40 및 DNS 9-feature는 별도 explicit source record이며 Network 5-feature에서
자동 생성하지 않는다. 현재 파일 replay는 실제 packet/log collector가 아니다.

## 설치본 TEST 서비스 probe

```bash
# tests/ 파일은 배포 wheel 일부가 아니라 독립 offline 진단 코드다.
<installed-python> -I tests/diagnose_gate_d_platform.py --directory <new-isolated-data> --input <synthetic-events> --features <synthetic-features> --artifacts <trusted-root> --native-python <native-python> --profile SERVER
```

Windows 새 venv에서는 같은 진단에 DESKTOP, 새 LOCALAPPDATA 전용 디렉터리를 사용한다.
신규 모델 feature fixture는 기존 Gate C test의 inputs() helper로 임시 경로에 생성했다.
수행한 probe는 HTTPServer(127.0.0.1, port=0) TEST transport, proxy 비활성,
실제 SOCApplication 및 opaque in-memory TEST identity를 사용한다.
401 unauthenticated, 403 incident/access denial, 422 invalid approval,
200 resume / 409 duplicate revision, two transport lifecycle, tampered receipt restore denial,
execution_records=0을 확인한다. 실제 TLS/server install/auth Provider를 제공하지 않는다.
Production authentication은 trusted Provider 및 incident-aware AccessPolicy의 별도 구성이
필요하다. 진단 fake provider를 배포 설정으로 사용하지 않는다.

## 장애와 복구

- 정상 종료: CLI writer lock 해제, SQL transaction 종료; 새 process에서 resume.
- 중복 writer: 두 번째 CLI deny, 첫 writer 정상 완료; lock/권한 검사를 삭제하지 않는다.
- interrupted READ: actual runtime process-exit 테스트의 explicit operator reconciliation을
  사용한다. 불명확한 action을 자동 replay하거나 승인 기록을 자동 재사용하지 않는다.
- stale writer-directory lock: 실제 writer가 종료했는지 외부 process 확인 및 원인을
  조사한다. DB/Context/Receipt/Audit 검증 전 임의 cleanup/삭제/자동 재실행을 하지 않는다.
- corrupted DB/receipt/context: fail-closed; 원본 보존·검증된 backup/복구 절차가 필요하다.
  시험은 오직 새 SQLite에 수행했다. 자동 DB 복구/운영 migration 제공을 주장하지 않는다.
- missing model/config/backend: sanitized no fallback exit; trusted files/env만 보완한다.

POSIX directory0700/file0600/UID/inode/sidecar와 Windows NTFS owner/protected DACL,
TrustedInstaller/OWNER RIGHTS/reparse/TOCTOU 정책을 유지한다. AppData라는 위치명은
보안 증명 대신 사용할 수 없다. unsupported FS는 fallback하지 않는다.
로그에는 raw Evidence, credentials, tokens, model internal data를 넣지 않는다.
Native subprocess는 기존 whitelist environment를 사용하고 LLM/provider 요청은 없다.
운영 서비스 bind/TLS/key rotation/process supervisor/access policy는 별도 미검증 범위다.
