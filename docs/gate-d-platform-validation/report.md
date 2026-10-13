# Gate D — 통제된 플랫폼·패키징 검증

## 판정: GATE_D_INCONCLUSIVE

Windows 11 Native 및 WSL에서 클린 non-editable 패키지 설치, 공식 3모델 추론,
CLI 시작/종료/프로세스 재시작, loopback 테스트 HTTP/ASGI lifecycle, 오류 경로,
READ_ONLY·무결성 경계를 확인했다. 그러나 별도 Linux Desktop/Headless 운영 호스트에
접근하지 못했으므로 지원 플랫폼 전체의 필수 실행을 완료했다고 판정하지 않는다.
운영 배포, 운영 인증 Provider/TLS/서비스 설치 및 GUI 검증도 수행하지 않았다.

## Gate C 기준선

- Commit: `b47c83d3e563a5c0862cc56edb21c504440e7724`.
- Annotated tag: `gate-c-soc-integration-rc1`.
- Gate C 테스트·보고서 2개만 Stage/commit; 원본 증거 SHA와 Windows 파일 SHA 확인.
- Gate B `787dff886c203cd14e351021f7d72b08fae17147` / tag 변경 없음.
- 기존 WSL 3104 passed/25 skipped, Windows 집중 249+16 및 Gate C WSL 2+100,
  Windows 1 passed 증거 재사용. 전체 회귀 재실행 없음.

## 패키징·설치 결과

1. Gate C HEAD를 `git archive`로 임시 사본에 복원했다. 사용자 README/pyproject
   변경이나 untracked 작업물을 빌드에 포함하지 않았다.
2. `uv build --offline` wheel/sdist PASS. pure Python wheel에 359개 entry가 있고
   `soc_agent/api/dashboard/style.css` 포함; 모델/DB/로그/unsafe path 없음.
3. WSL fresh venv에 `uv sync --frozen --no-dev --no-editable` 성공.
   첫 offline 시도는 NCCL cache 부재로 실패했고 pinned download 후 성공했다.
   GPU를 사용한 것은 아니다. XGBoost의 Linux transitive NCCL 의존성을 삭제하지 않았다.
4. Windows fresh venv에 `uv export --frozen --no-dev --no-emit-project`의 hash-locked
   requirements와 동일 wheel 설치 PASS. 원본 Conda 환경과 base는 변경하지 않았다.
5. SOC Core만으로 외부 추론을 실행한 시도는 공식 client 패키지 3개 부재로 fail-closed.
   설치 규칙을 명확히 해 official 0.1.0 base wheel 3개를 추가했다. ML 원본을 수정하지
   않고 pyproject/README/src 임시 사본에서 빌드; SOC code pin 일치 확인.
   두 build backend는 별도 isolated build에서만 설치했다.
6. base 패키지 설치에 `--no-deps`를 사용했지만 요구되는 NumPy/Pydantic은 이미
   frozen 설치로 충족됐으며 Linux `uv pip check`, Windows `pip check` 모두 PASS.
   Heavy Native 환경은 Gate B에서 검증한 기존 별도 interpreter를 재사용했다.
   Heavy backend의 fresh install 재현성은 이번에 새로 입증하지 않았다.
7. `-I`, unrelated cwd 및 installed module path 검사로 개발 SRC/PYTHONPATH에
   의존하지 않음을 확인했다. artifact 및 interpreter는 명시적 경로로 전달한다.

SOC package version은 0.1.0이며 RC 구분은 Git tag와 wheel SHA로 해야 한다.
[installation.md](installation.md)에 전체 필요 설치 단계를 기록했다.

## 실행 결과

| 검증 | 결과 |
|---|---|
| WSL installed Desktop/SERVER CLI | PASS: profile 각각 시작·별도 프로세스 재시작, 실제 3모델, DISPLAY/Wayland 없이 실행 |
| WSL installed SERVER + loopback TEST transport | PASS: 인증 READ, 401/403/422, resume/중복409, transport 두 lifecycle, receipt 변조 restore 거부, execution_records=0 |
| Windows clean wheel + official base + 기존 native env | PASS: DESKTOP 실제 3모델/재시작, 동일 loopback/무결성 테스트 |
| WSL 최종 config/storage fault tests | 5 passed / 1 deselected (13.42초) |
| Windows 최종 config/storage fault tests | 5 passed / 1 deselected (27.13초) |
| WSL 실제 duplicate CLI + crash/publication/audit 회귀 | 21 passed / 64 deselected (43.46초) |
| Windows 실제 duplicate CLI | 1 passed (34.77초) |
| 별도 Linux Desktop/Headless hosts | NOT_TESTED |

이번 신규 probe는 실제 production SOCApplication을 stdlib HTTPServer의
**loopback-only TEST transport**로 호출한다. 모델/Runtime/guard를 mock으로
대체하지 않았다. Identity/AccessPolicy와 LLM은 test/scripted 객체이므로 운영
인증·서버 제공 기능을 새로 구현했다고 주장하지 않는다. HTTP transport 종료/재시작과
CLI 실제 프로세스 재시작을 구분한다. 서버 transport lifecycle은 같은 service의
두 cycle이며 별도 운영 서비스 프로세스 supervisor 테스트가 아니다.

Fault 테스트는 feature 개수 불일치, artifact 부재, DNS 모델 독립 복사본 SHA 변조,
SQLite 손상, native executable 부재를 실제 CLI에서 실행했다. nonzero exit,
no fallback, traceback/raw marker 미출력과 writer lock cleanup을 확인했다.
실제 첫 writer가 살아 있는 동안 두 번째 CLI를 실행해 거부와 첫 정상 종료를 확인했다.
프로세스 강제 종료·pending claim explicit recovery·publication rollback·audit
실패는 기존 actual Runtime 테스트를 집중 실행했다. 자동 lock 삭제/자동 action replay는 없다.
동일 Incident CAS/다른 Incident/WRITE spy 및 Approval guard는 Gate C의 100개 증거와
동일 production SHA이므로 재사용한다.

## 결함·수정 및 보안

프로덕션 결함 또는 Guard 위반 없음; production source 변경 없음.
환경 보완: 누락된 cache/build backend 및 공식 base 패키지 설치.
진단 harness 초기 Principal 필수 scopes 누락을 실제 계약에 맞춰 수정했다.
테스트 identity는 scopes=(), opaque in-memory credential이며 실제 승인 권한이 아니다.
처음 base package 설치 완료를 설명한 시점에는 build 실패가 있었음을 후속 로그로
확인했고, 명령별 check=True 및 실제 3 wheel/installed code pin 확인으로 정정했다.
초기 실패를 숨기거나 skip/xfail, 검증 완화 또는 fake 모델로 대체하지 않았다.

Native 모델은 original immutable artifacts만 로딩한다. SHA 오류는 독립 copy만 변경했다.
원본 모델/Selection/Golden/Decision ID/Fusion/Policy/Approval/Audit 계약 불변.
운영 DB, 실제 WRITE, Live LLM, push, Conda base 및 ML 원본 수정 없음.
새 데이터 경로만 허용하는 probe가 일부 fresh DB receipt를 의도적으로 변조한 뒤
restore 거부를 확인한다. 해당 디렉터리는 테스트 후 재개하지 않는다.

신규 미커밋 파일:
- `tests/diagnose_gate_d_platform.py`
- `tests/integration/external_runtime/test_gate_d_fail_closed.py`
- 본 폴더의 report/matrix/installation/operations/remaining-risks 5개 문서.

Gate D commit/tag를 생성하지 않았다. 기존 tracked 수정 3개와 사용자 untracked는
보존했다. 원본 Windows 검증본은 보존하고 신규 package/test 사본만 별도 경로에 추가했다.

## 다음 조건

Gate E 운영 실행 준비를 PASS로 간주하고 진행할 수는 없다.
WSL/Windows 통제된 개발/설계는 조건부 가능하지만 별도 사용자 지시가 필요하다.
Gate D 최종 PASS를 위해 실제 Linux Desktop/Headless 호스트, 운영 인증·서비스
startup/shutdown/failure recovery 및 heavy backend installation 증거를 보완해야 한다.

## Artifact / 진단 SHA-256

- `autonomous_soc_agent-0.1.0-py3-none-any.whl`: `b43d689fc61a581d051d3d03aed841aad828db46a85d8c008bab7e0355e02e19`
- `dns_security_ai-0.1.0-py3-none-any.whl`: `cd959e3cc451b442e7385445f2782029fb22e3078aa0f32b8715440483a8cb20`
- `network_security_ai-0.1.0-py3-none-any.whl`: `a16fe7ac06f156a63d2d1c3946f16b959251acce45b779f7e897e088b9660220`
- `security_ai-0.1.0-py3-none-any.whl`: `6ab3a6beba0353889693932013e3776047bd87478c099b50a6689efa57912b3a`
- `tests/diagnose_gate_d_platform.py`: `3ca334687355e95d355d3140debbd7fa5fecb0d32e38bbaa3cf72a4890f8432f`
- `tests/integration/external_runtime/test_gate_d_fail_closed.py`: `c496a166c8e237019b8e28eecb9c20b5bf690fb0c7f551e6f61721228731479f`

## 최종 정적 검사 및 실행 증거

Ruff check PASS; format --check PASS (681 files); git diff --check PASS.
- `/tmp/soc-gate-d-build.log` SHA-256 `0eb7fe7e79c4e7ab7e2592c0d2d136aa3c64a5e32e76c6910481ccda3aca7e5b`
- `/tmp/soc-gate-d-install-online.log` SHA-256 `3a0d7979bad3763c01cfadb7ba55292f1e9367830c38c143515881bd7e0ab6ea`
- `/tmp/soc-gate-d-packaged-cli.log` SHA-256 `80d349ea97d1cf43c6ad9f523d99af73200394b5c21ff37621c87af9a549c768`
- `/tmp/soc-gate-d-loopback-linux.log` SHA-256 `27272577f8264ef3d13ffb7d865271444b0bd8e6f0c6b7eb705c56e2251f438e`
- `/tmp/soc-gate-d-fail-closed-final.log` SHA-256 `da2b01fe27f9ccc97a92aa61a381ecdbfc608268cdd1a2af9eb64484c74ea35d`
- `/tmp/soc-gate-d-recovery.log` SHA-256 `e7db560ad6029196ab5b4d90353f90f0a550301906bc17a04ec6480aea2ff5a6`
- `/mnt/c/soc-gate-d-packaging-20261013/probe-final.log` SHA-256 `786a7a7d3f4c24c5d9e7706b653f8efac6b48c82c13d45756dbc99c6c284ce21`
- `/mnt/c/soc-agent-final-native-20261013/windows-gate-d-fail-closed-final.log` SHA-256 `2582f775cd9bc98850d9bdcf23e0adddc13e3fb6b2744a4e89dd1a4a16647e33`
- `/mnt/c/soc-agent-final-native-20261013/windows-gate-d-duplicate.log` SHA-256 `0208066f6c64bfa8d720fb891ad871d9afeb6d4d9ad494a4a2329a011ffbe358`
