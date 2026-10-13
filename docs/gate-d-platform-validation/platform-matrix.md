# Platform Matrix

| 대상 | 통제된 실행·설치 | 운영 호스트 전체 검증 | 판정 |
|---|---|---|---|
| Windows 11 Desktop / Python 3.12.14 | fresh venv, locked core + base wheels, 실제 native 3모델, CLI/API/재시작/error/duplicate PASS | 운영 인증·installer·GUI·서비스 supervisor 미검증 | PASS (실제로 검증된 Python CLI/test transport 범위) |
| Linux Desktop | WSL Ubuntu x86_64의 packaged CLI 시작/종료/재시작/모델·권한 검증 PASS | 별도 Linux Desktop 없음 | INCONCLUSIVE |
| Linux Headless | WSL, display 없는 packaged SERVER CLI + 실제 loopback test HTTP/ASGI PASS | 별도 Linux server/systemd/service auth 없음 | INCONCLUSIVE |
| Windows Server | 지원 대상 아님 | 없음 | NOT_TESTED / 지원하지 않음 |

전체 GATE_D_INCONCLUSIVE. WSL 결과를 독립 Linux 운영 호스트로 대체하지 않는다.
Core venv는 양쪽에서 새로 구성했다. Native heavy env는 기존 검증 환경을 재사용했다.
이번 비교는 실행 호환성이고 bit-level native prediction 또는 최종 Decision equality
comparator의 새 PASS가 아니다. 과거 Gate A 비교는 별도 synthetic SOC 모델 범위다.
