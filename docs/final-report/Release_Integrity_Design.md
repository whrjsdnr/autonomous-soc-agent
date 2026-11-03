# 설치 Release·Session 무결성 설계

## 개발과 설치 실행의 분리

Development/Diagnostic 모드는 기존 editable Worktree와 일회성 `--native-review`를 사용한다. Source 변경, 임시 Session, Root 후보 변경은 기존 exact Binding을 다시 검토한다.

Installed Research MVP는 `installed-release.json`에 **이미 동결한 기존 review**의 Code/Git·Artifact·Launcher 참조를 등록한다. 실제 Native 실행 Source는 해당 Release의 frozen Git와 검증한 export이며 개발 HEAD를 새 실행에 자동 사용하지 않는다. 현재 등록된 Native backend는 검증된 코드2064af1이다. 새로운 관리 CLI 기능과 이 Native backend의 코드 identity는 별도로 기록한다.

관리 CLI도 검증된 Wheel을 사용자 전용 `~/.local/share/soc-agent/management/<wheel-prefix>-<installer-prefix>/`에 설치한다. 기존 Controller Python 준비기로 기본 Python을 구성한 뒤 실제 CLI·GUI·API 검토 import closure와 Tcl/Tk·과학 라이브러리 DSO·패키지 리소스를 격리한다. 전체 애플리케이션은 기존 Source-style 파일 SHA map으로 고정한다. 최소 Controller의 2048파일/64MiB 검증 한도는 변경하지 않으며 관리 애플리케이션 환경을 Native Controller qualification으로 취급하지 않는다. 표준 라이브러리 entry는 파일 SHA·소유자·권한을 확인한 뒤 고정 Python의 설치 패키지를 실행한다. 개발 Source import와 옛 venv fallback은 설치된 관리 Release가 존재하면 사용하지 않는다. 이 사용자 소유 설치는 Root 신뢰 승인이나 관리자로부터의 변조 방지 서명을 의미하지 않는다.

## 기존 검증 경로

| 대상 | 기존 검사 |
|---|---|
| 등록된 review/실행 pins | verify_review, installed reference 파일 비교 |
| Source/Controller identity | source-files + frozen execution Git + validate_plan |
| Root 고정8경로·실제 변경 집합 | installation_plan / bind_installation_scope / Root verify_contract |
| Namespace/Lease/Boot/Host 분리 | namespace_binding 및 승인 후 내부 검사 |
| Ledger chain·현재 head | ledger_snapshot; 변경 시 별도 검토 필요 |
| Model/Feature/입력 | 기존 Registry·Fingerprint·Attestation·ELIGIBLE·Action 승인 |
| API | 정확한 Incident/Revision·입력 SHA·Provider·횟수·비용·Timeout |

Release 등록에는 실행 유효기간을 활성화하지 않는다. 만료된 review를 설치 참조로 읽을 수 있지만 `verify_review`의 실행 기본 경로는 여전히 만료를 차단한다. 새 Session은 새 만료 제안을 만들고 새 직접 인간 결정을 요구한다. 소비된 영수증은 복사하지 않는다.

## Session 자동 준비

새 UUID와 DNS Session은 기존 `Store.create`, `dns_source.prepare`를 사용한다. Queue/Incident/Audit은 새 디렉터리로 분리한다. DNS Python과 Native Source는 검증된 Release를 재사용한다. 고정 TCP/DNS 포트·페이로드·횟수·Deadline·자원은 확대하지 않는다.

Root 후보에 Session 경로가 들어가므로 실행별 Root Manifest SHA는 달라진다. 이 변경을 숨기지 않으며 기존 Root 승인을 재사용하지 않는다. Source/Wheel 안정성과 실행별 설정의 정확성은 별도 대상이다. 초안 생성은 프로세스/Socket/Capture/API를 시작하지 않는다.

## 갱신·복구

`setup --installed-release NEW_REVIEW --update`만 참조를 교체한다. 새 후보 검증·새 Session 준비 이전에는 현재 참조를 바꾸지 않는다. 이전 참조와 profile을 보관한다. 게시 도중 중단해 profile/Release가 다르면 identity 검사로 실행을 차단한다. Root 설치/백업/rollback은 기존 직접 인증 Launcher가 담당한다.

자동 재시도는 없다. 이전 실행의 최초 오류·Cleanup 누락 시 새 Session 생성을 차단한다. 현재 Session을 GUI에서 닫거나 조회하는 행위는 Collector 생명주기를 변경하지 않는다. historical Session은 기존 GUI에 별도 attach하며 Source와 Session 표시는 유지한다.

## 증거

이번 비권한 실행 자료: `.git/operator-ux-validation-20261103/`. 기존 Root verify_contract를 실제 새 draft 파일에 적용하되 인간 결정/Root 서비스 조회만 메모리 fixture로 사용했다. 실제 Root 설치·서비스·Namespace 진입·Native·DNS·모델 Action·API·영수증 소비는 수행하지 않았다.
