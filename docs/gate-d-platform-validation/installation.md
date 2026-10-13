# 설치·패키징 재현

Python 3.12.14, SOC 0.1.0 / Git gate-c-soc-integration-rc1을 사용했다.
기존 프로젝트/Conda 환경에 설치하지 말고 새 전용 venv를 사용한다.
SOC pyproject ranges만으로 정확 버전이 고정되지 않으므로 uv.lock을 함께 사용한다.

## SOC core (실제 성공)

```bash
# trusted tag를 별도 빈 디렉터리에 git archive로 복원
uv build --offline --out-dir /tmp/soc-dist
uv sync --frozen --no-dev --no-editable
uv export --frozen --no-dev --no-emit-project --format requirements-txt > requirements.lock.txt
```

첫 offline install은 cached nvidia-nccl-cu13==2.31.2 부재로 실패했다.
Frozen online install 후 성공; dependencies는 업그레이드하지 않았다.
Linux XGBoost transitive GPU dependency는 CPU 추론에도 설치 비용이 있다.
필요한 wheels를 사전 준비하지 않으면 air-gapped install을 주장할 수 없다.

Windows는 새 venv에 다음을 실행했다(기존 soc-windows Python으로 venv만 생성).

```powershell
python -m venv C:\soc-gate-d-packaging-20261013\venv
# 아래 python은 새 venv의 Scripts\python.exe
python -m pip install --require-hashes -r requirements.lock.txt
python -m pip install --no-deps autonomous_soc_agent-0.1.0-py3-none-any.whl
```

Core wheel은 py3-none-any이며 stylesheet 포함을 확인했다. 모델 파일은 포함하지 않는다.
PyInstaller/installer가 구현되었다고 주장하지 않는다. pip/base upgrade는 수행하지 않았다.

## 외부 base packages (부모 SOC 환경에도 필요)

공식 network-security-ai / dns-security-ai / security-ai 0.1.0 wheel 3개가 필요하다.
`--native-python`만 제공하고 parent에 이 패키지가 없으면 reviewed_binding이 fail-closed.
ML 원본은 읽기 전용이고 pyproject/README/src의 임시 사본에서 공식 wheel을 빌드했다.
Build backend는 Network/SOC uv_build 0.12.x, DNS/common 0.13.x로 isolated build한다.

```bash
uv pip install --python <fresh-soc-python> --no-deps <official-network-wheel> <official-dns-wheel> <official-common-wheel>
uv pip check --python <fresh-soc-python>
```

Windows는 해당 wheel 3개를 pip install --no-deps 후 pip check했다.
`--no-deps`가 의존성 검증 우회가 되지 않도록 NumPy/Pydantic은 frozen core 설치로
이미 충족시키고 dependency check를 필수 실행한다. Source code pin도 일치 확인했다.
검증된 wheel SHA는 report.md에 기록한다. ML repository dev 절대경로를 installed
package의 런타임 경로로 사용하지 않는다.

## Native 환경 / artifacts

기존 validated interpreter와 release security-ai-artifacts-v1 파일을 재사용했다.
LightGBM 4.7.0, Torch 2.14.1, LiteRT 2.3.0, pandas 3.0.6의 기존 env에서 실제
Quality/Edge/DNS를 실행했다. 해당 heavy env의 fresh build는 이번에 재현하지 않았다.
SOC core lock은 이 optional heavy environment의 transitive lock이 아니다.

Production CLI에 `--artifacts <trusted-root>` 및 `--native-python <trusted-python>`을
명시한다. Windows 기존 private root는 LOCALAPPDATA/AutonomousSOCFinalArtifacts20261013이다.
실제 native worker와 probe가 pinned Model ID / Feature Contract / file SHA를 검증했다.
잘못된 root, SHA, backend는 failure이며 자동 download/replacement/retraining이 없다.
Scalers/pickle은 검증된 프로젝트 생성물만 로딩한다. 해시만으로 arbitrary pickle의
안전성이 보장되지 않으며 immutable trusted artifact root가 전제다.
