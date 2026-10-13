# Windows 동기화 / 재검증

실제 검증 디렉터리는 `C:\soc-agent-final-native-20261013`이다. 기존
`C:\soc-agent-windows-test`는 변경하지 않았다. 최종 patch delta의 SHA는
`windows-final-scope-delta.json`와 `windows-final-cas-delta.json`에 보존한다.

## 기존 검증본 동기화 전 확인

WSL Source: `\\wsl.localhost\Ubuntu\home\geonug\kdt-linux\autonomous-soc-agent`.
`windows-sync.json`에는 이번 코드/테스트 33개만 있다. 모델, 설정, `.env`,
보호된 Fusion helper는 대상이 아니다. 23개 기존 파일은 기록된 이전 SHA와
일치했으며 10개는 신규 파일이다. 실제 동기화 직전에 반드시 재확인한다.

```powershell
$source = '\\wsl.localhost\Ubuntu\home\geonug\kdt-linux\autonomous-soc-agent'
$target = 'C:\soc-agent-windows-test'
$m = Get-Content (Join-Path $source 'docs\security-ai-final-integration-20261012\windows-sync.json') -Raw -Encoding UTF8 | ConvertFrom-Json
foreach ($f in $m.files) {
    $s = Join-Path $source $f.path
    if ((Get-FileHash $s -Algorithm SHA256).Hash.ToLower() -ne $f.sha256) {
        throw "Source changed: $($f.path)"
    }
    $d = Join-Path $target $f.path
    if (Test-Path $d) {
        $hash = (Get-FileHash $d -Algorithm SHA256).Hash.ToLower()
        if ($hash -ne $f.sha256 -and $hash -ne $f.before_sha256) {
            throw "Target conflict: $($f.path)"
        }
    }
}
```

이는 확인 명령이며 기존 파일을 덮어쓰지 않는다. 업데이트는 기존 파일이 기록된
`before_sha256`과 일치할 때만 별도 백업/백업 SHA 확인 후 수행한다. 동일 SHA는
유지하고 신규 파일은 CreateNew로 생성한다. 다른 사용자 변경은 중단/보고한다.
복사 후 파일마다 Source/Target SHA를 다시 비교한다. 검증용 신규 디렉터리와
운영/사용자 사건 저장소를 혼용하지 않는다.

## 실제 검증 환경 명령

```powershell
conda activate soc-windows
Set-Location C:\soc-agent-final-native-20261013
$env:RUN_LIVE_LLM_TESTS = '0'
$env:PYTHONPATH = "$PWD\src"
$env:SOC_EXTERNAL_ARTIFACT_ROOT = Join-Path $env:LOCALAPPDATA 'AutonomousSOCFinalArtifacts20261013'
$env:SOC_EXTERNAL_INFERENCE_PYTHON = 'C:\soc-native-inference-final-20261013\Scripts\python.exe'

python -m pytest -q --tb=short -rs -rfE `
  tests/integration/external_runtime `
  tests/unit/persistence/test_native_windows_storage.py `
  tests/integration/demo/test_decision_pipeline_equivalence.py
python -m ruff check src tests
python -m ruff format --check .
```

별도 Native venv는 기존 soc-windows 패키지를 변경하지 않고 생성했다. 공식 모델
패키지 0.1.0은 기존 환경의 것을 재사용했다. 추가 Backend는 LightGBM 4.7.0,
Torch 2.14.1, LiteRT 2.3.0, pandas 3.0.6이다. 설치/백엔드 확인은 별도 환경에서
수행하며 그 환경에도 Source PYTHONPATH를 명시한다. 무단 의존성 업그레이드나
OS 권한 상승이 필요하지 않았다.

## Desktop 최초 실행/재시작

```powershell
$data = Join-Path $env:LOCALAPPDATA 'AutonomousSOCOperatorReviewSmoke'
# 새 전용 디렉터리를 사용한다. 기존 운영 DB는 지정하지 않는다.
python -m soc_agent.external_runtime `
  --directory $data `
  --input "$PWD\smoke-events.jsonl" `
  --external-features "$PWD\smoke-features.jsonl" `
  --artifacts $env:SOC_EXTERNAL_ARTIFACT_ROOT `
  --native-python $env:SOC_EXTERNAL_INFERENCE_PYTHON
```

같은 명령을 다시 실행하면 보존된 Context/Checkpoint를 재개한다. 모델을 다시
학습하거나 기존 Context를 바꾸지 않는다. CLI는 Synthetic feature 파일을 위한
수동/유한 재생이다. HTTP listener나 실제 Collector가 아니다.

C 루트의 WSL 생성 디렉터리는 ancestor write ACL 검사에서 거부될 수 있다.
이를 ACL 완화로 해결하지 않는다. 실제 Windows 보안 API로 생성한 LOCALAPPDATA
private 저장소/모델 복사본을 사용하고, AppData라는 경로명 자체를 보안 증명으로
대체하지 않는다. 런타임이 owner/DACL/reparse/sidecar를 실제 재검증한다.

## 아직 실행하지 않은 전체 Windows 회귀

집중 검증이 통과한 뒤 별도 실행한다. 이번 작업에서 최신 전체 Windows 회귀를
실행했다고 주장하지 않는다.

```powershell
python -m pytest -q --tb=short -rs -rfE *> windows-final-full.log
python -m ruff check src tests
python -m ruff format --check .
```

사용자 추가 요청인 Conda 26.7.1 base 업데이트는 WSL/Windows 중 대상 응답 대기다.
해당 업데이트와 SOC 모델/Runtime 검증 환경 변경을 혼동하지 않는다.
