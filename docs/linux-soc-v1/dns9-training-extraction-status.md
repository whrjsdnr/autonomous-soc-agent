# DNS9 학습·추출 계약 검토

판정: **INCOMPLETE / Raw DNS 모델 추론 BLOCKED**.
이번 변경은 학습 자료의 해시 검증과 누락 계약의 운영 진단을 추가한다.
DNS 수집 승인이나 기존 TFLite 모델의 운영 승인을 발급하지 않는다.

`security_ai/dns9_training_contract.json`은 실제 Feature Contract, Artifact Manifest,
두 학습·EDA Notebook의 파일 SHA를 기록한다. `dns9_contract.inspect_training(ml_root)`는
기존 DNS catalogue와 9개 특징 순서·Schema를 비교하고 해당 자료의 변경을 차단한다.
Raw DNS Transaction 결과와 `soc-agent doctor`에도 이 진단을 연결했다.

## 확인한 근거

기존 모델은 `cic-bell-dns-stateless9-v1`을 요구한다. 순서는
FQDN_count, subdomain_length, numeric, entropy, special, labels, labels_max,
labels_average, len이다. TFLite SHA는
`28e089af363dd565a4fb3d3f202de9e9f9804bd14a164de4fd7b61adb1201e33`이다.

원본 [UNB CIC-Bell-DNS-EXF-2021 특징 설명](https://www.unb.ca/cic/datasets/dns-exf-2021.html)은
FQDN·subdomain의 문자 수, 숫자 개수, query-name 문자 분포의 base-2 entropy,
특수문자 개수, label 수·최대·평균 길이를 설명한다. 특히 numeric은 비율이 아닌
개수로 설명되어 있다. 이는 기존 실험 DNS7의 numeric ratio와 다른 계약이다.

다만 이 설명만으로 원본 구현의 대소문자, trailing dot, IDNA/Unicode, 공백,
특수문자 집합, public suffix·subdomain 경계를 정확히 재현했다고 할 수 없다.
기존 Notebook은 이미 추출된 CSV의 9개 열을 선택한다. 현재 배포 DNN의 학습·Scaler
fit·INT8 export를 해당 Notebook에 연결하는 증거와 raw query→9개 값의 독립 golden pair는
확보되지 않았다. 기존 2개 precomputed fixture는 raw DNS golden pair가 아니다.

## 추론을 열기 위한 필수 자료

1. 원본 특징 추출 코드·버전·설정과 canonicalization 규칙.
2. Raw PCAP/query와 원래 9개 열을 연결하는 독립 golden pair 및 비교 결과.
3. Training split, 정확한 feature order/dtype, Scaler fit 결과와 모델 Export 연결.
4. 배포 INT8 tensor quantization, class mapping, threshold의 검증 근거.
5. 별도의 모델 Action 및 실제 DNS 수집 Scope 승인.

이 자료 없이 DNS7이나 임의 lexical9를 기존 DNS9 모델에 입력하지 않는다.
공식 특징 설명은 검토 자료로 보존했지만 이를 근거로 원래 ML package의 UNVERIFIED를
VERIFIED로 바꾸지 않았다. 새 contract 파일도 INCOMPLETE만 표현하며 권한을 부여하지 않는다.

## 수집과 추론의 구분

UDP/TCP raw DNS→Transaction→Provenance 처리는 기존 경로를 재사용한다.
현재 1시간 시험은 DNS 생성·외부망 접근이 금지된 TCP 전용 Scope였다.
Continuous TCX ABI는 헤더 metadata를 전달하며 DNS wire payload를 포함하지 않는다.
따라서 GUI에 DNS transaction이 없다는 사실을 DNS9 모델 실행 실패로 표시하지 않는다.
다음 실제 통합 시험은 기존 DNS Worker/Sidecar의 설치·진입·트래픽·Deadline·Cleanup 계약과
Continuous 전달 경로를 별도로 검증해야 한다. 이번 작업에서 이를 Live 활성화하지 않았다.
