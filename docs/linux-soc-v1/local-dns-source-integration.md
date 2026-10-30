# 로컬 DNS 공급원: dnsmasq 재사용 및 통합시험 준비

2026-10-30. `feat/one-command-runtime`. Source Freeze `c9bbb0d120eae5fcb333533f67f3f38e8285f30c`, Tree `3454516e5517d48aad7e295bc0f23b104baab76f`.
기존 Native 제한 시험과 53분28초 PARTIALLY_VERIFIED 기록은 보존한다.
이번에 실제 실행한 것은 일반 사용자 Host loopback1053의 DNS 응답 시험이다.
Root 인증·설치·Namespace 진입·TCX/AF_PACKET Capture·서비스 시작·Native 모델 추론·API 호출은 하지 않았다.

## 오픈소스 조사와 선택

| 후보 | 확인 근거 | 이번 적용 |
| --- | --- | --- |
| dnsmasq | [공식 문서](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html), [2.91 소스](https://raw.githubusercontent.com/imp/dnsmasq/v2.91/src/dnsmasq.c) | 이미 설치된 `/usr/sbin/dnsmasq`2.91을 재사용. UDP/TCP 서버를 새로 구현하지 않음 |
| CoreDNS | [bind 문서](https://github.com/coredns/coredns/blob/master/plugin/bind/README.md), [hosts plugin](https://coredns.io/plugins/hosts/) | 로컬 정적 응답이 가능하나 현재 binary 미설치. 이번 작은 시험에 새 배포·권한을 추가하지 않음 |
| dnslib | [프로젝트](https://github.com/paulc/dnslib) | 서버 framework를 제공하지만 현재 미설치·maintenance mode. 기존 설치 dnsmasq를 우선 |

dnsmasq는 `dnsmasq-base` 패키지의 Root 소유 실행파일이며 이 환경의 SHA256은
`c3104fc7512ca8c4cb4c759504b3c27365fb9987da55be544330c12d628cefe2`이다.
실제 binary의 version 출력에서 GPL version2 또는3을 확인했다. 소스를 복제/수정하지 않고
별도 프로세스로 실행한다. 새 Python 의존성이나 전역 패키지 설치는 없다.

설정은 `--conf-file=/dev/null --no-resolv --no-hosts --no-poll --bind-interfaces`,
고정 host-record `native-0516.localhost → 127.0.0.1`/TTL0, localhost local-zone,
cache0/pid-file 없음/질의 로그 비활성이다. upstream·DHCP·TFTP·DBus를 활성화하지 않는다.
기존 Host resolver·dnsmasq 서비스·`/etc/hosts`·`/etc/resolv.conf`를 바꾸지 않는다.
공식 `--test`는 서버를 시작하지 않고 문법만 검사한다. Target53/Host1053 두 설정 모두 통과했다.

## 운영 코드와 실제 로컬 시험

`continuous/dns_trial.py`는 dnsmasq의 고정 인자·서비스 후보와 제한된 Client를 제공한다.
DNS 서버의 응답/UDP/TCP 처리는 dnsmasq에 맡긴다. Client는 기존 QUESTION, TCP `_exact`,
Namespace 진입/credential drop/소유 자식 정리 코드를 재사용한다.
응답의 ID/NOERROR/Question/A record/TTL0/길이를 대조한다. 고정 Client만 추가했으며
임의 도메인·원격 서버·대체 포트·무한 retry는 지원하지 않는다.

사용자의 로컬 DNS 테스트 허용에 따라 **실제 `127.0.0.1:1053`에서 단1회** 검증했다.

| 항목 | 실제 결과 |
| --- | --- |
| 서버 | dnsmasq2.91, UID1000, Eff/Prm/Inh/Amb capability0 |
| Bounding capability | 일반 사용자 프로세스의 기존 bounding mask 유지. 전체 capability0으로 잘못 보고하지 않음 |
| 전송 | UDP2회/TCP1회, 세 응답 모두 NOERROR·고정 A record 일치 |
| 시간 | TCP Client close 후35초 이상 지나 마지막 UDP; 실제45.000152397초 관측 |
| 외부 영향 | 외부 연결0, resolver API0, Host DNS 설정 변경0 |
| 종료 | SIGTERM → dnsmasq exit0, UDP/TCP1053 잔류0, Cleanup VERIFIED |
| 증거 성격 | APPLICATION_PROTOCOL_ONLY_NOT_KERNEL_CAPTURE |

증거: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/final-live-preflight-20261029T235159Z/dnsmasq-local-test.json`.
이 결과는 Native raw DNS Capture 또는 DNS Transaction→Native GUI 실환경 성공이 아니다.
Application timestamp와 Socket Cookie를 Kernel Capture Attestation으로 승격하지 않는다.

## 전용 Namespace 통합 후보

새 요청서와 Root Manifest, 고정 파일6개, 실행 이미지·Session·모델·Runtime·Ledger Binding을
기존 one-command 검토 계약에 결합했다. **정책/승인 영수증·예약은 발급하지 않았다.**

- Namespace `net:[4026532232]`, lo/Ingress. 기존 Namespace 재생성·Host 설정 변경 없음.
- TCX 인증 READY → DNS 수집 Helper RUNNING → dnsmasq 서비스/Listener 확인 → 고정 DNS Client 시작.
- Server `127.0.0.53:53` UDP/TCP; Client `127.0.0.1`의 OS 배정 ephemeral port.
  query ID c201(UDP),c202(TCP),c203(UDP), UDP2/TCP1. Client TCP close 후35초,45초 관측.
- dnsmasq Server는 UID1000·**CAP_NET_BIND_SERVICE만**/NNP1,64MiB/CPU10%/tasks8/90초.
  이 제한 권한은 아직 활성화하지 않았으며 새 Scope 승인 필요. 일반 Client는 capability0으로 실행한다.
- 별도 Capture Helper는 UID1000 NET_RAW로 AF_PACKET을 열고 Eff/Prm/Inh/Amb0으로 내리며
  CapBnd NET_RAW/NNP1 유지. DNS 송신·서버·raw 수집 권한을 혼동하지 않는다.
- DNS Client 종료 후 dnsmasq를 정지. 기존 고정 TCP 공급원 최대38연결을 이어서 사용한다.
- Metadata→기존 DNSProducer→durable transcript→IsolatedDNS Transaction→Audit/GUI 연결.
  Queue32/Runtime256MiB/DNSmetadata8MiB, DNS9 INCOMPLETE/추론 차단.
- DNS Child는 비차단 poll로 관측하므로45초 대기 동안 Collector heartbeat 감시를 막지 않는다.
  모든 자식·서비스는 소유 자원만 Stop/Drain/정리한다. 자동 Root/Native 재실행 없음.

RF/LR은 **실제로 봉인된 ELIGIBLE job의 기존 exact Action 승인 이후** Worker가 자동 소비한다.
DNS가 첫 Window에 여러 Flow를 만들 수 있어 검토 도구의 기존 `job당 호출2개` 가정은
새 후보에서 `job당 ELIGIBLE 최대8/총20job/전체96추론` 제안으로 명시했다.
사용자가 이미 봉인된 작업을 직접 검토해야 하며 미래 입력 승인·자동 영수증 발급은 없다.
승인 없이 WAITING_EXACT_MODEL_ACTION_APPROVAL인 상태는 정상적인 차단이다.
Host Authentication 실수집/IF·실제 LLM API·DNS9·위험 대응은 이번 후보에서 제외한다.

시간은 기존 **전체3600초(시작·종료 포함)**,3500초까지 Stop 준비/3570초까지 Drain이다.
순수 Capture3600초가 필요하면 새 전체 시간·자원 계약이 필요하다. 이 후보를 순수1시간 수집으로
보고하거나 상한을 임의 연장하지 않는다.

## 검증과 보존

- Workspace 기존 Continuous/CLI/TCX 회귀216 PASS; OSS 변경 후 관련115 PASS 및 집중40 PASS.
- 최종 독립 Export210 PASS. 고정 Root coordinator 권한 경계 mock10 PASS.
- dnsmasq 실제 로컬 UDP/TCP 시험1회 PASS, 공식 syntax 검사2개 PASS.
- 보존 Native40/Prediction2/Incident1을 실제 Tk5화면에서 확인하고 종료·재연결 PASS.
  새 DNS 결과를 그 과거 Native 결과에 합치지 않았다.
- Native6개 이중 빌드 일치, 최종 Wheel 이중 빌드 일치. DNS 서버/Helper/App systemd 후보3개 문법 통과.
- Ruff check/format/diff 통과. Root mock 첫 회귀는 새 cleanup 순서를 이전 index0으로 가정해1 FAIL;
  App Stop 실패1개와 최초 오류 보존을 순서와 독립적으로 확인한 뒤10 PASS. 실패 로그도 보존.
- pytest의 임시 garbage directory 정리 warning49개가 있었으며 운영 오류나 승인 성공으로 해석하지 않음.
- Legacy Ledger81행 SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` 불변.
  Campaign Root12/Native4, Batch3 Root9/Native1 계측을 초기화/환급하지 않았다.
- 기존 설치 정책 SHA `401ecb1b5b8575916423f560d1befc7c16a30c91a5209284a48418c922e15f99` 불변.
  TCX/App/TCP 서비스 inactive/PID0. 새 Capture DNS Helper와 dnsmasq 서비스 미설치·inactive.
  기존 사용자 main 변경·Rollback·FAILED/UNKNOWN/false 증거 보존.

## 정확한 검토 자료와 다음 명령

검토서: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/final-live-preflight-20261029T235159Z/oss-final/native-dns-lifecycle-final-review/approval-package-final.md`.
Request SHA256 `0fb9f7094700452ae7a1c18b09aa66800f14c45df257b77bae43de368c698215`.
Root Manifest SHA256 `de01e056497ef1219687611f205817e4edd670bb941ad33ef591206df59ae4fc`.
Client image SHA256 `4251169e9c21a77ac703ff7c15b1500362e15aaab949274a430afaa4cab86c6d`.
Wheel SHA256 `64d71e117d53a9f1b7b1d25a2b498562ccb59f815de80fdd526e54615449194b`.
Source digest `f48edf07103a9e57a54e463bb528a09368dd66f88ab93c166174c0861221ad04`.
Session `a37e4b65-35b6-445a-8376-1718bee87803`, Release0.6.3.
유효기간 상한 `2026-10-30T08:36:32.192496+00:00` (2026-10-30 17:36:32 KST).
사용자에게 SHA를 입력하도록 요구하지 않는다. 만료/Binding 변경이면 다시 검증해야 한다.
Root 입장 시 기존 계약상 만료까지65분 이상 남아 있어야 하므로 만료 직전에는 시작할 수 없다.

승인 후의 시작 명령(이번 작업에서 실행하지 않음):

```bash
bash /home/geonug/kdt-linux/autonomous-soc-agent/.git/final-live-preflight-20261029T235159Z/oss-final/start-integrated.sh
```

이 명령은 기존 `soc-agent start --home .../profile --gui`를 사용한다. Scope/R1을 표시하고
TTY yes·직접 sudo 후에만 Root 경로를 실행한다. Host의 doctor/preview는 PASS와
Target 내부 check 필요 BLOCKED를 구분한다. 실제 내부 check를 Host 결과로 대체하지 않는다.
모델 Action 도구는 같은 review의 `execution/approve-sealed-models.sh`이며 이미 봉인된 입력만
검토한다. `status/stop/gui/doctor --home /home/geonug/kdt-linux/autonomous-soc-agent/.git/final-live-preflight-20261029T235159Z/oss-final/profile`도 기존 CLI를 그대로 사용한다.

최종 판정: **LOCAL_DNS_SOURCE_PROTOCOL_VERIFIED / 통합 Live 시험 승인·인증 대기**.
기존 전체 운영 판정 PARTIALLY_VERIFIED를 유지한다. OPERATIONS_VERIFIED 선언 없음.

## 2026-10-30 승인 전 메타데이터 정정

위 최초 요청서0fb9f709…의 미승인 모델 상한38/96 혼재를 바로잡았다.
최신 통합 검토 자료는 `/home/geonug/kdt-linux/autonomous-soc-agent/.git/packet-dns-final-review-20261030T001504Z/approval-review.md`다.
최신 Request SHA256 `497f0dad6a0192e178734ec5a7221afc65d8c8b379148e9fd6d0e17ba7ce46c9`,
Root Manifest `a3b3279ef431065aad5880765c9cd3dc411dc55f35b5e4e537e11cdd9efa3f56`, Session `9030e7b9-76d9-4e95-aa4f-7568878bc5bd`.
원본 미승인 자료·빈 Store·Audit는 별도 보존했다. Source/Wheel/Collector 변경은 없다.
운영 보고서의 마지막 절을 기준으로 하며 기존 SHA를 수정본 승인에 사용하지 않는다.
