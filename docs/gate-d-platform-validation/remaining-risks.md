# 남은 위험 / 미검증

- 별도 Linux Desktop/Headless 운영 호스트 없음: 전체 GATE_D_PASS 불가.
- 테스트 transport/identity는 production server/TLS/authentication 배포가 아니다.
- heavy Native env는 기존 것을 재사용; transitive dependency의 clean install 전체 재현성 미검증.
- 최신 전체 Windows regression은 Gate D에서 재실행하지 않았다.
- 새 외부 모델의 두 플랫폼 native probability/최종 Decision equivalence는 별도 comparator 필요.
- 실제 source extraction / 실시간 collector / production detection efficacy 미검증.
  DNS scaler pairing efficacy의 기존 UNVERIFIED 제한도 유지한다.
- GUI/installer/PyInstaller/service daemon은 구현되어 있지 않다.
- stale lock 및 ambiguous READ는 operator 확인/reconciliation 필요; 자동 삭제/자동 replay 없음.
- v16 fresh runtime opt-in만 사용; 운영 v14/v15 automatic migration 없음.
- trusted Python/adapters/native libs/SQL은 TCB; hostile-code/OS sandbox를 주장하지 않는다.
- Linux core install에는 XGBoost transitive NCCL 다운로드가 필요할 수 있다.
- package version0.1.0 재사용 때문에 배포 파일 선택 시 tag와 SHA를 반드시 함께 검증한다.

Gate E는 운영 준비 PASS를 전제로 자동 진행하지 않는다. 통제된 개발/설계의 조건부
착수 여부는 사용자 결정이다. 먼저 독립 Linux 호스트와 운영 service/auth/failure-recovery,
heavy dependency install evidence를 보완하면 Gate D 전체 판정을 재검토할 수 있다.
