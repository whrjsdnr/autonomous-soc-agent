# 심층 기술 Q&A — 49문항

답변은현재조사Scope에한정한다. 일반원리의공식정의는E19, 프로젝트사실은해당E번호의코드·실험을우선한다. 설명용추론을새실험결과로해석하지않는다.

## Q01. IDS와SOC의차이는?

IDS는탐지신호를생성하는구성요소이고SOC는그신호를조사·판단·감사·대응하는운영기능이다. 본프로젝트는탐지후조사단절을대상으로한다. 실제조직의업무절감률은측정하지않았다.

근거: [E01/E08](Evidence_Index.md).

## Q02. Signature와AnomalyDetection의차이는?

전자는명시된패턴일치,후자는기준분포에서의차이다. 이상은침해확정이아니므로IF/RF결과도provenance를가진advisory로관리한다.

근거: [E04/E07](Evidence_Index.md).

## Q03. Zero-day탐지라고할수있나?

독립미관측공격protocol이없으므로일반적인zero-day능력을입증하지못했다. session분리연구와knownlabeltest만으로그주장을하지않는다.

근거: [E04](Evidence_Index.md).

## Q04. RF가LR보다항상좋은가?

아니다.RF는비선형상호작용에유리하지만본Test에서FPR15.19%다.LR은더작고빠르지만FNR27.25%다.각품질/edge목적의trade-off를보여준다.

근거: [E04](Evidence_Index.md).

## Q05. RF128/depth12를왜썼나?

고정candidate구성과validation선정규칙의실제결과다.무한hyperparameter탐색이나test기반재조정을수행했다는근거는없다.

근거: [E04](Evidence_Index.md).

## Q06. LR scaling이왜필요한가?

단위/규모가다른입력에서규제와최적화의영향을일관되게하기위해train-onlyStandardScalerpipeline을사용했다.runtimefit은금지한다.

근거: [E04](Evidence_Index.md).

## Q07. IsolationForest는어떻게이상을찾나?

무작위분할에서짧은경로로고립되는표본의상대적이상성을이용한다.계정300초5feature에적용하는코드가있지만실제HostIF성공은미검증이다.

근거: [E07](Evidence_Index.md).

## Q08. IFcontaminationauto와0.95는같은가?

아니다.sklearnoffset/score와별도empiricalreference/decisionthreshold의의미를구분한다.0.95를공격확률95%라고설명하면안된다.

근거: [E07](Evidence_Index.md).

## Q09. 실제DNN구조는?

Top40은40→128(BN/ReLU/Dropout.2)→128(BN/ReLU/Dropout.2)→64(ReLU)→15logits다.inference에서softmax한다.DNSINT8은별도9→64→32→16→1이다.

근거: [E05/E06](Evidence_Index.md).

## Q10. CNN/LSTM/Autoencoder도사용했나?

조사한committednotebook/currentruntime에서실제학습·배포근거를확인하지못했다.다른미공유파일까지없다고증명한것은아니다.

근거: [E05](Evidence_Index.md).

## Q11. DNNloss와optimizer는?

Top40notebook은CrossEntropyLoss(reductionnone),AdamWlr1e-3/weightdecay1e-4다.공급DNSDNN의학습loss/optimizer는UNKNOWN이다.

근거: [E05/E06](Evidence_Index.md).

## Q12. DNNaccuracy가높은데왜macroF1은낮나?

큰클래스가전체accuracy를지배할수있다.fullvalidationaccuracy.9842에비해macroF1.6986이므로소수클래스실패를숨기지않는다.

근거: [E05](Evidence_Index.md).

## Q13. INT8이면무조건유리한가?

크기/연산량이줄수있지만runtime지원·quantization오차·saturation·minority성능을검증해야한다.TorchAO실험을Nativeprofile로자동등록하지않았다.

근거: [E05/E06](Evidence_Index.md).

## Q14. FeatureSelection은어떻게했나?

CIC78→Top40연구와실시간14고정계약을구분한다.14는모델rank상위14라는뜻이아니다.Top40projection의label충돌도보고한다.

근거: [E03/E05](Evidence_Index.md).

## Q15. 클래스불균형처리는?

Network14는trainbalancedclassweight이고SMOTE가없다.CICV3unique/V4frequency-aware는별도samplingprotocol이므로혼합해서설명하지않는다.

근거: [E04/E05](Evidence_Index.md).

## Q16. 데이터누수가없다고확정했나?

source/session/reference중복검사는있지만sharedfeaturevector/endpoint가있고device/campaign독립은미검증이다.validation시간역전과test사전관찰도공개했다.

근거: [E04](Evidence_Index.md).

## Q17. PrecisionRecall중무엇이중요한가?

오탐조사비용과미탐위험의trade-off다.단일정답이없고본quality/edge선정규칙과base-rate를함께설명해야한다.

근거: [E04](Evidence_Index.md).

## Q18. AP와PR-AUC는같은가?

본연구의PR요약은averageprecision이며trapezoidalinterpolation과같다고가정하지않는다.수치정의와사용함수를함께기록했다.

근거: [E04/E19](Evidence_Index.md).

## Q19. ROC-AUC만높으면운영가능한가?

아니다.threshold별FP/FN·calibration·base-rate·입력parity·resource/권한/cleanup이필요하다.모델score는집행권한이아니다.

근거: [E04/E15](Evidence_Index.md).

## Q20. InferenceLatency는어디부터재나?

연구single-rowbenchmark,packagepreprocess/load/lock포함latency,수집부터GUI까지E2E는측정경계가다르다.실제모델미실행이면latency는없는것이정확하다.

근거: [E04/E05/E15](Evidence_Index.md).

## Q21. eBPF와TCX는무엇을하나?

Kernel에서제한된프로그램을검증후hook에연결해관측한다.본프로젝트는승인된loIngressmetadata수집이며Host전체보호를검증한것은아니다.

근거: [E11/E19](Evidence_Index.md).

## Q22. BTF가왜필요했나?

해당Object의BTF기반maps선언에필요했는데-g0로없어졌다.BTF보존/parse후에도실제Kernelverifier/attach는별도검증해야했다.

근거: [E11](Evidence_Index.md).

## Q23. Kernelns를UTC로바꿔도되나?

clockepoch/namespace증거없이바꾸면시간상관관계가거짓이될수있다.NativeWindows는monotonicdomain을유지하고correlation도clockidentity를요구한다.

근거: [E02/E08](Evidence_Index.md).

## Q24. Queue가왜persistent여야하나?

수집과AI처리속도차이를완충하고crash후retainedwork를보존하기위해서다.무한용량이나외부호출exactly-once를의미하지않는다.

근거: [E02/E08](Evidence_Index.md).

## Q25. Backpressure와Drop은같은가?

backpressure는소비속도차이를제어하는상태이고drop은실제버림계수다.본boundedQueue의high-water/reject/drop/sourcegap을독립적으로기록한다.

근거: [E02/E16](Evidence_Index.md).

## Q26. WindowSeal은모델봉인인가?

아니다.실제입력수집구간과counter/epoch증거를고정한다.Flow완결성·modelAction은다른계약이다.

근거: [E03/E15](Evidence_Index.md).

## Q27. STOP이면Flow도완료되는가?

아니다.SHUTDOWNfinalflow는INCOMPLETE일수있고diagnosticseal은실패종료증거일뿐inference권한을만들지못한다.

근거: [E02/E03](Evidence_Index.md).

## Q28. CaptureQualityVERIFIED는어떤범위인가?

해당Window/소유hook/counter증거의범위다.모델정확도·전역무손실·전체Kernelcleanup·장기간무중단을포괄하지않는다.

근거: [E11/E12](Evidence_Index.md).

## Q29. DNS9계약이왜어려운가?

원본querycanonicalization/subdomain/specialcharacter정의·scalerfit/export연결이없다.이름과9차원형태만으로학습동등성을증명할수없다.

근거: [E06](Evidence_Index.md).

## Q30. Agent와Pipeline의차이는?

정해진계산경로를넘어추가근거와Tool순서를계획·평가하되상태·권한·횟수는결정론적으로통제한다.무제한자율성을의미하지않는다.

근거: [E01/E08](Evidence_Index.md).

## Q31. LLMStructuredOutput이안전성을보장하나?

shape/type검증일뿐진실성·권한을보장하지않는다.근거·Toolpermission·policy·humanboundary가추가로필요하다.

근거: [E08/E09](Evidence_Index.md).

## Q32. LLM이직접shell을실행하나?

아니다.임의shell문자열Tool이아니라predefined/read-only/schema검증Tool을사용한다.모델은Root/Native승인을발급할수없다.

근거: [E01/E08](Evidence_Index.md).

## Q33. 왜기존SOCRuntime을재사용했나?

claim/checkpoint/CAS/trace/policy에대한기존계약과검증을유지하고새조사engine의이중상태를피하기위해서다.

근거: [E08](Evidence_Index.md).

## Q34. Selector가모든Agent를선택하나?

아니다.기존SecurityAISelector/Fusion모듈은있지만Continuous후속조사는빈AIregistry로추가미승인모델호출을막는다.고정역할조율과구분한다.

근거: [E08/E09](Evidence_Index.md).

## Q35. Incident를어떻게연결하나?

동일target/scope/namespace/origin/clock/1분bucket등근거를요구한다.관련성이불명확하면merge하지않으며원래Incidentidentity를유지한다.

근거: [E08](Evidence_Index.md).

## Q36. EvidenceRevision은왜필요한가?

조사중새증거가오면기존계획이무엇을보고판단했는지보존해야한다.정렬된sourcepin으로새revision/task를만들고이전것을superseded로보존한다.

근거: [E08](Evidence_Index.md).

## Q37. 중복조사를어떻게막나?

taskidentity/sourcefingerprint/durableclaim/canonicalattemptinput/checkpoint를결합한다.외부call의결과불확실crash를무조건재실행하지않는다.

근거: [E08](Evidence_Index.md).

## Q38. Starvation은어떻게막나?

boundedpriority0–2와최대8개새작업overtaking제한을사용한다.AIpriority제안이deterministicfairness규칙을우회하지못한다.

근거: [E08](Evidence_Index.md).

## Q39. Known/UnknownError는어떻게다른가?

known은분류후기존승인된비파괴적revalidation/검증/실패escalation,unknown은evidencepackaging/read-only계획/평가다.커널·서비스자동변경은아니다.

근거: [E08](Evidence_Index.md).

## Q40. CheckpointResume가항상자동인가?

외부stepclaim전후를구분한다.이미LLM/Tool이실행됐을수있으면uncertainty/humanreview이며claim을훔쳐서자동중복호출하지않는다.

근거: [E08/E10](Evidence_Index.md).

## Q41. Heartbeat와DataProgress는왜분리했나?

긴SQLitewrite가생존게시를막는문제와살아있는process가업무를못하는문제는다르기때문이다.control생존과data정체를둘다계측한다.

근거: [E14/E16](Evidence_Index.md).

## Q42. Helper의최신원인은확정됐나?

4.181초송신공백과socketempty는확인됐지만어떤작업/스케줄링이원인인지는UNKNOWN이다.새stageelapsed진단도원인을자동확정하지않는다.

근거: [E12/E16](Evidence_Index.md).

## Q43. CPUquota를늘리면해결되는가?

그가설은시험이필요하고기존상한을임의완화할수없다.nr_throttled증가와throttled_usec동일snapshot으로직접인과를단정하지않았다.

근거: [E12](Evidence_Index.md).

## Q44. Cleanup은왜ExitCode만안보나?

소켓/FD/thread/PID/BPF소유자원이남을수있고ACK·durableaudit가없을수있다.영역별proof가필요하며최초오류도보존한다.

근거: [E10/E12](Evidence_Index.md).

## Q45. SHA와Ledger는무엇을보장하나?

검토대상identity와변경/소비/Replay를연결한다.SHA자체는공급자서명·신뢰·성공의증명이아니며namespace/ownership/policy/human승인이필요하다.

근거: [E04/E17](Evidence_Index.md).

## Q46. API비용이왜UNKNOWN인가?

Timeout후usage를못받으면원격처리와과금을확정못한다.사전예약상한과실제confirmedusage를분리하고무료라고표시하지않는다.

근거: [E10](Evidence_Index.md).

## Q47. 20분Replay성공이면Native도성공아닌가?

Replay는Kernel/rawsocket/cgroup/scheduling전체를검증하지않는다.실제wall1200초시험이지만Nativeevents0이므로VERIFIED_OFFLINE이다.

근거: [E14](Evidence_Index.md).

## Q48. GUI에빈값이있으면버그인가?

미수집·입력부적격·승인대기·실제실패를구분해야한다.없는모델latency를생성하지않되필수fullacceptance미충족은FAIL/PARTIAL로보고한다.

근거: [E12/E15](Evidence_Index.md).

## Q49. 실무적한계와차별성은?

차별성은Native입력계약부터조사claim/권한/audit/cleanup까지연결한것이다.한계는단일namespace/낮은traffic/장시간실패/학습분포이동/HostIF·DNS9·Assessment미완료다.

근거: [E04/E06/E07/E12](Evidence_Index.md).
