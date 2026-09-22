"""Model signal interpretation only. This is unrelated to execution PolicyEngine."""

from itertools import combinations

from soc_agent.security_ai.fusion.enums import AgreementState
from soc_agent.security_ai.fusion.models import FusionContribution

# Explicit supported attribution vocabulary; these are not severity or action rules.
CLASS_DIRECTIONS = (("BENIGN", False), ("BruteForce", True), ("DoS", True), ("PortScan", True))


def group_agreement(
    contributions: tuple[FusionContribution, ...],
) -> tuple[AgreementState, tuple[str, ...]]:
    states = []
    rules = []
    for left, right in combinations(contributions, 2):
        if left.model_kind == right.model_kind:
            if left.decision != right.decision:
                states.append(AgreementState.CONFLICTING)
                rules.append("same-task-same-input-categorical-conflict:v1")
            # Same-task repeated versions are not independent corroboration.
            continue
        kinds = {left.model_kind, right.model_kind}
        if kinds != {"network_classifier", "network_anomaly"}:
            continue
        classifier = left if left.model_kind == "network_classifier" else right
        anomaly = right if left.model_kind == "network_classifier" else left
        direction = dict(CLASS_DIRECTIONS)[classifier.decision]
        agrees = direction == (anomaly.decision == "anomaly")
        states.append(AgreementState.CONSISTENT if agrees else AgreementState.PARTIAL)
        rules.append("network-attribution-vs-baseline-deviation:v1")
    for state in (AgreementState.CONFLICTING, AgreementState.PARTIAL, AgreementState.CONSISTENT):
        if state in states:
            return state, tuple(sorted(set(rules)))
    return AgreementState.INSUFFICIENT, ()


def overall_agreement(groups: tuple[AgreementState, ...]) -> AgreementState:
    if AgreementState.CONFLICTING in groups:
        return AgreementState.CONFLICTING
    if len(groups) == 1:
        return groups[0]
    if any(s != AgreementState.INSUFFICIENT for s in groups):
        # There are separate source populations; never claim cross-group agreement.
        return AgreementState.PARTIAL
    return AgreementState.INSUFFICIENT


def network_relations(contributions: tuple[FusionContribution, ...]) -> tuple[str, ...]:
    relations = set()
    for classifier in contributions:
        if classifier.model_kind != "network_classifier":
            continue
        for anomaly in contributions:
            if anomaly.model_kind != "network_anomaly":
                continue
            pair = (dict(CLASS_DIRECTIONS)[classifier.decision], anomaly.decision == "anomaly")
            relations.add(
                {
                    (True, True): "attack_and_anomaly",
                    (False, True): "benign_with_anomaly",
                    (True, False): "attack_without_anomaly",
                    (False, False): "no_alert",
                }[pair]
            )
    return tuple(sorted(relations))
