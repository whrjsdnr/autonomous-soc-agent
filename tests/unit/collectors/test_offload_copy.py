import struct

import pytest
from tests.unit.collectors.test_checksum_evidence import aux, packet

from soc_agent.security_ai.collectors.offload_copy import analysis_copy, checksum, memory_pcap


def ipv6(protocol, partial):
    l3 = packet(protocol)
    segment = bytearray(l3[20:])
    offset = 6 if protocol == 17 else 16
    segment[offset : offset + 2] = bytes(2)
    address = bytes(15) + b"\1"
    pseudo = address * 2 + struct.pack("!I3xB", len(segment), protocol)
    value = checksum(pseudo) ^ 65535 if partial else checksum(pseudo + segment)
    segment[offset : offset + 2] = struct.pack("!H", value)
    return (
        struct.pack("!IHBB16s16s", 6 << 28, len(segment), protocol, 64, address, address) + segment
    )


@pytest.mark.parametrize("version", [4, 6])
@pytest.mark.parametrize("protocol", [6, 17])
@pytest.mark.parametrize("partial", [False, True])
def test_only_confirmed_partial_copies_are_rewritten(version, protocol, partial):
    original = packet(protocol, partial) if version == 4 else ipv6(protocol, partial)
    saved = original[:]
    result = analysis_copy(original, aux(original, 9 if partial else 1))
    assert result.status == ("CHECKSUM_PARTIAL_CONFIRMED" if partial else "CHECKSUM_VALID")
    assert result.packet is not None and original == saved
    changed = [i for i, (a, b) in enumerate(zip(original, result.packet, strict=True)) if a != b]
    offset = (20 if version == 4 else 40) + (6 if protocol == 17 else 16)
    assert set(changed) <= {offset, offset + 1}
    assert bool(changed) is partial
    verified = analysis_copy(result.packet, aux(result.packet))
    assert verified.status == "CHECKSUM_VALID"
    assert "packet" not in result.receipt()
    assert result.receipt()["transformed"] is partial


@pytest.mark.parametrize("protocol", [6, 17])
def test_completed_corruption_cannot_be_repaired_even_with_valid_kernel_bit(protocol):
    body = bytearray(packet(protocol))
    body[-1] ^= 1
    for status in (1, 129):
        result = analysis_copy(bytes(body), aux(body, status))
        assert result.status == "CHECKSUM_INVALID" and result.packet is None


def test_missing_aux_partial_wrong_seed_and_fragment_do_not_get_promoted():
    body = packet(partial=True)
    assert analysis_copy(body, None).status == "CHECKSUM_UNKNOWN"
    assert analysis_copy(body, aux(body[:30])).packet is None
    assert analysis_copy(body, aux(body, 265)).packet is None
    assert analysis_copy(body, aux(body, 137)).packet is None
    bad = bytearray(body)
    bad[26] ^= 1
    assert analysis_copy(bytes(bad), aux(bad, 9)).reason == "PARTIAL_SEED_MISMATCH"
    bad = bytearray(body)
    bad[6:8] = b"\x20\0"
    bad[10:12] = bytes(2)
    bad[10:12] = struct.pack("!H", checksum(bad[:20]))
    assert analysis_copy(bytes(bad), aux(bad, 9)).reason == "FRAGMENT"
    bad = bytearray(ipv6(17, True))
    bad[6] = 44
    assert analysis_copy(bytes(bad), aux(bad, 9)).packet is None


def test_memory_input_is_bounded_and_contains_original_timestamps():
    body = packet()
    data = memory_pcap([(1_234_567_890, body)])
    assert data[:4] == b"\x4d\x3c\xb2\xa1"
    assert struct.unpack_from("<IIII", data, 24) == (1, 234567890, len(body), len(body))
    with pytest.raises(ValueError, match="QUEUE32"):
        memory_pcap([(0, body)] * 33)


def test_pcap_public_input_rejects_more_than_queue32_and_truncation():
    from soc_agent.security_ai.collectors.offload_copy import validate_memory_pcap

    body = memory_pcap([(0, packet())])
    assert validate_memory_pcap(body) == 1
    with pytest.raises(ValueError, match="RECORD_BOUND"):
        validate_memory_pcap(body[:24] + body[24:] * 33)
    with pytest.raises(ValueError, match="TRUNCATED"):
        validate_memory_pcap(body[:-1])


def test_partial_payload_is_never_claimed_completed_integrity():
    body = bytearray(packet(partial=True))
    body[-1] ^= 1
    # A partial checksum cannot independently attest payload authenticity. Keep
    # the separate provenance state rather than silently relabeling as VALID.
    result = analysis_copy(bytes(body), aux(body, 9))
    assert result.status == "CHECKSUM_PARTIAL_CONFIRMED"
    assert result.receipt()["status"] != "CHECKSUM_VALID"
