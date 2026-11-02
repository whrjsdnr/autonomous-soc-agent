"""Exact historical source bytes, never executable fixtures or current authority."""

import hashlib


def historical_source(root, name, expected):
    current = root / name
    if current.is_file() and hashlib.sha256(current.read_bytes()).hexdigest() == expected:
        return current
    archive = root / "tests/fixtures/dns-heartbeat-source-history" / (expected + ".txt")
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected, name
    return archive


def historical_bundle(root, files):
    prefix = "src/soc_agent/security_ai/operational/network_capture/"
    return {
        name: hashlib.sha256(historical_source(root, prefix + name, sha).read_bytes()).hexdigest()
        for name, sha in files.items()
    }
