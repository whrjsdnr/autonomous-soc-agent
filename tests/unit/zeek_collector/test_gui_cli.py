from unittest.mock import Mock

from tests.zeek_collector_support import pcap_fixture

from soc_agent import cli
from soc_agent.gui.visual_metrics import VisualHistory


def test_offline_cli_handoff_never_authenticates(monkeypatch, tmp_path):
    from soc_agent.gui import __main__ as gui
    from soc_agent.security_ai.collectors.offline import OfflineZeek

    pcap = tmp_path / "approved.pcap"
    sha = pcap_fixture(pcap)
    auth = Mock(side_effect=AssertionError("No auth for offline file"))
    launch = Mock(return_value=0)
    monkeypatch.setattr(cli, "terminal_authenticate", auth)
    monkeypatch.setattr(OfflineZeek, "environment", lambda self: {})
    monkeypatch.setattr(gui, "main", launch)
    assert (
        cli.main(
            [
                "start",
                "--gui",
                "--monitor",
                "total",
                "--collector",
                "zeek-offline",
                "--pcap",
                str(pcap),
                "--pcap-sha256",
                sha,
            ]
        )
        == 0
    )
    args = launch.call_args.args[0]
    assert args[args.index("--collector") + 1] == "zeek-offline"
    assert args[args.index("--zeek-pcap-sha256") + 1] == sha
    auth.assert_not_called()


def test_offline_history_is_distinct_from_live_packet_rate():
    h = VisualHistory()
    for i in range(2):
        s = dict(
            state="OFFLINE_PROCESSING",
            session_id="fixture",
            input_origin="SYNTHETIC_ZEEK_JSON",
            collection_live=False,
            collector={"type": "zeek"},
            network={"collector_network_events": i * 5, "collector_dns_events": i * 2},
        )
        assert h.observe(s, at=i + 1)
    assert h.samples[-1].values["zeek_network"] == 5 and h.samples[-1].values["zeek_dns"] == 2
    assert h.samples[-1].values["raw"] is None
    assert not h.observe({**s, "state": "STOPPED"}, at=3)
    assert not h.observe(
        {**s, "state": "OFFLINE_PROCESSING", "input_origin": "NATIVE_AF_PACKET"}, at=4
    )
    assert not h.samples
