"""Same authenticated bounded reader; DNS metadata is allowed only in Total mode."""

from soc_agent.security_ai.operational.network_capture.capture import CaptureUnavailable
from soc_agent.security_ai.operational.network_capture.stream_transport import StreamingCapture
from soc_agent.security_ai.operational.network_capture.total_session import MODULE


class TotalCapture(StreamingCapture):
    helper_module = MODULE

    def _receive_record(self, message):
        original = message.packet
        if original is not None and original.dns is not None:
            if message.kind != "PACKET" or original.dns.query_name is not None:
                raise CaptureUnavailable("TOTAL_DNS_NAME_RETENTION_DENIED")
            message = message.model_copy(
                update={"packet": original.model_copy(update={"dns": None})}
            )
        packet = super()._receive_record(message)
        return original if packet is not None else None
