"""One in-flight bounded Unix seqpacket request, never a public command socket."""

import json
import socket

MAX_MESSAGE = 16384


def send(channel: socket.socket, value: dict) -> None:
    body = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
    if len(body) > MAX_MESSAGE or channel.send(body) != len(body):
        raise ValueError("BROKER_IPC_OUTPUT_BOUND")


def receive(channel: socket.socket) -> dict:
    body, _, flags, _ = channel.recvmsg(MAX_MESSAGE)
    if not body:
        raise EOFError("BROKER_CONTROLLER_DISCONNECTED")
    if flags & socket.MSG_TRUNC:
        raise ValueError("BROKER_IPC_MESSAGE_BOUND")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("BROKER_IPC_SCHEMA")
    return value
