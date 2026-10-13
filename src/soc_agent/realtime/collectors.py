"""Predefined read-only native commands; no message/EventData payload collection."""

import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from soc_agent.realtime.models import SourceIdentity, SourceMetadata, native_event


class CollectorUnavailable(ValueError):
    pass


class CursorUnavailable(CollectorUnavailable):
    pass


def bounded_command(args: list[str]) -> bytes:
    # Native commands have bounded record counts. Never print raw output on failure.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        try:
            result = subprocess.run(args, stdout=output, stderr=errors, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CollectorUnavailable("Read-only collector command unavailable") from error
        if result.returncode == 3:
            raise CollectorUnavailable("PERMISSION_DENIED: source is not readable by this user")
        if result.returncode or output.tell() > 4 * 1024 * 1024:
            raise CollectorUnavailable("Collector permission, cursor or output limit rejected")
        output.seek(0)
        return output.read()


class LinuxJournalCollector:
    identity = "linux:journal:v1"

    def __init__(self):
        self.command = shutil.which("journalctl")
        if (
            os.name != "posix"
            or self.command is None
            or not Path("/run/systemd/journal/socket").is_socket()
        ):
            raise CollectorUnavailable("UNSUPPORTED: journald unavailable")

    @staticmethod
    def parse(row):
        try:
            source = SourceIdentity(
                namespace="systemd-journal", generation=row["_MACHINE_ID"], record=row["__CURSOR"]
            )
            timestamp = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
                microseconds=int(row["__REALTIME_TIMESTAMP"])
            )
            return native_event(
                "linux",
                "journald:v1",
                source,
                SourceMetadata(
                    channel="journal",
                    provider=row.get("SYSLOG_IDENTIFIER", row.get("_COMM", "unknown")),
                    code=str(row.get("PRIORITY", "unknown")),
                    original_timestamp=str(row["__REALTIME_TIMESTAMP"]),
                ),
                timestamp,
            )
        except (KeyError, TypeError, ValueError, OverflowError) as error:
            raise CollectorUnavailable("Invalid journal record metadata") from error

    def poll(self, cursor=None, limit=16):
        if not 1 <= limit <= 256:
            raise ValueError("Collector batch limit invalid")
        base = [
            self.command,
            "--no-pager",
            "--quiet",
            "--output=json",
            "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,_MACHINE_ID,SYSLOG_IDENTIFIER,_COMM,PRIORITY",
        ]
        if cursor:
            # Detect vacuum/rotation loss rather than silently seek to a later timestamp.
            probe = bounded_command(base + ["--cursor=" + cursor.source.record, "--lines=+1"])
            rows = probe.splitlines()
            if not rows or self.parse(json.loads(rows[0])).source != cursor.source:
                raise CursorUnavailable("Journal cursor no longer retained")
            base += ["--after-cursor=" + cursor.source.record]
        # +N explicitly chooses FIRST N, avoiding tail-N data loss after a cursor.
        data = bounded_command(base + [f"--lines=+{limit}"])
        return [self.parse(json.loads(line)) for line in data.splitlines()]


class WindowsEventCollector:
    def __init__(self, channel="System"):
        if channel not in {"System", "Application", "Security"}:
            raise CollectorUnavailable("Unsupported Windows event channel")
        if os.name != "nt":
            raise CollectorUnavailable("UNSUPPORTED: Windows Event Log requires native Windows")
        self.channel = channel
        self.identity = "windows:eventlog:v1:" + channel

    @staticmethod
    def parse(data: bytes, channel: str):
        try:
            rows = json.loads(data.decode("utf-8-sig"))
            if not isinstance(rows, list) or len(rows) > 256:
                raise ValueError
            result = []
            for row in rows:
                if row["channel"] != channel:
                    raise ValueError
                result.append(
                    native_event(
                        "windows",
                        "eventlog:v1",
                        SourceIdentity(
                            namespace=channel, generation=row["computer"], record=row["record"]
                        ),
                        SourceMetadata(
                            channel=channel,
                            provider=row["provider"],
                            code=row["code"],
                            original_timestamp=row["time"],
                        ),
                        datetime.fromisoformat(row["time"].replace("Z", "+00:00")),
                    )
                )
            return result
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            raise CollectorUnavailable("Windows metadata response invalid") from error

    def query(self, query: str, limit: int):
        if self.channel not in {"System", "Application", "Security"}:
            raise CollectorUnavailable("Unsupported Windows event channel")
        if type(limit) is not int or not 1 <= limit <= 256:
            raise CollectorUnavailable("Invalid collector batch limit")
        if query != "*" and not re.fullmatch(
            r"\*\[System\[EventRecordID(?:=|>)[0-9]{1,20}\]\]", query
        ):
            raise CollectorUnavailable("Unsupported read-only event query")
        # Get-WinEvent is a read-only Event Log API adapter. Project only System metadata
        # before serialization; EventData/Message are never rendered to temporary files.
        command = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe",
        )
        script = (
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); "
            "$ErrorActionPreference='Stop'; try { $rows=@(Get-WinEvent "
            f"-LogName '{self.channel}' -FilterXPath '{query}' -Oldest -MaxEvents {limit} "
            "| ForEach-Object { @{record=[string]$_.RecordId; computer=$_.MachineName; "
            "channel=$_.LogName; provider=$_.ProviderName; code=[string]$_.Id; "
            "time=$_.TimeCreated.ToUniversalTime().ToString('o')} }); "
            "ConvertTo-Json -InputObject $rows -Compress } catch { "
            "if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { '[]' } "
            "elseif ($_.Exception.HResult -eq -2147024891) { exit 3 } "
            "else { exit 1 } }"
        )
        return self.parse(
            bounded_command([command, "-NoProfile", "-NonInteractive", "-Command", script]),
            self.channel,
        )

    def poll(self, cursor=None, limit=16):
        if not 1 <= limit <= 256:
            raise ValueError("Collector batch limit invalid")
        if cursor:
            record = cursor.source.record
            if not record.isdecimal() or len(record) > 20:
                raise CursorUnavailable("Invalid Windows cursor")
            probe = self.query(f"*[System[EventRecordID={record}]]", 1)
            if not probe or probe[0].source_digest != cursor.source_digest:
                raise CursorUnavailable("Windows log cleared, rotated or cursor replaced")
            return self.query(f"*[System[EventRecordID>{record}]]", limit)
        return self.query("*", limit)
