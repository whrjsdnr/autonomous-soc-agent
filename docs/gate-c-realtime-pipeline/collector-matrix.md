# Collector matrix

| Environment/source | Implementation | Actual verification |
|---|---|---|
| Windows 11 System | native Get-WinEvent read-only API adapter through fixed PowerShell command | PASS: metadata-only CLI start/restart, DONE 1 -> 2 |
| Windows Application | same allowlisted API, no policy modification | NOT_TESTED |
| Windows Security | caller permission required, sanitized unavailable/permission failure | NOT_TESTED; no elevation or audit policy change |
| WSL Ubuntu journald | journalctl JSON selected System metadata, FIRST +N entries | PASS: metadata-only SERVER CLI start/restart, DONE 1 -> 2 |
| separate Linux Desktop | same collector/CLI implementation | NOT_TESTED |
| separate Linux Headless host | same collector/CLI implementation | NOT_TESTED |
| Windows Server | excluded by CLI profile validation | NOT_APPLICABLE |

Initial collection starts at the oldest readable retained record. Native commands are
fixed, no shell=True, bounded batch 1..256, timeout 15 seconds, serialized output <=4 MiB.
Windows channel/XPath/count are validated before process creation; no arbitrary command API.
Get-WinEvent projects only record identity/provider/channel/time before JSON serialization.
Journal output excludes MESSAGE. Access scope is only records readable by the current user;
it is not a claim of complete system/security-channel coverage.

Resume verifies the saved record still exists before reading after it. Journal vacuum / log
rotation or cleared/replaced Windows RecordID fails closed. No automatic cursor reset to
current time, audit-policy change, sudo request, registry write or file permission repair.
