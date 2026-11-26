"""Deterministic extraction of remediation targets from sshd logs.

Targets are never taken from the language model. Because attackers control the
SSH username, the pattern is anchored to the end of each line: a fake
"from <ip> port <n>" inside a username cannot replace the address sshd appended.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass

FAILED_LOGIN = re.compile(
    r"^(?:[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+) "
    r"\S+ sshd(?:-session)?\[(?P<pid>\d{1,7})\]: "
    r"Failed password for .* from (?P<ip>[0-9A-Fa-f:.]+) port \d{1,5} ssh2$"
)
MIN_FAILURES = 5


@dataclass(frozen=True)
class Targets:
    """Targets derived from the log by code."""

    source_ip: str | None = None
    process_id: int | None = None
    failed_attempts: int = 0


def extract_targets(log_text: str, min_failures: int = MIN_FAILURES) -> Targets:
    """Find the dominant source of failed SSH logins.

    Args:
        log_text: sshd lines with traditional or ISO 8601 syslog timestamps.
        min_failures: Minimum failures before an address becomes a target.

    Returns:
        The dominant address and its most recent sshd PID, or empty targets if
        no address meets the threshold or the leading addresses are tied.
    """
    counts: Counter[str] = Counter()
    last_pid: dict[str, int] = {}
    for line in log_text.split("\n"):
        match = FAILED_LOGIN.match(line.rstrip("\r"))
        if match is None:
            continue
        try:
            ip = str(ipaddress.ip_address(match["ip"]))
        except ValueError:
            continue
        counts[ip] += 1
        last_pid[ip] = int(match["pid"])

    ranked = counts.most_common(2)
    if not ranked or ranked[0][1] < min_failures:
        return Targets()
    if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
        return Targets()
    ip, attempts = ranked[0]
    return Targets(source_ip=ip, process_id=last_pid[ip], failed_attempts=attempts)
