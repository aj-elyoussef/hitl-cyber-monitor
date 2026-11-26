"""Safe, offline fixtures for ``--simulate``.

The IP address comes from the TEST-NET-3 range (203.0.113.0/24), which is
reserved for documentation.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

_ATTEMPTS = (
    ("02:14:01", 4121, "root", 50122),
    ("02:14:03", 4123, "invalid user admin", 50130),
    ("02:14:04", 4125, "invalid user oracle", 50138),
    ("02:14:06", 4127, "root", 50146),
    ("02:14:07", 4129, "invalid user test", 50154),
    ("02:14:09", 4131, "invalid user postgres", 50162),
    ("02:14:10", 4133, "root", 50170),
    ("02:14:12", 4135, "invalid user ubuntu", 50178),
)

MOCK_BRUTE_FORCE_LOG = "\n".join(
    f"Nov 27 {when} web-01 sshd[{pid}]: Failed password for {user} "
    f"from 203.0.113.45 port {port} ssh2"
    for when, pid, user, port in _ATTEMPTS
)

CANNED_RESPONSE = {
    "threat_summary": (
        "Eight failed SSH logins in about 11 seconds from 203.0.113.45, cycling "
        "through root and common service account names. This is consistent with "
        "an automated brute-force attack. No successful login appears in the sample."
    ),
    "severity": "High",
    "recommended_action_id": "block_source_ip",
    "confirmation_question": "Do you want to block the source of these SSH attempts?",
}


class _SimulatedMessages:
    def create(self, **_: Any) -> SimpleNamespace:
        block = SimpleNamespace(type="text", text=json.dumps(CANNED_RESPONSE))
        return SimpleNamespace(stop_reason="end_turn", content=[block])


class SimulatedAnthropicClient:
    """Offline client returning a canned reply through the real validation path."""

    def __init__(self) -> None:
        self.messages = _SimulatedMessages()
