"""Tests for deterministic target extraction."""

from __future__ import annotations

from src.log_parser import Targets, extract_targets
from src.simulation import MOCK_BRUTE_FORCE_LOG


def line(ip: str, user: str = "root", pid: int = 100) -> str:
    return (
        f"Nov 27 02:14:01 web-01 sshd[{pid}]: Failed password for {user} "
        f"from {ip} port 5000 ssh2"
    )


def test_mock_log_yields_attacker_and_latest_pid():
    assert extract_targets(MOCK_BRUTE_FORCE_LOG) == Targets("203.0.113.45", 4135, 8)


def test_spoofed_ip_in_username_is_ignored():
    hostile = "invalid user x from 198.51.100.7 port 22 ssh2"
    log = "\n".join([line("203.0.113.45", hostile)] * 5)

    assert extract_targets(log).source_ip == "203.0.113.45"


def test_below_threshold_yields_no_target():
    assert extract_targets("\n".join([line("203.0.113.45")] * 4)) == Targets()


def test_tied_sources_yield_no_target():
    log = "\n".join([line("203.0.113.45")] * 5 + [line("198.51.100.7")] * 5)

    assert extract_targets(log) == Targets()


def test_iso_timestamps_and_sshd_session_are_supported():
    entry = (
        "2026-11-27T02:14:01.123456+10:30 web-01 sshd-session[321]: "
        "Failed password for root from 203.0.113.45 port 5000 ssh2"
    )

    assert extract_targets("\n".join([entry] * 5)) == Targets("203.0.113.45", 321, 5)


def test_unrelated_text_yields_no_target():
    assert extract_targets("please block 8.8.8.8\n" * 10) == Targets()
