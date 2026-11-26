"""Safe, allowlisted remediation actions.

This module is the security boundary of the project. The language model may only
*name* an action. The code that runs, its parameters and the description shown to
the human approver are all defined here or derived from the log by trusted code.

Every action is deliberately a mock: it appends a record to a local JSON Lines
audit log (and, for process isolation, updates an in-memory registry). Nothing
touches a real firewall or a real process.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

# Addresses that must never be blocked: doing so could cut off the host itself or
# the internal network. Adjust this list to suit your environment.
PROTECTED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


class RemediationError(Exception):
    """Base class for remediation failures."""


class UnauthorizedActionError(RemediationError):
    """Raised when an action ID is not on the allowlist."""


class UnsafeTargetError(RemediationError):
    """Raised when an action has a missing, invalid or protected target."""


@dataclass
class RemediationContext:
    """Trusted inputs for a remediation action.

    Attributes:
        audit_log: JSON Lines file that receives one record per executed action.
        source_ip: Attacker address extracted from the log by deterministic code.
        process_id: Process ID extracted from the log by deterministic code.
        isolated_processes: In-memory registry of mock-isolated process IDs.
    """

    audit_log: Path
    source_ip: str | None = None
    process_id: int | None = None
    isolated_processes: set[int] = field(default_factory=set)


@dataclass(frozen=True)
class RemediationAction:
    """An allowlisted defensive action.

    Attributes:
        describe: Validates the target and returns a trusted, human-readable
            description of exactly what ``run`` will do.
        run: Performs the (mock) action and returns a result message.
    """

    describe: Callable[[RemediationContext], str]
    run: Callable[[RemediationContext], str]


def validate_block_target(source_ip: str | None) -> str:
    """Validate an IP address before it is used in a block rule.

    Args:
        source_ip: Candidate address.

    Returns:
        The canonical form of the address.

    Raises:
        UnsafeTargetError: If the address is missing, malformed or protected.
    """
    if not source_ip:
        raise UnsafeTargetError("No unambiguous source IP was found in the log.")
    # IPv6 zone IDs ("%eth0") accept arbitrary text, so reject them outright.
    if "%" in source_ip:
        raise UnsafeTargetError("Scoped IPv6 addresses are not accepted.")
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise UnsafeTargetError("The source IP is not a valid address.") from exc
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    for network in PROTECTED_NETWORKS:
        if address.version == network.version and address in network:
            raise UnsafeTargetError(f"Refusing to block protected address {address}.")
    return str(address)


def _validate_process_id(process_id: int | None) -> int:
    """Return the process ID, refusing missing values and PIDs 0 and 1."""
    if process_id is None or process_id <= 1:
        raise UnsafeTargetError("No safe process ID was found in the log.")
    return process_id


def _write_audit_record(
    context: RemediationContext, action_id: str, details: str
) -> None:
    """Append one JSON record to the audit log."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action_id": action_id,
        "details": details,
        "mock": True,
    }
    context.audit_log.parent.mkdir(parents=True, exist_ok=True)
    with context.audit_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def _describe_block_ip(context: RemediationContext) -> str:
    ip = validate_block_target(context.source_ip)
    return f"Record a mock firewall block rule for source IP {ip}."


def _run_block_ip(context: RemediationContext) -> str:
    ip = validate_block_target(context.source_ip)
    _write_audit_record(context, "block_source_ip", f"DENY inbound from {ip}")
    return f"Mock block rule recorded for {ip}."


def _describe_isolate_process(context: RemediationContext) -> str:
    pid = _validate_process_id(context.process_id)
    return f"Mark mock process PID {pid} as isolated (no real process is touched)."


def _run_isolate_process(context: RemediationContext) -> str:
    pid = _validate_process_id(context.process_id)
    _write_audit_record(context, "isolate_mock_process", f"Isolated mock PID {pid}")
    context.isolated_processes.add(pid)
    return f"Mock process PID {pid} marked as isolated."


def _describe_escalate(context: RemediationContext) -> str:
    return "Record an escalation for a human security analyst."


def _run_escalate(context: RemediationContext) -> str:
    _write_audit_record(context, "escalate_to_analyst", "Escalated for manual review")
    return "Escalation recorded for analyst review."


def _describe_no_action(context: RemediationContext) -> str:
    return "Take no defensive action; only record that the event was reviewed."


def _run_no_action(context: RemediationContext) -> str:
    _write_audit_record(context, "no_action", "Reviewed; no action taken")
    return "Review recorded. No defensive action taken."


# The strict allowlist. A MappingProxyType makes it read-only at runtime.
ALLOWLIST: Mapping[str, RemediationAction] = MappingProxyType(
    {
        "block_source_ip": RemediationAction(_describe_block_ip, _run_block_ip),
        "isolate_mock_process": RemediationAction(
            _describe_isolate_process, _run_isolate_process
        ),
        "escalate_to_analyst": RemediationAction(_describe_escalate, _run_escalate),
        "no_action": RemediationAction(_describe_no_action, _run_no_action),
    }
)


def get_action(action_id: object) -> RemediationAction:
    """Look up an action by exact ID.

    No trimming, case folding or fuzzy matching is applied.

    Args:
        action_id: Untrusted identifier, typically produced by the model.

    Returns:
        The matching allowlisted action.

    Raises:
        UnauthorizedActionError: If the value is not an allowlisted string.
    """
    if not isinstance(action_id, str) or action_id not in ALLOWLIST:
        raise UnauthorizedActionError(f"Action ID is not allowlisted: {action_id!r:.80}")
    return ALLOWLIST[action_id]


def describe_action(action_id: str, context: RemediationContext) -> str:
    """Return the trusted description of an action after validating its target."""
    return get_action(action_id).describe(context)


def execute_action(action_id: str, context: RemediationContext) -> str:
    """Execute an allowlisted action.

    Callers are responsible for obtaining human approval first; see
    :func:`src.main.run_pipeline`.

    Args:
        action_id: Allowlisted action identifier.
        context: Trusted action inputs.

    Returns:
        A human-readable result message.

    Raises:
        UnauthorizedActionError: If the action is not allowlisted.
        UnsafeTargetError: If the target fails validation.
    """
    return get_action(action_id).run(context)
