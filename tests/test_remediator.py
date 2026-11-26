"""Tests for the allowlist and target validation."""

from __future__ import annotations

import json

import pytest

from src.remediator import (
    ALLOWLIST,
    RemediationContext,
    UnauthorizedActionError,
    UnsafeTargetError,
    describe_action,
    execute_action,
    validate_block_target,
)


@pytest.fixture
def context(tmp_path):
    return RemediationContext(
        audit_log=tmp_path / "audit.jsonl", source_ip="203.0.113.45", process_id=4135
    )


@pytest.mark.parametrize(
    "action_id",
    [
        "delete_everything",
        "rm -rf /",
        "block_source_ip; reboot",
        "__import__('os').system('id')",
        "BLOCK_SOURCE_IP",
        " block_source_ip",
        "__class__",
        "",
        None,
        123,
        ["block_source_ip"],
    ],
)
def test_unauthorized_action_ids_are_rejected(context, action_id):
    for operation in (describe_action, execute_action):
        with pytest.raises(UnauthorizedActionError):
            operation(action_id, context)

    assert not context.audit_log.exists()


def test_allowlist_is_read_only():
    with pytest.raises(TypeError):
        ALLOWLIST["new_action"] = ALLOWLIST["no_action"]  # type: ignore[index]


@pytest.mark.parametrize("action_id", list(ALLOWLIST))
def test_every_allowlisted_action_writes_one_mock_record(context, action_id):
    assert describe_action(action_id, context)
    assert not context.audit_log.exists(), "describing must have no side effects"

    execute_action(action_id, context)

    records = context.audit_log.read_text(encoding="utf-8").splitlines()
    assert len(records) == 1
    assert json.loads(records[0])["action_id"] == action_id
    assert json.loads(records[0])["mock"] is True


def test_isolation_updates_only_the_mock_registry(context):
    execute_action("isolate_mock_process", context)

    assert context.isolated_processes == {4135}


@pytest.mark.parametrize(
    "ip",
    [
        None,
        "",
        "not-an-ip",
        "203.0.113.45; reboot",
        "203.0.113.0/24",
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.9",
        "192.168.1.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "::ffff:10.0.0.1",
        "fe80::1%eth0; reboot",
    ],
)
def test_unsafe_block_targets_are_rejected(ip):
    with pytest.raises(UnsafeTargetError):
        validate_block_target(ip)


@pytest.mark.parametrize("pid", [None, -1, 0, 1])
def test_unsafe_process_ids_are_rejected(tmp_path, pid):
    context = RemediationContext(audit_log=tmp_path / "a.jsonl", process_id=pid)

    with pytest.raises(UnsafeTargetError):
        execute_action("isolate_mock_process", context)
