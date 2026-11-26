"""End-to-end pipeline tests with mocked external services."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

import src.main as app
from src.ai_analyzer import ThreatAnalyzer
from src.notifier import Decision, NotifierError
from src.simulation import MOCK_BRUTE_FORCE_LOG


def run(make_client, response_text, approver, tmp_path, log=MOCK_BRUTE_FORCE_LOG):
    return app.run_pipeline(
        log,
        ThreatAnalyzer(client=make_client(response_text)),
        approver,
        tmp_path / "audit.jsonl",
        output=lambda _: None,
    )


def approver_returning(decision):
    approver = MagicMock()
    approver.request_approval.return_value = decision
    return approver


@pytest.fixture
def spy_execute(monkeypatch):
    spy = MagicMock(return_value="done")
    monkeypatch.setattr(app, "execute_action", spy)
    return spy


@pytest.mark.parametrize(
    ("decision", "exit_code"),
    [
        (Decision.REJECTED, app.ExitCode.REJECTED),
        (Decision.TIMED_OUT, app.ExitCode.TIMED_OUT),
        (None, app.ExitCode.REJECTED),
        ("approved", app.ExitCode.REJECTED),
        (True, app.ExitCode.REJECTED),
    ],
)
def test_anything_but_approval_aborts_execution(
    make_client, payload, tmp_path, spy_execute, decision, exit_code
):
    result = run(make_client, json.dumps(payload), approver_returning(decision), tmp_path)

    assert result == exit_code
    spy_execute.assert_not_called()


def test_approval_executes_once(make_client, payload, tmp_path, spy_execute):
    approver = approver_returning(Decision.APPROVED)

    result = run(make_client, json.dumps(payload), approver, tmp_path)

    assert result == app.ExitCode.EXECUTED
    spy_execute.assert_called_once()
    assert spy_execute.call_args.args[0] == "block_source_ip"


@pytest.mark.parametrize("bad_id", ["rm -rf /", "format_disk"])
def test_invalid_llm_output_never_reaches_human_or_remediator(
    make_client, payload, tmp_path, spy_execute, bad_id
):
    payload["recommended_action_id"] = bad_id
    approver = approver_returning(Decision.APPROVED)

    result = run(make_client, json.dumps(payload), approver, tmp_path)

    assert result == app.ExitCode.FAILED_SAFE
    approver.request_approval.assert_not_called()
    spy_execute.assert_not_called()


def test_missing_target_stops_before_asking(make_client, payload, tmp_path, spy_execute):
    approver = approver_returning(Decision.APPROVED)

    result = run(make_client, json.dumps(payload), approver, tmp_path, log="odd line")

    assert result == app.ExitCode.FAILED_SAFE
    approver.request_approval.assert_not_called()
    spy_execute.assert_not_called()


def test_notifier_failure_fails_safe(make_client, payload, tmp_path, spy_execute):
    approver = MagicMock()
    approver.request_approval.side_effect = NotifierError("down")

    result = run(make_client, json.dumps(payload), approver, tmp_path)

    assert result == app.ExitCode.FAILED_SAFE
    spy_execute.assert_not_called()


@pytest.mark.parametrize(
    ("answer", "code", "written"), [("yes", 0, True), ("no", 3, False)]
)
def test_simulate_cli_end_to_end(tmp_path, capsys, answer, code, written):
    audit = tmp_path / "audit.jsonl"

    result = app.main(["--simulate", "--auto-answer", answer, "--audit-log", str(audit)])

    assert result == code
    assert audit.exists() is written
    assert "SIMULATION MODE" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--log-file", "x.log", "--auto-answer", "yes"],
        ["--log-file", "x.log", "--live-ai"],
        ["--simulate", "--live-telegram", "--auto-answer", "yes"],
        ["--simulate", "--timeout", "0"],
    ],
)
def test_unsafe_or_invalid_cli_arguments_are_rejected(argv):
    with pytest.raises(SystemExit) as caught:
        app.main(argv)

    assert caught.value.code == 2


def test_missing_log_file_fails_safe(tmp_path):
    result = app.main(["--log-file", str(tmp_path / "missing.log")])

    assert result == app.ExitCode.FAILED_SAFE
