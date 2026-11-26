"""Command-line entry point for the HITL cybersecurity monitor."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Callable, Sequence
from enum import IntEnum
from pathlib import Path

from src.ai_analyzer import MAX_LOG_CHARS, AnalysisError, ThreatAnalyzer
from src.log_parser import extract_targets
from src.notifier import (
    Approver,
    ConsoleApprover,
    Decision,
    NotifierError,
    TelegramApprover,
)
from src.remediator import (
    RemediationContext,
    RemediationError,
    describe_action,
    execute_action,
)
from src.simulation import MOCK_BRUTE_FORCE_LOG, SimulatedAnthropicClient


class ExitCode(IntEnum):
    """Process exit codes (argparse uses 2 for usage errors)."""

    EXECUTED = 0
    FAILED_SAFE = 1
    REJECTED = 3
    TIMED_OUT = 4


def run_pipeline(
    log_text: str,
    analyzer: ThreatAnalyzer,
    approver: Approver,
    audit_log: Path,
    output: Callable[[str], None] = print,
) -> ExitCode:
    """Run analyse, approve and remediate for one batch of log lines.

    Args:
        log_text: Untrusted log lines.
        analyzer: Threat analyzer.
        approver: Human approval channel.
        audit_log: Destination for mock remediation records.
        output: Function used to print progress.

    Returns:
        The exit code describing the outcome.
    """
    try:
        output("[1/4] Analysing log entries...")
        analysis = analyzer.analyze(log_text)
        output(
            f"      Severity: {analysis.severity.value} | "
            f"Proposed action: {analysis.recommended_action_id}"
        )

        output("[2/4] Validating the action and deriving its target from the log...")
        targets = extract_targets(log_text)
        context = RemediationContext(
            audit_log=audit_log,
            source_ip=targets.source_ip,
            process_id=targets.process_id,
        )
        # Fails here, before bothering the human, if the action or target is unsafe.
        description = describe_action(analysis.recommended_action_id, context)
        output(f"      {description}")

        output("[3/4] Waiting for human approval...")
        decision = approver.request_approval(analysis, description)

        # The only path to execution is an explicit approval.
        if decision is Decision.TIMED_OUT:
            output("[4/4] ABORTED: approval timed out. No action taken.")
            return ExitCode.TIMED_OUT
        if decision is not Decision.APPROVED:
            output("[4/4] ABORTED: not approved. No action taken.")
            return ExitCode.REJECTED

        result = execute_action(analysis.recommended_action_id, context)
        output(f"[4/4] APPROVED: {result}")
        output(f"      Audit log: {audit_log.as_posix()}")
        return ExitCode.EXECUTED
    except (AnalysisError, NotifierError, RemediationError, OSError) as exc:
        output(f"FAILED SAFE: {exc}")
        return ExitCode.FAILED_SAFE


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="python -m src.main",
        description="Human-in-the-Loop AI cybersecurity monitor.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--simulate",
        action="store_true",
        help="Use a mock SSH brute-force log. Offline unless combined with --live-*.",
    )
    source.add_argument("--log-file", type=Path, help="Analyse an sshd log excerpt.")
    parser.add_argument(
        "--live-ai",
        action="store_true",
        help="With --simulate, call the real Claude API.",
    )
    parser.add_argument(
        "--live-telegram",
        action="store_true",
        help="With --simulate, ask for approval on your phone.",
    )
    parser.add_argument(
        "--auto-answer",
        choices=("yes", "no"),
        help="Offline simulation only: answer the console prompt automatically.",
    )
    parser.add_argument(
        "--timeout", type=_positive_int, default=300, help="Approval timeout in seconds."
    )
    parser.add_argument("--audit-log", type=Path, default=Path("logs/audit.jsonl"))
    return parser


def _load_env_file() -> None:
    """Load ``.env`` from the working directory if python-dotenv is installed."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(Path.cwd() / ".env")


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, wire up dependencies and run the pipeline."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.log_file and (args.live_ai or args.live_telegram):
        parser.error("--live-ai and --live-telegram apply only to --simulate.")
    use_live_ai = args.log_file is not None or args.live_ai
    use_telegram = args.log_file is not None or args.live_telegram
    if args.auto_answer and (not args.simulate or use_telegram):
        parser.error("--auto-answer is allowed only with console simulation.")

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    if use_live_ai or use_telegram:
        _load_env_file()

    try:
        if args.simulate:
            print("SIMULATION MODE: mock log, mock remediation.")
            log_text = MOCK_BRUTE_FORCE_LOG
            print(log_text)
        else:
            with args.log_file.open(encoding="utf-8", errors="replace") as handle:
                log_text = handle.read(MAX_LOG_CHARS + 1)

        analyzer = (
            ThreatAnalyzer()
            if use_live_ai
            else ThreatAnalyzer(client=SimulatedAnthropicClient())
        )
        approver: Approver
        if use_telegram:
            approver = TelegramApprover(
                os.environ.get("TELEGRAM_BOT_TOKEN", ""),
                os.environ.get("TELEGRAM_CHAT_ID", ""),
                timeout_seconds=args.timeout,
            )
        else:
            approver = ConsoleApprover(auto_answer=args.auto_answer)
    except (AnalysisError, NotifierError, OSError) as exc:
        print(f"FAILED SAFE: {exc}")
        return ExitCode.FAILED_SAFE

    return run_pipeline(log_text, analyzer, approver, args.audit_log)


if __name__ == "__main__":
    sys.exit(main())
