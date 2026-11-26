"""Human approval channels: Telegram (phone) and console (offline simulation).

Both channels fail closed. Only an explicit "Yes" returns
:attr:`Decision.APPROVED`.
"""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Callable
from enum import Enum
from typing import Any, Protocol

import requests

from src.ai_analyzer import ThreatAnalysis

logger = logging.getLogger(__name__)

API_BASE = "https://api.telegram.org"
LONG_POLL_SECONDS = 25
MAX_CONSECUTIVE_ERRORS = 3


class NotifierError(Exception):
    """Raised when an approval channel cannot be used safely."""


class Decision(str, Enum):
    """Outcome of an approval request."""

    APPROVED = "approved"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"


class Approver(Protocol):
    """Anything that can ask a human to approve an action."""

    def request_approval(
        self, analysis: ThreatAnalysis, action_description: str
    ) -> Decision:
        """Ask for approval and return the decision."""
        ...


def format_message(analysis: ThreatAnalysis, action_description: str) -> str:
    """Build the approval message.

    ``action_description`` comes from trusted code and is shown separately from
    the AI text, so a misleading AI question cannot disguise what "Yes" does.
    """
    return (
        "SECURITY ALERT\n"
        f"Severity (AI assessment): {analysis.severity.value}\n\n"
        f"AI summary (unverified):\n{analysis.threat_summary}\n\n"
        f"AI question:\n{analysis.confirmation_question}\n\n"
        "IF YOU TAP YES, THIS EXACT ACTION RUNS (verified by code):\n"
        f"{action_description}"
    )


class TelegramApprover:
    """Request approval through a Telegram bot with inline Yes/No buttons.

    Only private chats are supported: the user who presses a button must have the
    same ID as the configured chat.
    """

    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        timeout_seconds: float = 300,
        session: Any | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Create a Telegram approver.

        Args:
            bot_token: Token issued by @BotFather.
            chat_id: Your numeric private chat ID.
            timeout_seconds: How long to wait for a button press.
            session: ``requests.Session`` compatible object.
            clock: Monotonic clock, injectable for tests.
            sleep: Sleep function, injectable for tests.

        Raises:
            NotifierError: If configuration is missing or invalid.
        """
        if not bot_token or not chat_id:
            raise NotifierError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required.")
        if not chat_id.isascii() or not chat_id.isdigit():
            raise NotifierError("TELEGRAM_CHAT_ID must be a numeric private chat ID.")
        self._token = bot_token
        self._chat_id = int(chat_id)
        self._timeout = timeout_seconds
        self._session = session or requests.Session()
        self._clock = clock
        self._sleep = sleep

    def __repr__(self) -> str:
        return "TelegramApprover(<credentials hidden>)"

    def _call(self, method: str, payload: dict[str, Any], timeout: float = 15) -> Any:
        """Call a Bot API method and return its ``result`` field.

        Exceptions from ``requests`` can include the URL, which contains the bot
        token. They are replaced and their chain is suppressed.
        """
        try:
            response = self._session.post(
                f"{API_BASE}/bot{self._token}/{method}", json=payload, timeout=timeout
            )
            body = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise NotifierError(
                f"Telegram {method} failed: {type(exc).__name__}"
            ) from None
        if not isinstance(body, dict) or body.get("ok") is not True:
            code = body.get("error_code") if isinstance(body, dict) else None
            raise NotifierError(f"Telegram {method} was rejected (error code {code}).")
        return body.get("result")

    def request_approval(
        self, analysis: ThreatAnalysis, action_description: str
    ) -> Decision:
        """Send the alert and wait for a Yes or No button press.

        Args:
            analysis: Validated AI assessment.
            action_description: Trusted description of the pending action.

        Returns:
            The human's decision, or :attr:`Decision.TIMED_OUT`.

        Raises:
            NotifierError: If Telegram cannot be reached or returns bad data.
        """
        # A fresh random nonce stops old or replayed buttons approving this request.
        nonce = secrets.token_urlsafe(16)
        sent = self._call(
            "sendMessage",
            {
                "chat_id": self._chat_id,
                "text": format_message(analysis, action_description),
                # No parse_mode: AI text is never interpreted as markup.
                "link_preview_options": {"is_disabled": True},
                "reply_markup": {
                    "inline_keyboard": [
                        [
                            {"text": "Yes", "callback_data": f"{nonce}:yes"},
                            {"text": "No", "callback_data": f"{nonce}:no"},
                        ]
                    ]
                },
            },
        )
        if not isinstance(sent, dict) or not isinstance(sent.get("message_id"), int):
            raise NotifierError("Telegram sendMessage returned no message ID.")
        message_id = sent["message_id"]
        try:
            return self._wait_for_decision(nonce, message_id)
        finally:
            self._remove_buttons(message_id)

    def _wait_for_decision(self, nonce: str, message_id: int) -> Decision:
        deadline = self._clock() + self._timeout
        offset: int | None = None
        errors = 0
        while (remaining := deadline - self._clock()) > 0:
            poll = int(min(LONG_POLL_SECONDS, remaining))
            payload: dict[str, Any] = {
                "timeout": poll,
                "allowed_updates": ["callback_query"],
            }
            if offset is not None:
                payload["offset"] = offset
            try:
                updates = self._call("getUpdates", payload, timeout=poll + 10)
                if not isinstance(updates, list):
                    raise NotifierError("Telegram getUpdates returned invalid data.")
            except NotifierError:
                errors += 1
                if errors >= MAX_CONSECUTIVE_ERRORS:
                    raise
                self._sleep(2)
                continue
            errors = 0

            # A reply that arrives after the deadline never approves anything.
            if self._clock() > deadline:
                break

            for update in updates:
                if not isinstance(update, dict):
                    continue
                if isinstance(update.get("update_id"), int):
                    offset = update["update_id"] + 1
                decision = self._read_decision(update, nonce, message_id)
                if decision is not None:
                    return decision
            if not updates:
                self._sleep(0.5)
        return Decision.TIMED_OUT

    def _read_decision(
        self, update: dict[str, Any], nonce: str, message_id: int
    ) -> Decision | None:
        """Return a decision only for an authentic press on the current message."""
        query = update.get("callback_query")
        if not isinstance(query, dict):
            return None
        sender = query.get("from")
        message = query.get("message")
        if not isinstance(sender, dict) or not isinstance(message, dict):
            return None
        chat = message.get("chat")
        if (
            sender.get("id") != self._chat_id
            or not isinstance(chat, dict)
            or chat.get("id") != self._chat_id
            or message.get("message_id") != message_id
        ):
            return None
        decisions = {
            f"{nonce}:yes": Decision.APPROVED,
            f"{nonce}:no": Decision.REJECTED,
        }
        data = query.get("data")
        decision = decisions.get(data) if isinstance(data, str) else None
        if decision is not None:
            self._acknowledge(query.get("id"), decision)
        return decision

    def _acknowledge(self, query_id: object, decision: Decision) -> None:
        """Stop the button spinner. Cosmetic, so failures are only logged."""
        try:
            self._call(
                "answerCallbackQuery",
                {"callback_query_id": query_id, "text": f"Received: {decision.value}"},
            )
        except NotifierError as exc:
            logger.warning("%s", exc)

    def _remove_buttons(self, message_id: int) -> None:
        """Remove the keyboard so the request cannot appear to be still open."""
        try:
            self._call(
                "editMessageReplyMarkup",
                {
                    "chat_id": self._chat_id,
                    "message_id": message_id,
                    "reply_markup": {"inline_keyboard": []},
                },
            )
        except NotifierError as exc:
            logger.warning("%s", exc)


class ConsoleApprover:
    """Terminal stand-in for the phone, used by offline simulation."""

    def __init__(
        self,
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        auto_answer: str | None = None,
    ) -> None:
        """Create a console approver.

        Args:
            input_func: Function used to read the answer.
            output_func: Function used to print the alert.
            auto_answer: ``"yes"`` or ``"no"`` for non-interactive simulation.
        """
        self._input = input_func
        self._output = output_func
        self._auto_answer = auto_answer

    def request_approval(
        self, analysis: ThreatAnalysis, action_description: str
    ) -> Decision:
        """Print the alert and read a Yes/No answer. Anything but yes rejects."""
        self._output("\n--- Simulated phone notification ---")
        self._output(format_message(analysis, action_description))
        self._output("[ Yes ]  [ No ]")
        if self._auto_answer is not None:
            answer = self._auto_answer
            self._output(f"Your answer (yes/no): {answer}  (auto)")
        else:
            try:
                answer = self._input("Your answer (yes/no): ")
            except (EOFError, KeyboardInterrupt):
                return Decision.REJECTED
        approved = answer.strip().lower() in {"y", "yes"}
        return Decision.APPROVED if approved else Decision.REJECTED
