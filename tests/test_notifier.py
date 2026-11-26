"""Tests for the approval channels with a mocked Telegram API."""

from __future__ import annotations

from typing import Any

import pytest
import requests

from src.notifier import ConsoleApprover, Decision, NotifierError, TelegramApprover

CHAT_ID = 123456
MESSAGE_ID = 77
TOKEN = "123:TEST-TOKEN"
DESCRIPTION = "Record a mock firewall block rule for source IP 203.0.113.45."


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class FakeResponse:
    def __init__(self, body: Any) -> None:
        self.body = body

    def json(self) -> Any:
        return self.body


class FakeTelegram:
    """In-memory Bot API. Button presses use the real nonce from sendMessage."""

    def __init__(self, clock: FakeClock, script: list | None = None) -> None:
        self.clock = clock
        self.script = list(script or [])
        self.calls: list[tuple[str, dict]] = []
        self.buttons: dict[str, str] = {}

    def post(self, url: str, json: dict, timeout: float) -> FakeResponse:
        method = url.rsplit("/", 1)[1]
        self.calls.append((method, json))
        if method == "sendMessage":
            row = json["reply_markup"]["inline_keyboard"][0]
            self.buttons = {b["text"]: b["callback_data"] for b in row}
            return FakeResponse({"ok": True, "result": {"message_id": MESSAGE_ID}})
        if method == "getUpdates":
            self.clock.now += max(json["timeout"], 1)
            step = self.script.pop(0) if self.script else []
            result = step(self) if callable(step) else step
            return FakeResponse({"ok": True, "result": result})
        return FakeResponse({"ok": True, "result": True})

    def payloads(self, method: str) -> list[dict]:
        return [body for name, body in self.calls if name == method]


def press(button: str, *, user=CHAT_ID, chat=CHAT_ID, message=MESSAGE_ID, data=None):
    """Create a scripted getUpdates response containing one button press."""

    def build(api: FakeTelegram) -> list[dict]:
        return [
            {
                "update_id": 10,
                "callback_query": {
                    "id": "query-1",
                    "from": {"id": user},
                    "message": {"message_id": message, "chat": {"id": chat}},
                    "data": data or api.buttons[button],
                },
            }
        ]

    return build


def make_approver(api: Any, clock: FakeClock, timeout: float = 60) -> TelegramApprover:
    return TelegramApprover(
        TOKEN,
        str(CHAT_ID),
        timeout_seconds=timeout,
        session=api,
        clock=clock,
        sleep=clock.sleep,
    )


@pytest.mark.parametrize(
    ("button", "expected"), [("Yes", Decision.APPROVED), ("No", Decision.REJECTED)]
)
def test_button_press_returns_decision(analysis, button, expected):
    clock = FakeClock()
    api = FakeTelegram(clock, [press(button)])

    decision = make_approver(api, clock).request_approval(analysis, DESCRIPTION)

    assert decision is expected
    assert api.payloads("answerCallbackQuery")
    assert api.payloads("editMessageReplyMarkup")


def test_message_contains_question_trusted_action_and_buttons(analysis):
    clock = FakeClock()
    api = FakeTelegram(clock, [press("No")])

    make_approver(api, clock).request_approval(analysis, DESCRIPTION)

    sent = api.payloads("sendMessage")[0]
    assert analysis.threat_summary in sent["text"]
    assert analysis.confirmation_question in sent["text"]
    assert DESCRIPTION in sent["text"]
    assert "parse_mode" not in sent
    assert sent["link_preview_options"] == {"is_disabled": True}
    assert set(api.buttons) == {"Yes", "No"}
    assert all(len(data.encode()) <= 64 for data in api.buttons.values())


@pytest.mark.parametrize(
    "forged",
    [
        press("Yes", user=999),
        press("Yes", chat=999),
        press("Yes", message=1),
        press("Yes", data="stale-nonce:yes"),
    ],
    ids=["wrong-user", "wrong-chat", "wrong-message", "stale-nonce"],
)
def test_forged_or_stale_presses_are_ignored(analysis, forged):
    clock = FakeClock()
    api = FakeTelegram(clock, [forged])

    decision = make_approver(api, clock).request_approval(analysis, DESCRIPTION)

    assert decision is Decision.TIMED_OUT
    assert not api.payloads("answerCallbackQuery")


def test_offset_advances_past_ignored_updates(analysis):
    clock = FakeClock()
    api = FakeTelegram(clock, [press("Yes", user=999), press("No")])

    decision = make_approver(api, clock).request_approval(analysis, DESCRIPTION)

    assert decision is Decision.REJECTED
    assert api.payloads("getUpdates")[1]["offset"] == 11


def test_no_reply_times_out(analysis):
    clock = FakeClock()
    api = FakeTelegram(clock)

    decision = make_approver(api, clock).request_approval(analysis, DESCRIPTION)

    assert decision is Decision.TIMED_OUT
    assert api.payloads("editMessageReplyMarkup")


def test_late_approval_is_ignored(analysis):
    clock = FakeClock()

    def late(api: FakeTelegram) -> list[dict]:
        clock.now += 1000
        return press("Yes")(api)

    api = FakeTelegram(clock, [late])

    decision = make_approver(api, clock).request_approval(analysis, DESCRIPTION)

    assert decision is Decision.TIMED_OUT


def test_network_errors_do_not_leak_the_token(analysis):
    class Broken:
        def post(self, url: str, **kwargs: Any) -> None:
            raise requests.ConnectionError(f"cannot reach {url}")

    clock = FakeClock()

    with pytest.raises(NotifierError) as caught:
        make_approver(Broken(), clock).request_approval(analysis, DESCRIPTION)

    assert TOKEN not in str(caught.value)
    assert caught.value.__suppress_context__


@pytest.mark.parametrize("body", [{"ok": False, "error_code": 401}, [], {"ok": True}])
def test_bad_send_response_fails_safely(analysis, body):
    class Rejecting:
        def post(self, url: str, **kwargs: Any) -> FakeResponse:
            return FakeResponse(body)

    with pytest.raises(NotifierError):
        make_approver(Rejecting(), FakeClock()).request_approval(analysis, DESCRIPTION)


def test_repeated_poll_failures_raise(analysis):
    clock = FakeClock()
    api = FakeTelegram(clock, [None, None, None])

    with pytest.raises(NotifierError):
        make_approver(api, clock, timeout=600).request_approval(analysis, DESCRIPTION)

    assert len(api.payloads("getUpdates")) == 3


def test_single_poll_failure_is_retried(analysis):
    clock = FakeClock()
    api = FakeTelegram(clock, [None, press("Yes")])

    decision = make_approver(api, clock).request_approval(analysis, DESCRIPTION)

    assert decision is Decision.APPROVED


@pytest.mark.parametrize(
    ("token", "chat_id"),
    [("", "1"), ("token", ""), ("token", "-100123"), ("token", "@channel")],
)
def test_invalid_configuration_is_rejected(token, chat_id):
    with pytest.raises(NotifierError):
        TelegramApprover(token, chat_id)


def test_repr_hides_credentials():
    assert TOKEN not in repr(TelegramApprover(TOKEN, str(CHAT_ID)))


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ("yes", Decision.APPROVED),
        (" Y ", Decision.APPROVED),
        ("no", Decision.REJECTED),
        ("", Decision.REJECTED),
        ("yes please", Decision.REJECTED),
    ],
)
def test_console_approves_only_explicit_yes(analysis, answer, expected):
    approver = ConsoleApprover(input_func=lambda _: answer, output_func=lambda _: None)

    assert approver.request_approval(analysis, DESCRIPTION) is expected


@pytest.mark.parametrize("error", [EOFError, KeyboardInterrupt])
def test_console_interruption_rejects(analysis, error):
    def interrupted(_: str) -> str:
        raise error

    approver = ConsoleApprover(input_func=interrupted, output_func=lambda _: None)

    assert approver.request_approval(analysis, DESCRIPTION) is Decision.REJECTED
