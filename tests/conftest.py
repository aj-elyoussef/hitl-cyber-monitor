"""Shared fixtures. No test touches the real network."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests

from src.ai_analyzer import ThreatAnalysis, parse_analysis
from src.simulation import CANNED_RESPONSE


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove real credentials and block real HTTP requests."""
    for name in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_MODEL",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
    ):
        monkeypatch.delenv(name, raising=False)

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("Tests must not make real HTTP requests.")

    monkeypatch.setattr(requests.Session, "request", refuse)


@pytest.fixture
def payload() -> dict[str, str]:
    return dict(CANNED_RESPONSE)


@pytest.fixture
def analysis() -> ThreatAnalysis:
    return parse_analysis(json.dumps(CANNED_RESPONSE))


@pytest.fixture
def make_client():
    """Build a mocked Anthropic client."""

    def factory(text: str, stop_reason: str = "end_turn") -> MagicMock:
        client = MagicMock()
        client.messages.create.return_value = SimpleNamespace(
            stop_reason=stop_reason,
            content=[
                SimpleNamespace(type="thinking", thinking=""),
                SimpleNamespace(type="text", text=text),
            ],
        )
        return client

    return factory
