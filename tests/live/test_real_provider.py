"""Opt-in live checks against the configured real provider.

Skipped unless AGENTSHIELD_RUN_REAL=1. They use the provider quota, never run in CI, and are
not research evidence (integration checks only).
"""

from __future__ import annotations

import os

import pytest

from agentshield.config import load_model_config
from agentshield.crm.tools import tool_schemas
from agentshield.llm.openai_compatible import OpenAICompatibleClient
from agentshield.llm.settings import load_environment, resolve_model_settings
from agentshield.schemas.llm import ChatMessage, GenerationConfig, MessageRole
from tests.conftest import ROOT

pytestmark = [
    pytest.mark.real_llm,
    pytest.mark.skipif(
        os.environ.get("AGENTSHIELD_RUN_REAL") != "1", reason="set AGENTSHIELD_RUN_REAL=1"
    ),
]


def _client() -> OpenAICompatibleClient:
    config = load_model_config(ROOT / "configs" / "model.groq.yaml")
    return OpenAICompatibleClient(resolve_model_settings(config, load_environment(ROOT)))


def test_model_is_listed() -> None:
    client = _client()
    assert client.model_id in {m["id"] for m in client.list_models()}


def test_single_tool_call_roundtrip() -> None:
    client = _client()
    messages = [
        ChatMessage(role=MessageRole.SYSTEM, content="You are a CRM assistant. Use tools."),
        ChatMessage(role=MessageRole.USER, content="Get invoice INV-003."),
    ]
    response = client.complete(
        messages, tool_schemas(["get_invoice"]), GenerationConfig(max_output_tokens=200)
    )
    assert response.tool_calls and response.tool_calls[0].name == "get_invoice"
    assert response.tool_calls[0].arguments == {"invoice_id": "INV-003"}
