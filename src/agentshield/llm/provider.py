"""Build the LLM client for resolved settings. A real provider never degrades to fake."""

from __future__ import annotations

from agentshield.llm.fake_agent import HeuristicFakeAgent
from agentshield.llm.openai_compatible import OpenAICompatibleClient
from agentshield.llm.protocol import LLMClient
from agentshield.llm.settings import ResolvedModelSettings


def build_client(settings: ResolvedModelSettings) -> LLMClient:
    if settings.provider == "fake":
        return HeuristicFakeAgent(model=settings.model_id)
    return OpenAICompatibleClient(settings)
