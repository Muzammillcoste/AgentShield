"""Build the LLM client for resolved settings. A real provider never degrades to fake."""

from __future__ import annotations

from agentshield.llm.fake_agent import HeuristicFakeAgent
from agentshield.llm.openai_compatible import OpenAICompatibleClient
from agentshield.llm.protocol import LLMClient
from agentshield.llm.settings import ResolvedModelSettings


def build_client(
    settings: ResolvedModelSettings, *, fake_follows_injections: bool = False
) -> LLMClient:
    """`fake_follows_injections` makes the offline fake obey tool-output imperatives (to test
    attack/defense plumbing); it has no effect on real providers."""
    if settings.provider == "fake":
        return HeuristicFakeAgent(
            model=settings.model_id, follow_injections=fake_follows_injections
        )
    return OpenAICompatibleClient(settings)
