"""LLM adapter for grounded answer generation."""

from __future__ import annotations

import os

from langchain_openai import ChatOpenAI

from .models import GeneratedAnswer, RetrievedChunk
from .prompting import build_messages


class OpenAIAnswerGenerator:
    def __init__(self, model: str | None = None) -> None:
        self.model = model or os.getenv("RAG_CHAT_MODEL", "gpt-4o-mini")

    def generate(self, question: str, chunks: list[RetrievedChunk]) -> GeneratedAnswer:
        response = ChatOpenAI(model=self.model, temperature=0).invoke(
            build_messages(question, chunks)
        )
        content = response.content
        if isinstance(content, list):
            content = "".join(
                item.get("text", "") if isinstance(item, dict) else str(item)
                for item in content
            )
        return GeneratedAnswer(answer=str(content).strip())
