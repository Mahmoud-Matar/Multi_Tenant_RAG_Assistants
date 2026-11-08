"""Query normalization and input safety checks."""

from __future__ import annotations

import re


CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def screen_query(
    question: str,
    *,
    allowed_topics: list[str] | None = None,
    excluded_topics: list[str] | None = None,
) -> str:
    normalized = " ".join(question.split())
    if len(normalized) < 2:
        raise ValueError("Please enter a more complete question.")
    if len(normalized) > 2000:
        raise ValueError("The question exceeds the 2,000 character limit.")
    if CONTROL_CHARACTERS.search(question):
        raise ValueError("The question contains unsupported control characters.")
    lowered = normalized.casefold()
    excluded = [topic.strip().casefold() for topic in (excluded_topics or []) if topic.strip()]
    if any(topic in lowered for topic in excluded):
        raise ValueError("This question is outside the tenant's approved domain.")
    allowed = [topic.strip().casefold() for topic in (allowed_topics or []) if topic.strip()]
    if allowed and not any(topic in lowered for topic in allowed):
        raise ValueError("This question is outside the tenant's approved domain.")
    return normalized
