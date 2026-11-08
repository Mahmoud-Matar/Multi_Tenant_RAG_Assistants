"""Deterministic screening for prompt injection and RAG poisoning indicators."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


ZERO_WIDTH_AND_BIDI = re.compile("[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]")
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
LONG_SECRET = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")

RULES: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "prompt_injection",
        "high",
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\b.{0,48}\b(?:previous|prior|system|developer|security|policy|instructions?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "prompt_injection",
        "high",
        "role_reassignment",
        re.compile(
            r"\b(?:you are now|act as|switch roles?|new system prompt|developer message)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "prompt_injection",
        "high",
        "embedded_model_instruction",
        re.compile(
            r"\b(?:assistant|model|chatbot)\s+(?:must|shall|should|will)\b|\bfollow (?:only )?these instructions\b",
            re.IGNORECASE,
        ),
    ),
    (
        "tenant_escape",
        "critical",
        "cross_tenant_request",
        re.compile(
            r"\b(?:access|search|retrieve|show|switch|impersonate)\b.{0,50}\b(?:another|other|different) tenant\b|\btenant[_ -]?id\s*[:=]",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "data_exfiltration",
        "critical",
        "protected_data_extraction",
        re.compile(
            r"\b(?:reveal|show|print|dump|extract|exfiltrate|list)\b.{0,60}\b(?:system prompt|hidden prompt|developer message|secrets?|credentials?|all documents|database rows?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "poisoned_content",
        "high",
        "citation_suppression",
        re.compile(
            r"\b(?:do not|never)\s+(?:cite|mention|disclose)\s+(?:this|the source|these instructions)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "hidden_text",
        "high",
        "hidden_markup",
        re.compile(
            r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(?:white|#fff(?:fff)?))",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True)
class ThreatFinding:
    category: str
    severity: str
    indicators: tuple[str, ...]
    evidence_hash: str
    evidence_excerpt: str


def _redacted_excerpt(text: str, limit: int = 240) -> str:
    value = ZERO_WIDTH_AND_BIDI.sub("[hidden-character]", text)
    value = EMAIL.sub("[email]", value)
    value = LONG_SECRET.sub("[redacted-token]", value)
    value = " ".join(value.split())
    return value[:limit]


def screen_for_threats(text: str, *, source: str) -> list[ThreatFinding]:
    """Return grouped findings without executing or interpreting suspicious text."""
    grouped: dict[tuple[str, str], list[str]] = {}
    if ZERO_WIDTH_AND_BIDI.search(text):
        grouped.setdefault(("hidden_text", "high"), []).append("unicode_concealment")
    for category, severity, indicator, pattern in RULES:
        if pattern.search(text):
            # Citation suppression is only a poisoning signal in retrieved content.
            if indicator == "citation_suppression" and source == "user_query":
                continue
            grouped.setdefault((category, severity), []).append(indicator)

    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    excerpt = _redacted_excerpt(text)
    return [
        ThreatFinding(
            category=category,
            severity=severity,
            indicators=tuple(sorted(set(indicators))),
            evidence_hash=digest,
            evidence_excerpt=excerpt,
        )
        for (category, severity), indicators in grouped.items()
    ]
