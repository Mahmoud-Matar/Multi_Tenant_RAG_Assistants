"""Deterministic citation validation before an answer leaves the backend."""

from __future__ import annotations

import re

from .models import Citation, RetrievedChunk


CITATION_PATTERN = re.compile(r"\[(\d+)]")
SENTENCE_PATTERN = re.compile(r"(?<=[.!?])\s+|\n+")
WORD_PATTERN = re.compile(r"[a-z0-9]+")
STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in",
    "is", "it", "of", "on", "or", "that", "the", "this", "to", "was", "with",
}


def _tokens(value: str) -> set[str]:
    tokens = set()
    for token in WORD_PATTERN.findall(value.casefold()):
        if token in STOP_WORDS:
            continue
        if token.endswith("ies") and len(token) > 4:
            token = f"{token[:-3]}y"
        elif token.endswith("s") and len(token) > 3:
            token = token[:-1]
        tokens.add(token)
    return tokens


def _sentence_is_supported(
    sentence: str, chunks: list[RetrievedChunk], minimum_support: float
) -> bool:
    citation_numbers = [int(value) for value in CITATION_PATTERN.findall(sentence)]
    claim = CITATION_PATTERN.sub("", sentence).strip()
    claim_tokens = _tokens(claim)
    if len(claim_tokens) < 2:
        return True
    if not citation_numbers or any(number < 1 or number > len(chunks) for number in citation_numbers):
        return False
    evidence_tokens = set().union(
        *(_tokens(chunks[number - 1].text) for number in citation_numbers)
    )
    return len(claim_tokens & evidence_tokens) / len(claim_tokens) >= minimum_support


def validate_citations(
    answer: str,
    chunks: list[RetrievedChunk],
    *,
    minimum_support: float = 0.65,
) -> list[Citation]:
    numbers = [int(value) for value in CITATION_PATTERN.findall(answer)]
    unique_numbers = list(dict.fromkeys(numbers))
    if not answer or not unique_numbers or any(number < 1 or number > len(chunks) for number in unique_numbers):
        return []
    sentences = [sentence.strip() for sentence in SENTENCE_PATTERN.split(answer) if sentence.strip()]
    if not all(
        _sentence_is_supported(sentence, chunks, minimum_support)
        for sentence in sentences
    ):
        return []
    citations = []
    for number in unique_numbers:
        chunk = chunks[number - 1]
        excerpt = " ".join(chunk.text.split())
        if len(excerpt) > 240:
            excerpt = f"{excerpt[:237].rstrip()}..."
        citations.append(
            Citation(
                number=number,
                document_id=chunk.document_id,
                version_id=chunk.version_id,
                chunk_id=chunk.chunk_id,
                filename=chunk.filename,
                excerpt=excerpt,
            )
        )
    return citations
