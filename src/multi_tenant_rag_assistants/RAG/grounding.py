"""Deterministic citation validation before an answer leaves the backend."""

from __future__ import annotations

import re

from .models import Citation, RetrievedChunk


CITATION_PATTERN = re.compile(r"\[(\d+)]")


def validate_citations(answer: str, chunks: list[RetrievedChunk]) -> list[Citation]:
    numbers = [int(value) for value in CITATION_PATTERN.findall(answer)]
    unique_numbers = list(dict.fromkeys(numbers))
    if not answer or not unique_numbers or any(number < 1 or number > len(chunks) for number in unique_numbers):
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
