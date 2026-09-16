"""Small deterministic behavior-clustering helpers."""

from __future__ import annotations


def similarity(left: set[str] | frozenset[str], right: set[str] | frozenset[str]) -> float:
    a = set(left)
    b = set(right)
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def cluster(behaviors: list[frozenset[str]], threshold: float = 0.6) -> list[list[int]]:
    """Group behavior observations using deterministic Jaccard similarity."""
    groups: list[list[int]] = []
    for index, item in enumerate(behaviors):
        target = None
        for group in groups:
            representative = behaviors[group[0]]
            if similarity(item, representative) >= threshold:
                target = group
                break
        if target is None:
            groups.append([index])
        else:
            target.append(index)
    return groups
