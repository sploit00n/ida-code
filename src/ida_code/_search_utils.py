"""Shared search utilities for doc_search and example_search.

Provides word-boundary-aware matching: "set" matches "set_name" and
"ida_name.set_name" but not "reset" or "offset".

Boundaries are: start-of-string, underscore, dot, whitespace.
"""

import re
from functools import lru_cache


@lru_cache(maxsize=128)
def _boundary_pattern(term: str) -> re.Pattern:
    """Regex that matches term at an underscore/dot/whitespace boundary."""
    escaped = re.escape(term)
    return re.compile(rf"(?:^|[_.\s]){escaped}", re.IGNORECASE)


def term_matches(term: str, text: str) -> bool:
    """Check if term appears in text at a word boundary.

    Boundaries are: start-of-string, underscore, dot, whitespace.
    Fast path: rejects via substring check before running regex.

    Dotted terms (e.g. "ida_funcs.get_func") use plain substring
    matching since the dot is already specific enough.
    """
    if term not in text.lower():
        return False
    if "." in term:
        return True  # dotted terms: substring match is sufficient
    return _boundary_pattern(term).search(text) is not None
