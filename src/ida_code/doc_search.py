"""Keyword search over IDA HTML documentation.

Indexes the pre-built ``search_index.json`` manifest IDA ships in
``IDA_DOCS_DIR/search/``. Python source (library APIs + example scripts)
lives in ``code_search.py`` instead — see the cross-link below.
"""

import json
import logging
from html.parser import HTMLParser

from ida_code._search_utils import term_matches
from ida_code.config import IDA_DOCS_DIR

log = logging.getLogger(__name__)

_html_docs: list[tuple[str, str, str]] | None = None  # (title, clean_text, location)


class _HTMLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self._parts: list[str] = []

    def handle_data(self, data: str):
        self._parts.append(data)

    def get_text(self) -> str:
        return "".join(self._parts)


def _strip_html(html: str) -> str:
    s = _HTMLStripper()
    s.feed(html)
    return s.get_text()


def _load_html_docs() -> list[tuple[str, str, str]]:
    index_path = IDA_DOCS_DIR / "search" / "search_index.json"
    with open(index_path) as f:
        data = json.load(f)

    entries = []
    for doc in data["docs"]:
        title = doc.get("title", "")
        text = _strip_html(doc.get("text", ""))
        location = doc.get("location", "")
        if title or text:
            entries.append((title, text, location))
    return entries


def _ensure_indexes():
    global _html_docs
    if _html_docs is None:
        log.info("Loading HTML docs index from %s", IDA_DOCS_DIR)
        _html_docs = _load_html_docs()
        log.info("Loaded %d HTML doc entries", len(_html_docs))


def search(
    query: str,
    max_results: int = 5,
    max_snippet_length: int = 150,
    include_examples: bool = True,
) -> dict:
    """Search IDA HTML documentation. Returns a structured dict.

    When ``include_examples=True`` (default) the result also carries a
    ``related_examples`` list — top-2 hits from ``code_search`` filtered to
    ``kind="example"``. Library API definitions are not cross-linked here;
    callers wanting those should use ``search_code`` directly.
    """
    _ensure_indexes()

    terms = query.lower().split()
    if not terms:
        return {"query": query, "results": []}
    log.debug("Searching for terms: %s", terms)

    results: list[tuple[float, str, str, str]] = []  # (score, title, snippet, source)

    for title, text, location in _html_docs:
        score = _score(terms, title, text)
        if score > 0:
            snippet = _excerpt(text, terms, max_len=max_snippet_length)
            results.append((score, title, snippet, f"docs: {location}"))

    results.sort(key=lambda r: r[0], reverse=True)
    results = results[:max_results]

    result = {
        "query": query,
        "results": [
            {"source": source, "title": title, "snippet": snippet, "score": score}
            for score, title, snippet, source in results
        ],
    }

    if include_examples:
        # Lazy import to avoid a circular dependency at module-load time —
        # code_search.search() also imports doc_search.search() for its own
        # cross-link.
        from ida_code.code_search import search as _search_code

        ex = _search_code(
            query, max_results=2, kind="example", max_snippet_lines=5,
            include_docs=False,
        )
        if ex.get("results"):
            result["related_examples"] = ex["results"]

    return result


def _score(terms: list[str], title: str, text: str) -> float:
    """Score a document. Title matches 4.0, body matches 1.0, all-terms bonus 1.5x."""
    total = 0.0
    matched_terms = 0

    title_lower = title.lower()
    text_lower = text.lower()

    for term in terms:
        term_score = 0.0
        if term_matches(term, title_lower):
            term_score = max(term_score, 4.0)
        if term_matches(term, text_lower):
            term_score = max(term_score, 1.0)

        if term_score > 0:
            matched_terms += 1
        total += term_score

    if len(terms) > 1 and matched_terms == len(terms):
        total *= 1.5

    return total


def _excerpt(text: str, terms: list[str], max_len: int = 300) -> str:
    """Extract a snippet of *text* around the first matching term."""
    if not text:
        return ""

    lowered = text.lower()
    best_pos = -1
    for term in terms:
        pos = lowered.find(term)
        if pos != -1 and (best_pos == -1 or pos < best_pos):
            best_pos = pos

    if best_pos == -1:
        snippet = text[:max_len]
    else:
        half = max_len // 2
        start = max(0, best_pos - half)
        end = min(len(text), start + max_len)
        if end - start < max_len:
            start = max(0, end - max_len)
        snippet = text[start:end]
        if start > 0:
            snippet = "..." + snippet
        if end < len(text):
            snippet = snippet + "..."

    # Collapse whitespace for readability.
    return " ".join(snippet.split())
