import json
import logging
import re
from html.parser import HTMLParser
from pathlib import Path

from ida_code._search_utils import term_matches
from ida_code.config import IDA_DOCS_DIR, IDA_PYTHON_DIR, IDALIB_PYTHON_DIR

log = logging.getLogger(__name__)

# Lazily-built indexes.
_html_docs: list[tuple[str, str, str]] | None = None  # (title, clean_text, location)
_py_chunks: list[tuple[str, str, str]] | None = None   # (name, body, source_file)


class _HTMLStripper(HTMLParser):
    """Strip HTML tags, keep text content."""

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


def _load_py_chunks() -> list[tuple[str, str, str]]:
    chunks = []
    for py_file in sorted(IDA_PYTHON_DIR.glob("ida_*.py")):
        _parse_py_file(py_file, chunks)
    # Also include idautils.py and idc.py if present.
    for name in ("idautils.py", "idc.py"):
        p = IDA_PYTHON_DIR / name
        if p.exists():
            _parse_py_file(p, chunks)
    # Standalone idalib entry-point: idapro/{__init__,config}.py
    idapro_pkg = IDALIB_PYTHON_DIR / "idapro"
    if idapro_pkg.is_dir():
        for py_file in sorted(idapro_pkg.glob("*.py")):
            _parse_py_file(py_file, chunks, source_name=f"idapro/{py_file.name}")
    return chunks


def _parse_py_file(
    path: Path,
    chunks: list[tuple[str, str, str]],
    source_name: str | None = None,
):
    """Split a Python file into chunks at top-level def/class boundaries."""
    if source_name is None:
        source_name = path.name
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return

    # Find lines that start a new def or class at the top level (no indentation
    # or class-level indentation for methods).
    boundary_pattern = re.compile(r"^(def |class )")
    boundaries: list[int] = []
    for i, line in enumerate(lines):
        if boundary_pattern.match(line):
            boundaries.append(i)

    if not boundaries:
        return

    for idx, start in enumerate(boundaries):
        end = boundaries[idx + 1] if idx + 1 < len(boundaries) else len(lines)
        block = lines[start:end]

        # Extract name from the first line.
        first_line = block[0]
        m = re.match(r"(?:def|class)\s+(\w+)", first_line)
        if not m:
            continue
        name = m.group(1)

        # Skip SWIG internals.
        if name.startswith("_swig"):
            continue

        # Keep a reasonable amount of context: signature + docstring + a few lines.
        body = "\n".join(block[:40])
        chunks.append((name, body, source_name))


def _ensure_indexes():
    global _html_docs, _py_chunks
    if _html_docs is None:
        log.info("Loading HTML docs index from %s", IDA_DOCS_DIR)
        _html_docs = _load_html_docs()
        log.info("Loaded %d HTML doc entries", len(_html_docs))
    if _py_chunks is None:
        log.info("Loading Python API chunks from %s", IDA_PYTHON_DIR)
        _py_chunks = _load_py_chunks()
        log.info("Loaded %d Python API chunks", len(_py_chunks))


def search(
    query: str,
    max_results: int = 5,
    max_snippet_length: int = 150,
    include_examples: bool = True,
) -> dict:
    """Search IDA docs and Python API sources. Returns structured dict."""
    _ensure_indexes()

    terms = query.lower().split()
    if not terms:
        return {"query": query, "results": []}
    log.debug("Searching for terms: %s", terms)

    results: list[tuple[float, str, str, str]] = []  # (score, title, snippet, source)

    # Search HTML docs.
    for title, text, location in _html_docs:
        score = _score(terms, title, text)
        if score > 0:
            snippet = _excerpt(text, terms, max_len=max_snippet_length)
            results.append((score, title, snippet, f"docs: {location}"))

    # Search Python API chunks (name field gets higher weight).
    for name, body, source_file in _py_chunks:
        score = _score_py(terms, name, body)
        if score > 0:
            snippet = _excerpt(body, terms, max_len=max_snippet_length)
            results.append((score, name, snippet, f"python: {source_file}"))

    # Sort by score descending.
    results.sort(key=lambda r: r[0], reverse=True)
    results = results[:max_results]

    result = {
        "query": query,
        "results": [
            {"source": source, "title": title, "snippet": snippet, "score": score}
            for score, title, snippet, source in results
        ],
    }

    # Cross-link: append matching examples if available.
    if include_examples:
        from ida_code.example_search import search as _search_examples

        ex_results = _search_examples(query, max_results=2, max_snippet_lines=5)
        if ex_results["results"]:
            result["related_examples"] = ex_results["results"]

    return result


def _score(terms: list[str], title: str, text: str) -> float:
    """Score a document against search terms with field weighting.

    Title matches score 4.0, body matches score 1.0.
    All-terms-match bonus: 1.5x multiplier.
    """
    total = 0.0
    matched_terms = 0

    title_lower = title.lower()
    text_lower = text.lower()

    for term in terms:
        term_score = 0.0

        # Title match (high value)
        if term_matches(term, title_lower):
            term_score = max(term_score, 4.0)

        # Body match (lower value)
        if term_matches(term, text_lower):
            term_score = max(term_score, 1.0)

        if term_score > 0:
            matched_terms += 1
        total += term_score

    # All-terms-match bonus
    if len(terms) > 1 and matched_terms == len(terms):
        total *= 1.5

    return total


def _score_py(terms: list[str], name: str, body: str) -> float:
    """Score a Python API chunk with name-weighted scoring.

    Name matches score 5.0, body matches score 1.0.
    """
    total = 0.0
    matched_terms = 0

    name_lower = name.lower()
    body_lower = body.lower()

    for term in terms:
        term_score = 0.0

        # Name match (highest value — this IS the API definition)
        if term_matches(term, name_lower):
            term_score = max(term_score, 5.0)

        # Body match
        if term_matches(term, body_lower):
            term_score = max(term_score, 1.0)

        if term_score > 0:
            matched_terms += 1
        total += term_score

    if len(terms) > 1 and matched_terms == len(terms):
        total *= 1.5

    return total


def _excerpt(text: str, terms: list[str], max_len: int = 300) -> str:
    """Extract a snippet around the first matching term."""
    text_lower = text.lower()
    best_pos = len(text)
    for t in terms:
        # Use simple substring find for excerpt positioning
        pos = text_lower.find(t)
        if pos != -1 and pos < best_pos:
            best_pos = pos

    start = max(0, best_pos - 50)
    end = start + max_len
    snippet = text[start:end].strip()

    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."

    # Collapse whitespace.
    snippet = re.sub(r"\s+", " ", snippet)
    return snippet
