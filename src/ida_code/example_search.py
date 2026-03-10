"""Index and search official IDAPython example scripts.

Parses metadata from two sources:
  1. ``index.md`` — structured markdown with titles, descriptions, keywords,
     difficulty levels, categories, and curated "APIs Used" lists.
  2. Each ``.py`` file — ``ast`` module extracts the structured docstring,
     imports, top-level definitions, and ``ida_*`` attribute accesses.

The index is built lazily on first search and cached in a module global.
"""

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from ida_code._search_utils import term_matches
from ida_code.config import IDA_EXAMPLES_DIR

log = logging.getLogger(__name__)

_index: list["ExampleEntry"] | None = None


@dataclass
class ExampleEntry:
    """A single indexed example script."""

    # Identity
    id: str
    filename: str
    rel_path: str
    abs_path: str

    # From index.md
    title: str = ""
    summary: str = ""
    description: str = ""
    level: str = ""
    category: str = ""
    keywords: list[str] = field(default_factory=list)
    apis_used: list[str] = field(default_factory=list)

    # From AST parsing
    imports: list[str] = field(default_factory=list)
    definitions: list[str] = field(default_factory=list)
    api_calls: list[str] = field(default_factory=list)

    # Full source text
    source: str = ""


# ---------------------------------------------------------------------------
# index.md parsing
# ---------------------------------------------------------------------------

# Matches section headers like: ## User interface {#ui}
_CATEGORY_RE = re.compile(r"^##\s+.+?\{#(\w+)\}")

# Matches example headers like: ### Some title {#some_id}
_EXAMPLE_RE = re.compile(r"^###\s+(.+?)\s*\{#(\w+)\}")

# Matches source code table row:
# | [file.py](url) | kw1 kw2 | Level |
_SOURCE_ROW_RE = re.compile(
    r"\|\s*\[([^\]]+)\]\([^)]*\)\s*\|\s*(.*?)\s*\|\s*(\w+)\s*\|"
)

# Matches API lines like: * `ida_kernwin.add_hotkey`
_API_RE = re.compile(r"^\*\s+`([^`]+)`")

# Matches TOC links like: <a href='#add_hotkey'>...</a>
_TOC_LINK_RE = re.compile(r"<a\s+href=['\"]#(\w+)['\"]>")


def _parse_toc_categories(text: str) -> dict[str, str]:
    """Extract id -> category mapping from the TOC tables.

    The TOC section has ``## Category {#cat}`` headers followed by HTML tables
    containing ``<a href='#example_id'>`` links. The detail section later
    (``## Examples list``) has no category headers.
    """
    id_to_cat: dict[str, str] = {}
    current_category = ""

    for line in text.splitlines():
        m = _CATEGORY_RE.match(line)
        if m:
            current_category = m.group(1)
            continue
        # Stop at the flat listing section — everything after is details
        if line.strip() == "## Examples list":
            break
        if current_category:
            for link_match in _TOC_LINK_RE.finditer(line):
                id_to_cat[link_match.group(1)] = current_category

    return id_to_cat


def parse_index_md(text: str) -> dict[str, dict]:
    """Parse index.md into a dict keyed by example id.

    Returns a dict mapping id -> {title, description, keywords, level,
    category, apis_used, source_file}.
    """
    # First pass: build id -> category from the TOC tables
    toc_categories = _parse_toc_categories(text)

    entries: dict[str, dict] = {}
    current_id = ""
    current: dict | None = None
    in_apis = False

    for line in text.splitlines():
        # Detect example block start
        m = _EXAMPLE_RE.match(line)
        if m:
            if current:
                entries[current_id] = current
            title = m.group(1)
            current_id = m.group(2)
            current = {
                "title": title,
                "description": "",
                "keywords": [],
                "level": "",
                "category": toc_categories.get(current_id, ""),
                "apis_used": [],
                "source_file": "",
            }
            in_apis = False
            continue

        if current is None:
            continue

        # Detect APIs Used section
        if line.strip().startswith("**APIs Used:**"):
            in_apis = True
            continue

        # Detect end of block (horizontal rule)
        if line.strip() == "***":
            in_apis = False
            if current:
                entries[current_id] = current
                current = None
            continue

        # Parse API entries
        if in_apis:
            m = _API_RE.match(line.strip())
            if m:
                current["apis_used"].append(m.group(1))
            continue

        # Parse source code table row
        m = _SOURCE_ROW_RE.search(line)
        if m:
            current["source_file"] = m.group(1)
            kw_str = m.group(2).strip()
            if kw_str:
                current["keywords"] = kw_str.split()
            current["level"] = m.group(3).lower()
            continue

        # Accumulate description text (skip table headers and empty lines)
        stripped = line.strip()
        if (
            stripped
            and not stripped.startswith("|")
            and not stripped.startswith("<")
        ):
            if current["description"]:
                current["description"] += " " + stripped
            else:
                current["description"] = stripped

    # Flush last entry
    if current:
        entries[current_id] = current

    return entries


# ---------------------------------------------------------------------------
# Docstring parsing
# ---------------------------------------------------------------------------


def parse_docstring(docstring: str) -> dict[str, str]:
    """Parse a structured IDAPython example docstring.

    Expected format::

        summary: one-line summary
        description:
          multi-line description
        level: beginner
    """
    result: dict[str, str] = {}
    if not docstring:
        return result

    current_key = ""
    current_val: list[str] = []

    for line in docstring.splitlines():
        stripped = line.strip()

        # Try to match a key: value line
        m = re.match(r"^(\w+):\s*(.*)", stripped)
        if m:
            # Save previous key
            if current_key:
                result[current_key] = " ".join(current_val).strip()
            current_key = m.group(1)
            val = m.group(2)
            current_val = [val] if val else []
        elif current_key and stripped:
            current_val.append(stripped)

    if current_key:
        result[current_key] = " ".join(current_val).strip()

    return result


# ---------------------------------------------------------------------------
# AST parsing
# ---------------------------------------------------------------------------


def parse_ast(source: str) -> dict:
    """Extract imports, definitions, and ida_* API calls from source code.

    Returns dict with keys: imports, definitions, api_calls.
    """
    result: dict[str, list[str]] = {
        "imports": [],
        "definitions": [],
        "api_calls": [],
    }

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return result

    for node in ast.walk(tree):
        # Collect imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                result["imports"].append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                result["imports"].append(node.module)

        # Collect top-level function/class definitions
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Only top-level (direct children of Module)
            if _is_top_level(tree, node):
                result["definitions"].append(node.name)

        # Collect ida_* attribute accesses like ida_hexrays.decompile
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id.startswith("ida_"):
                api = f"{node.value.id}.{node.attr}"
                if api not in result["api_calls"]:
                    result["api_calls"].append(api)
            elif isinstance(node.value, ast.Name) and node.value.id in ("idc", "idautils"):
                api = f"{node.value.id}.{node.attr}"
                if api not in result["api_calls"]:
                    result["api_calls"].append(api)

    return result


def _is_top_level(tree: ast.Module, node: ast.AST) -> bool:
    """Check if a node is a direct child of the module body."""
    return node in tree.body


# ---------------------------------------------------------------------------
# Index building
# ---------------------------------------------------------------------------

# Map category directory names to canonical category ids
_DIR_TO_CATEGORY = {
    "ui": "ui",
    "disassembler": "disassembler",
    "decompiler": "decompiler",
    "debugger": "debugger",
    "types": "types",
    "misc": "misc",
}


def _infer_category(rel_path: str) -> str:
    """Infer category from the relative path."""
    parts = Path(rel_path).parts
    if parts:
        return _DIR_TO_CATEGORY.get(parts[0], "misc")
    return "misc"


def _build_index(examples_dir: Path) -> list[ExampleEntry]:
    """Build the full example index from index.md and .py files."""
    entries: list[ExampleEntry] = []

    # Parse index.md if available
    index_md_path = examples_dir / "index.md"
    index_data: dict[str, dict] = {}
    if index_md_path.is_file():
        try:
            index_data = parse_index_md(index_md_path.read_text(errors="replace"))
        except OSError:
            log.warning("Could not read %s", index_md_path)

    # Walk all .py files
    py_files = sorted(examples_dir.rglob("*.py"))
    for py_path in py_files:
        rel_path = py_path.relative_to(examples_dir)
        filename = py_path.stem  # e.g. "vds1"

        try:
            source = py_path.read_text(errors="replace")
        except OSError:
            continue

        entry = ExampleEntry(
            id=filename,
            filename=py_path.name,
            rel_path=str(rel_path),
            abs_path=str(py_path),
            source=source,
            category=_infer_category(str(rel_path)),
        )

        # Merge index.md metadata
        md = index_data.get(filename, {})
        if md:
            entry.title = md.get("title", "")
            entry.description = md.get("description", "")
            entry.keywords = md.get("keywords", [])
            entry.level = md.get("level", "")
            if md.get("category"):
                entry.category = md["category"]
            entry.apis_used = md.get("apis_used", [])

        # Parse docstring
        try:
            tree = ast.parse(source)
            ds = ast.get_docstring(tree)
        except SyntaxError:
            ds = None
        if ds:
            parsed_ds = parse_docstring(ds)
            if not entry.title and parsed_ds.get("summary"):
                entry.title = parsed_ds["summary"]
            entry.summary = parsed_ds.get("summary", "")
            if not entry.description and parsed_ds.get("description"):
                entry.description = parsed_ds["description"]
            if not entry.level and parsed_ds.get("level"):
                entry.level = parsed_ds["level"]

        # Parse AST for imports, definitions, API calls
        ast_info = parse_ast(source)
        entry.imports = ast_info["imports"]
        entry.definitions = ast_info["definitions"]
        entry.api_calls = ast_info["api_calls"]

        entries.append(entry)

    return entries


def _ensure_index():
    global _index
    if _index is None:
        log.info("Building example index from %s", IDA_EXAMPLES_DIR)
        _index = _build_index(IDA_EXAMPLES_DIR)
        log.info("Indexed %d example scripts", len(_index))


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def score_example(entry: ExampleEntry, terms: list[str]) -> float:
    """Score an example against search terms using weighted fields."""
    total = 0.0
    matched_terms = 0

    for term in terms:
        term_score = 0.0
        t = term.lower()

        # API match: apis_used (curated from index.md)
        for api in entry.apis_used:
            if term_matches(t, api.lower()):
                term_score = max(term_score, 5.0)
                break

        # API match: api_calls (AST-derived)
        for api in entry.api_calls:
            if term_matches(t, api.lower()):
                term_score = max(term_score, 4.0)
                break

        # Title match
        if term_matches(t, entry.title.lower()):
            term_score = max(term_score, 4.0)

        # Keyword match
        for kw in entry.keywords:
            if term_matches(t, kw.lower()):
                term_score = max(term_score, 3.0)
                break

        # Summary match
        if term_matches(t, entry.summary.lower()):
            term_score = max(term_score, 3.0)

        # Import match
        for imp in entry.imports:
            if term_matches(t, imp.lower()):
                term_score = max(term_score, 2.0)
                break

        # Description match
        if term_matches(t, entry.description.lower()):
            term_score = max(term_score, 1.5)

        # Definition match
        for defn in entry.definitions:
            if term_matches(t, defn.lower()):
                term_score = max(term_score, 1.5)
                break

        # Source fallback (uses plain substring — source is too large for boundary matching)
        if term_score == 0 and t in entry.source.lower():
            term_score = 0.5

        if term_score > 0:
            matched_terms += 1
        total += term_score

    # All-terms-match bonus
    if len(terms) > 1 and matched_terms == len(terms):
        total *= 1.5

    return total


# ---------------------------------------------------------------------------
# Snippet extraction
# ---------------------------------------------------------------------------


def extract_snippet(source: str, terms: list[str], max_lines: int = 15) -> str:
    """Extract a relevant snippet from source, skipping the module docstring."""
    lines = source.splitlines()
    if not lines:
        return ""

    # Skip the docstring: find where it ends
    start_line = _find_docstring_end(source)

    code_lines = lines[start_line:]
    if not code_lines:
        code_lines = lines  # fallback to full source

    if not terms:
        snippet = code_lines[:max_lines]
        return "\n".join(snippet)

    # Find the line with the best term overlap
    best_idx = 0
    best_count = 0
    for i, line in enumerate(code_lines):
        lower = line.lower()
        count = sum(1 for t in terms if term_matches(t.lower(), lower))
        if count > best_count:
            best_count = count
            best_idx = i

    # Window around the best line
    half = max_lines // 2
    win_start = max(0, best_idx - half)
    win_end = min(len(code_lines), win_start + max_lines)
    # Adjust start if we're near the end
    if win_end - win_start < max_lines:
        win_start = max(0, win_end - max_lines)

    snippet_lines = code_lines[win_start:win_end]
    return "\n".join(snippet_lines)


def _find_docstring_end(source: str) -> int:
    """Return the line number (0-based) where the module docstring ends."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0

    if not tree.body:
        return 0

    first = tree.body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
        # end_lineno is 1-based, we want the next line (0-based)
        return first.end_lineno
    return 0


# ---------------------------------------------------------------------------
# Public search API
# ---------------------------------------------------------------------------


def search(
    query: str,
    max_results: int = 5,
    category: str = "",
    level: str = "",
    max_snippet_lines: int = 10,
) -> dict:
    """Search example scripts and return structured dict."""
    _ensure_index()

    terms = query.lower().split()
    if not terms:
        return {"query": query, "results": []}

    results: list[tuple[float, ExampleEntry]] = []

    for entry in _index:
        # Apply filters
        if category and entry.category != category.lower():
            continue
        if level and entry.level != level.lower():
            continue

        s = score_example(entry, terms)
        if s > 0:
            results.append((s, entry))

    results.sort(key=lambda r: r[0], reverse=True)
    results = results[:max_results]

    return {
        "query": query,
        "results": [
            {
                "title": entry.title or entry.filename,
                "file": entry.rel_path,
                "level": entry.level,
                "category": entry.category,
                "summary": entry.summary,
                "apis": entry.apis_used[:10],
                "snippet": extract_snippet(entry.source, terms, max_lines=max_snippet_lines),
                "score": score,
            }
            for score, entry in results
        ],
    }
