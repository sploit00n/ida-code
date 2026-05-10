"""Unified search over Python source: library APIs + example scripts.

Two corpora share one index and one search function:

- **Library** chunks: top-level ``def``/``class`` from ``python/ida_*.py``,
  ``idautils.py``, ``idc.py``, and ``idalib/python/idapro/*.py``. AST-parsed
  per file; each chunk gets its name, docstring, and surrounding source.
- **Example** scripts: full files from ``python/examples/`` (with the
  curated ``index.md`` metadata) and ``idalib/examples/`` (no manifest,
  AST-only metadata).

The index is built lazily on first search and cached in a module global.
"""

import ast
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from ida_code._search_utils import term_matches
from ida_code.config import (
    IDA_EXAMPLES_DIR,
    IDA_PYTHON_DIR,
    IDALIB_EXAMPLES_DIR,
    IDALIB_PYTHON_DIR,
)

log = logging.getLogger(__name__)

_index: list["CodeEntry"] | None = None

# Module names whose imports are stripped from the displayed `imports` field
# in results — they're noise (stdlib, ida runtime). idapro is intentionally
# *not* in this set: it's the standalone-idalib entry point and users
# searching `imports=idapro` expect to see it in the result.
_STDLIB_NAMES = frozenset(sys.stdlib_module_names)
_BUILTIN_IDA_MODULES = frozenset({"idc", "idaapi", "idautils"})


@dataclass
class CodeEntry:
    """One indexed entity — either a library chunk or an example script."""

    kind: str                         # "library" | "example"
    title: str = ""                   # func/class name (library) or example title
    file: str = ""                    # display path, e.g. "idapro/__init__.py"
    abs_path: str = ""
    source: str = ""                  # chunk source (library) or full file (example)
    docstring: str = ""               # extracted docstring (both kinds)

    # File position metadata — used to translate snippet windows into
    # absolute file line numbers so the LLM can call get_source(file, N).
    # Library entries: file_start_line = the def's line in the file.
    # Example entries: file_start_line = 1 (source IS the file).
    file_start_line: int = 1          # 1-based line of source[0] in the file
    file_total_lines: int = 0         # total lines of the source FILE (not chunk)

    # Example-only fields (library entries leave these empty).
    summary: str = ""
    description: str = ""
    level: str = ""
    category: str = ""
    keywords: list[str] = field(default_factory=list)
    apis_used: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    definitions: list[str] = field(default_factory=list)
    api_calls: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# index.md parsing (curated example metadata)
# ---------------------------------------------------------------------------

_CATEGORY_RE = re.compile(r"^##\s+.+?\{#(\w+)\}")
_EXAMPLE_RE = re.compile(r"^###\s+(.+?)\s*\{#(\w+)\}")
_SOURCE_ROW_RE = re.compile(
    r"\|\s*\[([^\]]+)\]\([^)]*\)\s*\|\s*(.*?)\s*\|\s*(\w+)\s*\|"
)
_API_RE = re.compile(r"^\*\s+`([^`]+)`")
_TOC_LINK_RE = re.compile(r"<a\s+href=['\"]#(\w+)['\"]>")


def _parse_toc_categories(text: str) -> dict[str, str]:
    id_to_cat: dict[str, str] = {}
    current_category = ""
    for line in text.splitlines():
        m = _CATEGORY_RE.match(line)
        if m:
            current_category = m.group(1)
            continue
        if line.strip() == "## Examples list":
            break
        if current_category:
            for link_match in _TOC_LINK_RE.finditer(line):
                id_to_cat[link_match.group(1)] = current_category
    return id_to_cat


def parse_index_md(text: str) -> dict[str, dict]:
    """Parse index.md into a dict keyed by example id."""
    toc_categories = _parse_toc_categories(text)
    entries: dict[str, dict] = {}
    current_id = ""
    current: dict | None = None
    in_apis = False

    for line in text.splitlines():
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

        if line.strip().startswith("**APIs Used:**"):
            in_apis = True
            continue

        if line.strip() == "***":
            in_apis = False
            if current:
                entries[current_id] = current
                current = None
            continue

        if in_apis:
            m = _API_RE.match(line.strip())
            if m:
                current["apis_used"].append(m.group(1))
            continue

        m = _SOURCE_ROW_RE.search(line)
        if m:
            current["source_file"] = m.group(1)
            kw_str = m.group(2).strip()
            if kw_str:
                current["keywords"] = kw_str.split()
            current["level"] = m.group(3).lower()
            continue

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

    if current:
        entries[current_id] = current

    return entries


def parse_docstring(docstring: str) -> dict[str, str]:
    """Parse a structured IDAPython example docstring (summary/description/level)."""
    result: dict[str, str] = {}
    if not docstring:
        return result

    current_key = ""
    current_val: list[str] = []

    for line in docstring.splitlines():
        stripped = line.strip()
        m = re.match(r"^(\w+):\s*(.*)", stripped)
        if m:
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
    """Extract imports, top-level definitions, and ida_* API calls."""
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
        if isinstance(node, ast.Import):
            for alias in node.names:
                result["imports"].append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                result["imports"].append(node.module)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node in tree.body:
                result["definitions"].append(node.name)
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and (
                node.value.id.startswith("ida_") or node.value.id in ("idc", "idautils")
            ):
                api = f"{node.value.id}.{node.attr}"
                if api not in result["api_calls"]:
                    result["api_calls"].append(api)

    return result


# ---------------------------------------------------------------------------
# Index: example side
# ---------------------------------------------------------------------------

_DIR_TO_CATEGORY = {
    "ui": "ui",
    "disassembler": "disassembler",
    "decompiler": "decompiler",
    "debugger": "debugger",
    "types": "types",
    "misc": "misc",
}


def _infer_category(rel_path: str) -> str:
    parts = Path(rel_path).parts
    if parts:
        return _DIR_TO_CATEGORY.get(parts[0], "misc")
    return "misc"


def _build_example_index(examples_dir: Path) -> list[CodeEntry]:
    """Walk examples_dir, build CodeEntry list with kind='example'.

    Skips silently if the dir doesn't exist (idalib/examples may be absent).
    """
    entries: list[CodeEntry] = []
    if not examples_dir.is_dir():
        return entries

    index_md_path = examples_dir / "index.md"
    index_data: dict[str, dict] = {}
    if index_md_path.is_file():
        try:
            index_data = parse_index_md(index_md_path.read_text(errors="replace"))
        except OSError:
            log.warning("Could not read %s", index_md_path)

    for py_path in sorted(examples_dir.rglob("*.py")):
        rel_path = py_path.relative_to(examples_dir)
        filename = py_path.stem

        try:
            source = py_path.read_text(errors="replace")
        except OSError:
            continue

        entry = CodeEntry(
            kind="example",
            file=str(rel_path),
            abs_path=str(py_path),
            source=source,
            category=_infer_category(str(rel_path)),
            file_start_line=1,
            file_total_lines=len(source.splitlines()),
        )
        # Track the original filename for snippet display
        entry.title = ""

        md = index_data.get(filename, {})
        if md:
            entry.title = md.get("title", "")
            entry.description = md.get("description", "")
            entry.keywords = md.get("keywords", [])
            entry.level = md.get("level", "")
            if md.get("category"):
                entry.category = md["category"]
            entry.apis_used = md.get("apis_used", [])

        try:
            tree = ast.parse(source)
            ds = ast.get_docstring(tree)
        except SyntaxError:
            ds = None
        if ds:
            entry.docstring = ds
            parsed_ds = parse_docstring(ds)
            if not entry.title and parsed_ds.get("summary"):
                entry.title = parsed_ds["summary"]
            entry.summary = parsed_ds.get("summary", "")
            if not entry.description and parsed_ds.get("description"):
                entry.description = parsed_ds["description"]
            if not entry.level and parsed_ds.get("level"):
                entry.level = parsed_ds["level"]

        ast_info = parse_ast(source)
        entry.imports = ast_info["imports"]
        entry.definitions = ast_info["definitions"]
        entry.api_calls = ast_info["api_calls"]

        # Title fallback: filename if nothing set
        if not entry.title:
            entry.title = py_path.name

        entries.append(entry)

    return entries


# ---------------------------------------------------------------------------
# Index: library side (AST-based chunker, replaces the old regex chunker)
# ---------------------------------------------------------------------------


def _build_library_index() -> list[CodeEntry]:
    """Index top-level def/class chunks from IDA's Python API + idapro module."""
    entries: list[CodeEntry] = []

    # IDAPython API: ida_*.py + idautils.py + idc.py
    if IDA_PYTHON_DIR.is_dir():
        for py_path in sorted(IDA_PYTHON_DIR.glob("ida_*.py")):
            _index_library_file(py_path, py_path.name, entries)
        for name in ("idautils.py", "idc.py"):
            p = IDA_PYTHON_DIR / name
            if p.is_file():
                _index_library_file(p, name, entries)

    # Standalone idalib: idapro package
    idapro_pkg = IDALIB_PYTHON_DIR / "idapro"
    if idapro_pkg.is_dir():
        for py_path in sorted(idapro_pkg.glob("*.py")):
            _index_library_file(py_path, f"idapro/{py_path.name}", entries)

    return entries


def _index_library_file(path: Path, display_name: str, entries: list[CodeEntry]) -> None:
    """Parse one library .py file and append a CodeEntry per top-level def/class."""
    try:
        source = path.read_text(errors="replace")
    except OSError:
        return
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return

    # Module-level imports (used for the imports filter on library entries).
    module_imports: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                module_imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                module_imports.append(node.module)

    src_lines = source.splitlines()
    file_total_lines = len(src_lines)

    # Collect top-level FunctionDef / ClassDef nodes in order.
    chunk_starts: list[tuple[int, ast.AST]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            chunk_starts.append((node.lineno - 1, node))  # 0-based

    if not chunk_starts:
        return

    for idx, (start, node) in enumerate(chunk_starts):
        end = chunk_starts[idx + 1][0] if idx + 1 < len(chunk_starts) else len(src_lines)
        # Skip SWIG internals.
        if node.name.startswith("_swig"):
            continue

        chunk_source = "\n".join(src_lines[start:end])
        docstring = ast.get_docstring(node) or ""

        entries.append(CodeEntry(
            kind="library",
            title=node.name,
            file=display_name,
            abs_path=str(path),
            source=chunk_source,
            docstring=docstring,
            imports=module_imports,
            file_start_line=node.lineno,  # 1-based line of the def in the file
            file_total_lines=file_total_lines,
        ))


# ---------------------------------------------------------------------------
# Lazy index init
# ---------------------------------------------------------------------------


def _ensure_index() -> None:
    global _index
    if _index is not None:
        return
    log.info("Building code index (libraries + examples)")
    libs = _build_library_index()
    examples = _build_example_index(IDA_EXAMPLES_DIR) + _build_example_index(IDALIB_EXAMPLES_DIR)
    _index = libs + examples
    log.info(
        "Indexed %d code entries (%d library chunks, %d example scripts)",
        len(_index), len(libs), len(examples),
    )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def score_library(entry: CodeEntry, terms: list[str], docstring_only: bool = False) -> float:
    """Score a library chunk: name 5x, docstring 3x, body (excl. docstring) 1x.

    ``docstring_only=True`` restricts scoring to the docstring only —
    useful for "find a function that DOES X" queries where identifier hits
    are noise.
    """
    name_lower = "" if docstring_only else entry.title.lower()
    doc_lower = entry.docstring.lower()
    if docstring_only:
        body = ""
    elif entry.docstring:
        body = entry.source.replace(entry.docstring, "", 1).lower()
    else:
        body = entry.source.lower()

    total = 0.0
    matched = 0
    for term in terms:
        t = term.lower()
        score = 0.0
        if name_lower and term_matches(t, name_lower):
            score = max(score, 5.0)
        if doc_lower and term_matches(t, doc_lower):
            score = max(score, 3.0)
        if body and term_matches(t, body):
            score = max(score, 1.0)
        if score > 0:
            matched += 1
        total += score

    if len(terms) > 1 and matched == len(terms):
        total *= 1.5
    return total


def score_example(entry: CodeEntry, terms: list[str], docstring_only: bool = False) -> float:
    """Score an example against search terms using weighted fields.

    ``docstring_only=True`` restricts scoring to the parsed docstring
    fields (summary, description) — same intent as ``score_library``.
    """
    total = 0.0
    matched_terms = 0

    for term in terms:
        term_score = 0.0
        t = term.lower()

        if not docstring_only:
            for api in entry.apis_used:
                if term_matches(t, api.lower()):
                    term_score = max(term_score, 5.0)
                    break
            for api in entry.api_calls:
                if term_matches(t, api.lower()):
                    term_score = max(term_score, 4.0)
                    break
            if term_matches(t, entry.title.lower()):
                term_score = max(term_score, 4.0)
            for kw in entry.keywords:
                if term_matches(t, kw.lower()):
                    term_score = max(term_score, 3.0)
                    break

        # Summary/description always count — they ARE the docstring.
        if term_matches(t, entry.summary.lower()):
            term_score = max(term_score, 3.0)

        if not docstring_only:
            for imp in entry.imports:
                if term_matches(t, imp.lower()):
                    term_score = max(term_score, 2.0)
                    break

        if term_matches(t, entry.description.lower()):
            term_score = max(term_score, 1.5)

        if not docstring_only:
            for defn in entry.definitions:
                if term_matches(t, defn.lower()):
                    term_score = max(term_score, 1.5)
                    break
            if term_score == 0 and t in entry.source.lower():
                term_score = 0.5

        if term_score > 0:
            matched_terms += 1
        total += term_score

    if len(terms) > 1 and matched_terms == len(terms):
        total *= 1.5

    return total


# ---------------------------------------------------------------------------
# Snippet extraction
# ---------------------------------------------------------------------------


def extract_snippet(
    source: str, terms: list[str], max_lines: int = 15,
    max_line_chars: int = 200, *,
    skip_module_docstring: bool = True,
) -> tuple[str, int, int]:
    """Window into *source* around the line best matching *terms*.

    Returns ``(text, source_window_start, length)`` — a 0-based line offset
    within the input source plus the snippet's line count. The caller
    translates ``source_window_start`` to an absolute file line using the
    entry's ``file_start_line``.

    Per-line cap: ``max_line_chars`` truncates each line with ``...`` when
    it exceeds the limit. Set to 0 to disable.

    Module docstrings are stripped by default (example case). Library chunks
    pass ``skip_module_docstring=False`` to keep the def signature + docstring
    visible.
    """
    lines = source.splitlines()
    if not lines:
        return "", 0, 0

    skipped = _find_module_docstring_end(source) if skip_module_docstring else 0
    code_lines = lines[skipped:] or lines
    if code_lines is lines:
        skipped = 0

    if not terms:
        win_start = 0
    else:
        best_idx = 0
        best_count = 0
        for i, line in enumerate(code_lines):
            lower = line.lower()
            count = sum(1 for t in terms if term_matches(t.lower(), lower))
            if count > best_count:
                best_count = count
                best_idx = i

        half = max_lines // 2
        win_start = max(0, best_idx - half)

    win_end = min(len(code_lines), win_start + max_lines)
    if win_end - win_start < max_lines:
        win_start = max(0, win_end - max_lines)

    snippet_lines = code_lines[win_start:win_end]
    if max_line_chars and max_line_chars > 3:
        snippet_lines = [
            (ln[: max_line_chars - 3] + "...") if len(ln) > max_line_chars else ln
            for ln in snippet_lines
        ]

    text = "\n".join(snippet_lines)
    return text, skipped + win_start, len(snippet_lines)


def _find_module_docstring_end(source: str) -> int:
    """Return the line number (0-based) where the module docstring ends."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0
    if not tree.body:
        return 0
    first = tree.body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
        return first.end_lineno
    return 0


# ---------------------------------------------------------------------------
# Imports display filter
# ---------------------------------------------------------------------------


def _filter_imports_for_display(imports: list[str]) -> list[str]:
    """Drop stdlib + ida_* runtime modules; keep third-party libs (idapro, lief, ...)."""
    interesting: list[str] = []
    seen: set[str] = set()
    for m in imports:
        if m in seen:
            continue
        seen.add(m)
        top = m.split(".")[0]
        if top.startswith("ida_") or top.startswith("_ida_"):
            continue
        if top in _BUILTIN_IDA_MODULES:
            continue
        if top in _STDLIB_NAMES:
            continue
        interesting.append(m)
    return interesting


# ---------------------------------------------------------------------------
# Public search API
# ---------------------------------------------------------------------------


def search(
    query: str,
    max_results: int = 5,
    kind: str = "",
    imports: str = "",
    category: str = "",
    level: str = "",
    max_snippet_lines: int = 10,
    max_snippet_line_chars: int = 200,
    docstring_only: bool = False,
    include_docs: bool = True,
) -> dict:
    """Search the unified code index. See `server.search_code` for full docs."""
    _ensure_index()

    terms = query.lower().split()
    if not terms:
        return {"query": query, "results": []}

    # Normalize filter inputs.
    kind_filter = kind.strip().lower()
    imports_filter = imports.strip()
    category_filter = category.strip().lower()
    level_filter = level.strip().lower()

    scored: list[tuple[float, CodeEntry]] = []

    for entry in _index:
        if kind_filter and entry.kind != kind_filter:
            continue

        if imports_filter:
            imports_lower = imports_filter.lower()
            if not any(term_matches(imports_lower, m.lower()) for m in entry.imports):
                continue

        if entry.kind == "example":
            if category_filter and entry.category.lower() != category_filter:
                continue
            if level_filter and entry.level.lower() != level_filter:
                continue

        if entry.kind == "library":
            s = score_library(entry, terms, docstring_only=docstring_only)
        else:
            s = score_example(entry, terms, docstring_only=docstring_only)
        if s > 0:
            scored.append((s, entry))

    scored.sort(key=lambda r: r[0], reverse=True)
    scored = scored[:max_results]

    results = [
        _to_result_dict(e, terms, max_snippet_lines, max_snippet_line_chars)
        for _, e in scored
    ]
    # When the caller restricted to a single kind, every result has the same
    # value — drop it from each entry to save tokens.
    if kind_filter:
        for r in results:
            r.pop("kind", None)

    out = {"query": query, "results": results}

    if include_docs:
        from ida_code.doc_search import search as _search_docs
        doc_res = _search_docs(query, max_results=2, max_snippet_length=200, include_examples=False)
        if doc_res.get("results"):
            out["related_docs"] = doc_res["results"]

    return out


def _to_result_dict(
    entry: CodeEntry, terms: list[str], max_lines: int, max_line_chars: int,
) -> dict:
    """Build a result dict, omitting fields that carry no signal.

    Token-efficiency rules:
      - empty strings/lists are dropped (level/category/summary/imports)
      - ``score`` is sort-only, never emitted (LLMs don't use it)
      - ``apis`` is dropped — redundant with the snippet
      - ``title`` is dropped when it equals the file's basename
        (un-curated examples like ``idacli.py``)
      - ``snippet_start_line`` + ``total_lines`` only emitted when the
        snippet doesn't cover the whole file/chunk — otherwise no fetch
        needed

    The caller may further drop ``kind`` after the fact if it filtered to a
    single kind (every result would carry the same value).
    """
    skip_module = entry.kind == "example"
    text, src_win_start, snippet_length = extract_snippet(
        entry.source, terms,
        max_lines=max_lines, max_line_chars=max_line_chars,
        skip_module_docstring=skip_module,
    )

    # Translate source-window start to absolute file line (1-based).
    file_snippet_start = entry.file_start_line + src_win_start
    src_win_end = src_win_start + snippet_length
    source_total_lines = len(entry.source.splitlines())
    truncated = (
        src_win_start > 0
        or src_win_end < source_total_lines
        or entry.file_total_lines > (entry.file_start_line - 1) + source_total_lines
    )

    if entry.kind == "library":
        out: dict = {
            "kind": "library",
            "title": entry.title,
            "file": entry.file,
            "snippet": text,
        }
    else:
        out = {
            "kind": "example",
            "file": entry.file,
            "snippet": text,
        }
        if entry.title and entry.title != Path(entry.file).name:
            out["title"] = entry.title
        if entry.level:
            out["level"] = entry.level
        if entry.category:
            out["category"] = entry.category
        if entry.summary:
            out["summary"] = entry.summary
        filtered_imports = _filter_imports_for_display(entry.imports)
        if filtered_imports:
            out["imports"] = filtered_imports

    if truncated:
        out["snippet_start_line"] = file_snippet_start
        out["total_lines"] = entry.file_total_lines
        # Hint pair: file + start line is what get_source needs to fetch more.

    return out
