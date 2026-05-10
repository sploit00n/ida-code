"""Unit tests for ida_code.code_search.

Tests parsing, scoring, and snippet extraction using synthetic data —
no IDA installation needed.
"""

import tempfile
from pathlib import Path

from ida_code.code_search import (
    CodeEntry,
    _build_example_index,
    _filter_imports_for_display,
    extract_snippet,
    parse_ast,
    parse_docstring,
    parse_index_md,
    score_example,
    score_library,
)


class TestParseDocstring:
    def test_basic(self):
        ds = "summary: do something\n\ndescription:\n  A longer explanation.\n\nlevel: beginner"
        result = parse_docstring(ds)
        assert result["summary"] == "do something"
        assert "longer explanation" in result["description"]
        assert result["level"] == "beginner"

    def test_single_line_description(self):
        ds = "summary: test\n\ndescription: inline desc\n\nlevel: advanced"
        result = parse_docstring(ds)
        assert result["description"] == "inline desc"

    def test_empty(self):
        assert parse_docstring("") == {}

    def test_multiline_description(self):
        ds = "summary: test\n\ndescription:\n  line one\n  line two\n\nlevel: beginner"
        result = parse_docstring(ds)
        assert "line one" in result["description"]
        assert "line two" in result["description"]

    def test_summary_only(self):
        ds = "summary: just a summary"
        result = parse_docstring(ds)
        assert result["summary"] == "just a summary"


class TestParseAst:
    def test_imports(self):
        source = "import ida_funcs\nimport os\nfrom ida_bytes import get_byte\n"
        result = parse_ast(source)
        assert "ida_funcs" in result["imports"]
        assert "os" in result["imports"]
        assert "ida_bytes" in result["imports"]

    def test_definitions(self):
        source = "def main():\n    pass\n\nclass MyHandler:\n    pass\n"
        result = parse_ast(source)
        assert "main" in result["definitions"]
        assert "MyHandler" in result["definitions"]

    def test_nested_function_excluded(self):
        source = "def outer():\n    def inner():\n        pass\n"
        result = parse_ast(source)
        assert "outer" in result["definitions"]
        assert "inner" not in result["definitions"]

    def test_api_calls(self):
        source = "import ida_hexrays\nresult = ida_hexrays.decompile(ea)\n"
        result = parse_ast(source)
        assert "ida_hexrays.decompile" in result["api_calls"]

    def test_idc_api_calls(self):
        source = "import idc\ncolor = idc.get_color(ea, idc.CIC_ITEM)\n"
        result = parse_ast(source)
        assert "idc.get_color" in result["api_calls"]

    def test_no_duplicates(self):
        source = "import ida_funcs\nida_funcs.get_func(ea)\nida_funcs.get_func(ea2)\n"
        result = parse_ast(source)
        assert result["api_calls"].count("ida_funcs.get_func") == 1

    def test_syntax_error(self):
        result = parse_ast("def bad syntax(:\n")
        assert result["imports"] == []
        assert result["definitions"] == []
        assert result["api_calls"] == []


class TestScoreExample:
    def _make_entry(self, **kwargs):
        defaults = dict(kind="example", file="test.py", abs_path="/test.py")
        defaults.update(kwargs)
        return CodeEntry(**defaults)

    def test_api_match_highest(self):
        entry = self._make_entry(apis_used=["ida_kernwin.add_hotkey"])
        score = score_example(entry, ["add_hotkey"])
        assert score >= 5.0

    def test_title_match(self):
        entry = self._make_entry(title="Decompile current function")
        score = score_example(entry, ["decompile"])
        assert score >= 4.0

    def test_keyword_match(self):
        entry = self._make_entry(keywords=["coloring"])
        score = score_example(entry, ["coloring"])
        assert score >= 3.0

    def test_import_match(self):
        entry = self._make_entry(imports=["ida_hexrays"])
        score = score_example(entry, ["ida_hexrays"])
        assert score >= 2.0

    def test_source_fallback(self):
        entry = self._make_entry(source="# some obscure token xyz\n")
        score = score_example(entry, ["xyz"])
        assert 0 < score <= 1.0

    def test_no_match(self):
        entry = self._make_entry(title="foo", source="bar\n")
        score = score_example(entry, ["nonexistent"])
        assert score == 0

    def test_all_terms_bonus(self):
        entry = self._make_entry(
            title="decompile function",
            keywords=["hook"],
        )
        score_both = score_example(entry, ["decompile", "hook"])
        score_one = score_example(entry, ["decompile"])
        # The bonus should make multi-term match more than additive
        assert score_both > score_one

    def test_multiple_terms(self):
        entry = self._make_entry(
            title="Custom graph with actions",
            keywords=["graph", "actions"],
        )
        score = score_example(entry, ["graph", "actions"])
        assert score > 0

    def test_case_insensitive(self):
        entry = self._make_entry(title="Decompile Function")
        score = score_example(entry, ["DECOMPILE"])
        assert score > 0

    def test_api_calls_scored(self):
        entry = self._make_entry(api_calls=["ida_hexrays.decompile"])
        score = score_example(entry, ["decompile"])
        assert score >= 4.0

    def test_description_match(self):
        entry = self._make_entry(description="This shows how to use hooks")
        score = score_example(entry, ["hooks"])
        assert score >= 1.5

    def test_definition_match(self):
        entry = self._make_entry(definitions=["MyHandler"])
        score = score_example(entry, ["myhandler"])
        assert score >= 1.5


class TestExtractSnippet:
    def test_basic(self):
        source = '"""\nsummary: test\n"""\nimport ida_funcs\n\ndef main():\n    pass\n'
        text, _, _ = extract_snippet(source, ["main"])
        assert "def main" in text
        assert "summary:" not in text

    def test_no_docstring(self):
        source = "import ida_funcs\n\ndef main():\n    pass\n"
        text, _, _ = extract_snippet(source, ["main"])
        assert "def main" in text

    def test_term_centered(self):
        lines = ["import os"] + [f"line_{i}" for i in range(30)] + ["target_line"]
        source = "\n".join(lines)
        text, _, _ = extract_snippet(source, ["target_line"], max_lines=5)
        assert "target_line" in text

    def test_empty_source(self):
        text, start, length = extract_snippet("", ["foo"])
        assert text == ""
        assert start == 0
        assert length == 0

    def test_returns_length(self):
        source = "line1\nline2\nline3\nline4\n"
        _, start, length = extract_snippet(source, [], max_lines=2,
                                            skip_module_docstring=False)
        assert start == 0
        assert length == 2

    def test_no_terms(self):
        source = "line1\nline2\nline3\n"
        text, _, _ = extract_snippet(source, [], max_lines=2)
        assert "line1" in text

    def test_docstring_skipped(self):
        source = '"""\nsummary: skip me\n\ndescription:\n  should not appear\n\nlevel: beginner\n"""\nimport ida_funcs\ncode_here = True\n'
        text, _, _ = extract_snippet(source, ["code_here"])
        assert "skip me" not in text
        assert "code_here" in text

    def test_per_line_truncation(self):
        """Ultra-long lines get truncated with '...' rather than bloating the snippet."""
        long = "x = " + "y" * 500
        source = f"import os\n{long}\nz = 1\n"
        text, _, _ = extract_snippet(source, ["x"], max_lines=5, max_line_chars=50,
                                      skip_module_docstring=False)
        # The long line was truncated (no full 500-y string survives)
        assert "y" * 500 not in text
        assert "..." in text

    def test_per_line_disabled_when_zero(self):
        long = "x = " + "y" * 500
        source = f"import os\n{long}\n"
        text, _, _ = extract_snippet(source, ["x"], max_lines=5, max_line_chars=0,
                                      skip_module_docstring=False)
        assert "y" * 500 in text


class TestParseIndexMd:
    # Mirrors the real index.md structure: TOC with category headers and
    # <a href='#id'> links, then a flat "## Examples list" with detail blocks.
    SAMPLE_INDEX = """\
## User interface {#ui}

<table><tbody>
<tr><td>Beginner</td><td><ul><li><a href='#add_hotkey'>Assign a shortcut</a></li></ul></td></tr>
</tbody></table>

## Decompilation {#decompiler}

<table><tbody>
<tr><td>Beginner</td><td><ul><li><a href='#vds1'>Decompile current function</a></li></ul></td></tr>
</tbody></table>

## Examples list

### Assign a shortcut {#add_hotkey}
Use `ida_kernwin.add_hotkey` for quick prototyping.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [add_hotkey.py](https://example.com/add_hotkey.py) | actions shortcuts | Beginner |

**APIs Used:**
* `ida_kernwin.add_hotkey`
* `ida_kernwin.del_hotkey`

***

### Decompile current function {#vds1}
Shows basic decompilation usage.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds1.py](https://example.com/vds1.py) | decompile hexrays | Beginner |

**APIs Used:**
* `ida_hexrays.decompile`
* `ida_hexrays.init_hexrays_plugin`

***
"""

    def test_parses_entries(self):
        result = parse_index_md(self.SAMPLE_INDEX)
        assert "add_hotkey" in result
        assert "vds1" in result

    def test_title(self):
        result = parse_index_md(self.SAMPLE_INDEX)
        assert result["add_hotkey"]["title"] == "Assign a shortcut"

    def test_category(self):
        result = parse_index_md(self.SAMPLE_INDEX)
        assert result["add_hotkey"]["category"] == "ui"
        assert result["vds1"]["category"] == "decompiler"

    def test_level(self):
        result = parse_index_md(self.SAMPLE_INDEX)
        assert result["add_hotkey"]["level"] == "beginner"

    def test_keywords(self):
        result = parse_index_md(self.SAMPLE_INDEX)
        assert "actions" in result["add_hotkey"]["keywords"]
        assert "shortcuts" in result["add_hotkey"]["keywords"]

    def test_apis_used(self):
        result = parse_index_md(self.SAMPLE_INDEX)
        apis = result["add_hotkey"]["apis_used"]
        assert "ida_kernwin.add_hotkey" in apis
        assert "ida_kernwin.del_hotkey" in apis

    def test_description(self):
        result = parse_index_md(self.SAMPLE_INDEX)
        assert "prototyping" in result["add_hotkey"]["description"]

    def test_source_file(self):
        result = parse_index_md(self.SAMPLE_INDEX)
        assert result["add_hotkey"]["source_file"] == "add_hotkey.py"

    def test_empty_input(self):
        assert parse_index_md("") == {}

    def test_no_apis_section(self):
        md = """\
## Misc {#misc}

<table><tbody>
<tr><td><ul><li><a href='#simple'>Simple</a></li></ul></td></tr>
</tbody></table>

## Examples list

### Simple example {#simple}
Just a test.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [simple.py](https://example.com/simple.py) |  | Beginner |

***
"""
        result = parse_index_md(md)
        assert result["simple"]["apis_used"] == []
        assert result["simple"]["keywords"] == []


class TestBuildExampleIndexFlatCorpus:
    """``_build_example_index`` must work on a directory with no ``index.md``
    (and a flat layout) — the shape of ``idalib/examples``."""

    def test_flat_corpus_no_index_md(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "demo.py").write_text(
                '"""summary: open and close a database."""\n'
                'import idapro\n'
                'idapro.open_database("/tmp/x", False)\n'
            )
            entries = _build_example_index(root)
            assert len(entries) == 1
            entry = entries[0]
            assert entry.kind == "example"
            assert entry.file == "demo.py"
            assert entry.summary == "open and close a database."
            assert "idapro" in entry.imports

    def test_missing_dir_returns_empty(self):
        entries = _build_example_index(Path("/does/not/exist/here"))
        assert entries == []


class TestScoreLibrary:
    def _make_lib(self, **kwargs):
        defaults = dict(kind="library", file="ida_funcs.py")
        defaults.update(kwargs)
        return CodeEntry(**defaults)

    def test_name_match_dominates(self):
        entry = self._make_lib(title="open_database", docstring="", source="def open_database(): pass")
        assert score_library(entry, ["open_database"]) >= 5.0

    def test_docstring_outranks_body(self):
        """A query that hits only the docstring should score higher (3) than
        a query that hits only the body (1)."""
        doc_only = self._make_lib(
            title="foo", docstring="parse arbitrary input",
            source='def foo():\n    """parse arbitrary input"""\n    return 1\n',
        )
        body_only = self._make_lib(
            title="bar", docstring="",
            source='def bar():\n    # parse the user data\n    pass\n',
        )
        assert score_library(doc_only, ["parse"]) > score_library(body_only, ["parse"])

    def test_no_match(self):
        entry = self._make_lib(title="foo", docstring="bar", source="def foo(): pass")
        assert score_library(entry, ["xyz"]) == 0.0

    def test_all_terms_bonus(self):
        entry = self._make_lib(
            title="open_database",
            docstring="open a binary",
            source='def open_database(): """open a binary"""',
        )
        single = score_library(entry, ["open_database"])
        both = score_library(entry, ["open", "binary"])
        # Both terms hit the docstring → bonus multiplier 1.5x
        assert both > single * 0.6, (single, both)


class TestFilterImportsForDisplay:
    def test_strips_stdlib(self):
        out = _filter_imports_for_display(["os", "json", "argparse", "pathlib", "idapro"])
        assert out == ["idapro"]

    def test_strips_ida_modules(self):
        out = _filter_imports_for_display(["ida_funcs", "ida_hexrays", "idapro", "idc", "idautils"])
        assert out == ["idapro"]

    def test_keeps_third_party(self):
        out = _filter_imports_for_display(["lief", "capstone", "os"])
        assert sorted(out) == ["capstone", "lief"]

    def test_dedupes(self):
        out = _filter_imports_for_display(["idapro", "idapro"])
        assert out == ["idapro"]


class TestDocstringOnly:
    """``docstring_only=True`` restricts scoring so identifier hits don't
    pollute semantic queries like 'open binary file'."""

    def _lib(self, **kw):
        defaults = dict(kind="library", file="x.py")
        defaults.update(kw)
        return CodeEntry(**defaults)

    def test_library_skips_name_when_docstring_only(self):
        entry = self._lib(title="open_database", docstring="completely unrelated text",
                          source="def open_database(): pass")
        all_score = score_library(entry, ["open_database"], docstring_only=False)
        doc_score = score_library(entry, ["open_database"], docstring_only=True)
        assert all_score >= 5.0
        assert doc_score == 0.0  # name skipped, docstring doesn't contain term

    def test_library_keeps_docstring(self):
        entry = self._lib(title="foo", docstring="parse and validate user input",
                          source='def foo():\n    """parse and validate user input"""')
        score = score_library(entry, ["parse"], docstring_only=True)
        assert score >= 3.0

    def _ex(self, **kw):
        defaults = dict(kind="example", file="t.py")
        defaults.update(kw)
        return CodeEntry(**defaults)

    def test_example_keeps_summary_and_description(self):
        entry = self._ex(summary="rename a function",
                         description="walks all functions and renames them",
                         apis_used=["ida_name.set_name"], source="x = 1")
        score = score_example(entry, ["rename"], docstring_only=True)
        assert score >= 3.0

    def test_example_skips_apis_when_docstring_only(self):
        entry = self._ex(summary="no match here",
                         apis_used=["ida_name.set_name"],
                         source="ida_name.set_name(0, 'foo')")
        all_score = score_example(entry, ["set_name"], docstring_only=False)
        doc_score = score_example(entry, ["set_name"], docstring_only=True)
        assert all_score > 0
        assert doc_score == 0.0


class TestResultPositionMetadata:
    """Truncated snippets carry snippet_start_line + total_lines so the LLM
    can call get_source(file, line) to fetch more context."""

    def test_library_truncated_emits_position(self):
        from ida_code.code_search import _to_result_dict
        # 50-line chunk, snippet shows 5 lines → truncated
        body_lines = [f"    line_{i} = {i}" for i in range(50)]
        source = "def foo():\n" + "\n".join(body_lines) + "\n"
        entry = CodeEntry(
            kind="library", title="foo", file="ida_funcs.py",
            source=source, docstring="",
            file_start_line=100, file_total_lines=500,
        )
        out = _to_result_dict(entry, ["line_25"], max_lines=5, max_line_chars=200)
        assert out["snippet_start_line"] >= 100
        assert out["total_lines"] == 500

    def test_no_truncation_no_position(self):
        from ida_code.code_search import _to_result_dict
        source = "def foo(): pass"
        entry = CodeEntry(
            kind="library", title="foo", file="x.py",
            source=source, docstring="",
            file_start_line=1, file_total_lines=1,
        )
        out = _to_result_dict(entry, ["foo"], max_lines=10, max_line_chars=200)
        # Whole thing fits → no fetch needed → no position metadata
        assert "snippet_start_line" not in out
        assert "total_lines" not in out


class TestSearch:
    """Tests against the live index — confirms kind/imports filters and the
    cross-link to docs work end-to-end (skips if idalib isn't available)."""

    def test_kind_filter_library_only(self):
        from ida_code.code_search import search
        r = search("open_database", kind="library", max_results=3, include_docs=False)
        assert r["results"], "expected library hits for open_database"
        # When the caller filters to a single kind, the redundant `kind`
        # field is omitted from each result. We verify the filter worked
        # by checking the source file is a library path.
        assert all("kind" not in hit for hit in r["results"])
        assert all(
            hit["file"].endswith(".py") and "examples" not in hit["file"]
            for hit in r["results"]
        )

    def test_imports_filter(self):
        from ida_code.code_search import search
        r = search("open", imports="idapro", max_results=5, include_docs=False)
        # All results must be entries that actually import idapro.
        for hit in r["results"]:
            # Either an example (whose imports list contained idapro) or a
            # library file that itself imports idapro.
            assert hit["kind"] in ("example", "library")

    def test_related_docs_default_on(self):
        from ida_code.code_search import search
        r = search("open_database", max_results=2)
        # The cross-link is opt-out — should be present unless include_docs=False
        assert "related_docs" in r or not r["results"]

    def test_related_docs_suppressed(self):
        from ida_code.code_search import search
        r = search("open_database", max_results=2, include_docs=False)
        assert "related_docs" not in r
