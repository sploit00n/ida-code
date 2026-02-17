"""Unit tests for ida_code.example_search.

Tests parsing, scoring, and snippet extraction using synthetic data —
no IDA installation needed.
"""

from ida_code.example_search import (
    ExampleEntry,
    extract_snippet,
    parse_ast,
    parse_docstring,
    parse_index_md,
    score_example,
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
        defaults = dict(
            id="test", filename="test.py", rel_path="test.py", abs_path="/test.py"
        )
        defaults.update(kwargs)
        return ExampleEntry(**defaults)

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
        snippet = extract_snippet(source, ["main"])
        assert "def main" in snippet
        # Docstring should be skipped
        assert "summary:" not in snippet

    def test_no_docstring(self):
        source = "import ida_funcs\n\ndef main():\n    pass\n"
        snippet = extract_snippet(source, ["main"])
        assert "def main" in snippet

    def test_term_centered(self):
        lines = ["import os"] + [f"line_{i}" for i in range(30)] + ["target_line"]
        source = "\n".join(lines)
        snippet = extract_snippet(source, ["target_line"], max_lines=5)
        assert "target_line" in snippet

    def test_empty_source(self):
        assert extract_snippet("", ["foo"]) == ""

    def test_no_terms(self):
        source = "line1\nline2\nline3\n"
        snippet = extract_snippet(source, [], max_lines=2)
        assert "line1" in snippet

    def test_docstring_skipped(self):
        source = '"""\nsummary: skip me\n\ndescription:\n  should not appear\n\nlevel: beginner\n"""\nimport ida_funcs\ncode_here = True\n'
        snippet = extract_snippet(source, ["code_here"])
        assert "skip me" not in snippet
        assert "code_here" in snippet


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
