"""Unit tests for ida_code.doc_search.

Tests the scoring, excerpt extraction, and HTML stripping logic using
synthetic data — no IDA installation needed.
"""

from unittest.mock import patch

from ida_code.doc_search import _excerpt, _score, _strip_html


class TestStripHtml:
    def test_basic_tags(self):
        assert _strip_html("<b>bold</b>") == "bold"

    def test_nested_tags(self):
        assert _strip_html("<div><p>hello</p></div>") == "hello"

    def test_no_tags(self):
        assert _strip_html("plain text") == "plain text"

    def test_empty(self):
        assert _strip_html("") == ""

    def test_attributes_stripped(self):
        assert _strip_html('<a href="url">link</a>') == "link"


class TestScore:
    def test_all_terms_match(self):
        score = _score(["foo", "bar"], "foo", "bar baz")
        assert score > 0

    def test_no_match(self):
        assert _score(["xyz"], "foo", "bar") == 0

    def test_partial_match(self):
        score = _score(["foo", "missing"], "foo", "bar")
        assert score > 0

    def test_case_insensitive(self):
        assert _score(["foo"], "FOO", "BAR") > 0

    def test_title_match_higher_than_body(self):
        title_score = _score(["func"], "func", "")
        body_score = _score(["func"], "", "func is used")
        assert title_score > body_score

    def test_body_match_counted(self):
        assert _score(["body"], "", "body text") > 0

    # --- Word-boundary matching ---

    def test_no_match_substring_without_boundary(self):
        """'set' should NOT match 'reset' (no boundary before 'set')."""
        assert _score(["set"], "", "reset value") == 0

    def test_match_at_boundary(self):
        """'set' should match 'set_name' (start-of-string boundary)."""
        assert _score(["set"], "", "set_name is used") > 0

    def test_no_match_offset(self):
        """'set' should NOT match 'offset'."""
        assert _score(["set"], "", "offset value") == 0

    def test_match_underscore_boundary(self):
        """'func' should match 'get_func'."""
        assert _score(["func"], "", "get_func returns") > 0

    def test_no_match_defunct(self):
        """'func' should NOT match 'defunct'."""
        assert _score(["func"], "", "defunct code") == 0

    # --- All-terms-match bonus ---

    def test_all_terms_bonus(self):
        score_both = _score(["foo", "bar"], "foo bar", "")
        score_one = _score(["foo"], "foo", "")
        # Both terms matching should give a bonus beyond additive
        assert score_both > score_one * 2


class TestExcerpt:
    def test_short_text_returned_fully(self):
        result = _excerpt("hello world", ["hello"], max_len=300)
        assert "hello world" in result

    def test_excerpt_around_match(self):
        text = "A" * 200 + " TARGET " + "B" * 200
        result = _excerpt(text, ["target"], max_len=100)
        assert "TARGET" in result
        assert len(result) < 200  # much shorter than original

    def test_ellipsis_at_start(self):
        text = "A" * 200 + "match" + "B" * 200
        result = _excerpt(text, ["match"], max_len=100)
        assert result.startswith("...")

    def test_ellipsis_at_end(self):
        text = "A" * 200 + "match" + "B" * 200
        result = _excerpt(text, ["match"], max_len=100)
        assert result.endswith("...")

    def test_no_match_returns_beginning(self):
        text = "start of text and more"
        result = _excerpt(text, ["nonexistent"], max_len=300)
        assert "start" in result

    def test_whitespace_collapsed(self):
        result = _excerpt("foo   \n\n   bar", ["foo"], max_len=300)
        assert "  " not in result


class TestSearchCrossLinking:
    """Test that search() includes related_examples when available.

    The cross-link now goes through code_search (with kind="example") instead
    of the old example_search module — but the response field name and
    semantics stay the same for back-compat.
    """

    @patch("ida_code.doc_search._ensure_indexes")
    @patch("ida_code.doc_search._html_docs", [("Test Title", "test body text", "test.html")])
    def test_related_examples_included(self, mock_ensure):
        from ida_code.doc_search import search

        mock_code_results = {
            "query": "test",
            "results": [{"kind": "example", "title": "Example", "file": "test.py", "score": 5.0}],
        }
        with patch("ida_code.code_search.search", return_value=mock_code_results):
            result = search("test", include_examples=True)
            assert "related_examples" in result
            assert len(result["related_examples"]) == 1

    @patch("ida_code.doc_search._ensure_indexes")
    @patch("ida_code.doc_search._html_docs", [("Test Title", "test body text", "test.html")])
    def test_no_related_examples_when_disabled(self, mock_ensure):
        from ida_code.doc_search import search

        result = search("test", include_examples=False)
        assert "related_examples" not in result

    @patch("ida_code.doc_search._ensure_indexes")
    @patch("ida_code.doc_search._html_docs", [("Test Title", "test body text", "test.html")])
    def test_no_related_examples_when_none_match(self, mock_ensure):
        from ida_code.doc_search import search

        empty = {"query": "test", "results": []}
        with patch("ida_code.code_search.search", return_value=empty):
            result = search("test", include_examples=True)
            assert "related_examples" not in result


# `idapro/__init__.py` chunk indexing now lives in `tests/test_code_search.py`
# (see TestSearch).
