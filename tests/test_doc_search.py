"""Unit tests for ida_code.doc_search.

Tests the scoring, excerpt extraction, and HTML stripping logic using
synthetic data — no IDA installation needed.
"""

from unittest.mock import patch

from ida_code.doc_search import _excerpt, _score, _score_py, _strip_html


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


class TestScorePy:
    def test_name_match_highest(self):
        """Name match should score higher than body-only match."""
        name_score = _score_py(["get_func"], "get_func", "")
        body_score = _score_py(["get_func"], "other", "get_func is called")
        assert name_score > body_score

    def test_name_match_value(self):
        score = _score_py(["get_func"], "get_func", "")
        assert score >= 5.0

    def test_body_only_match(self):
        score = _score_py(["get_func"], "other_name", "get_func is used here")
        assert 0 < score < 5.0

    def test_no_match(self):
        assert _score_py(["xyz"], "foo", "bar baz") == 0

    def test_boundary_respected(self):
        """'set' should not match name 'reset'."""
        assert _score_py(["set"], "reset", "") == 0


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
    """Test that search() includes related_examples when available."""

    @patch("ida_code.doc_search._ensure_indexes")
    @patch("ida_code.doc_search._html_docs", [("Test Title", "test body text", "test.html")])
    @patch("ida_code.doc_search._py_chunks", [])
    def test_related_examples_included(self, mock_ensure):
        from ida_code.doc_search import search

        mock_example_results = {
            "query": "test",
            "results": [{"title": "Example", "file": "test.py", "score": 5.0}],
        }
        with patch("ida_code.example_search.search", return_value=mock_example_results):
            result = search("test", include_examples=True)
            assert "related_examples" in result
            assert len(result["related_examples"]) == 1

    @patch("ida_code.doc_search._ensure_indexes")
    @patch("ida_code.doc_search._html_docs", [("Test Title", "test body text", "test.html")])
    @patch("ida_code.doc_search._py_chunks", [])
    def test_no_related_examples_when_disabled(self, mock_ensure):
        from ida_code.doc_search import search

        result = search("test", include_examples=False)
        assert "related_examples" not in result

    @patch("ida_code.doc_search._ensure_indexes")
    @patch("ida_code.doc_search._html_docs", [("Test Title", "test body text", "test.html")])
    @patch("ida_code.doc_search._py_chunks", [])
    def test_no_related_examples_when_none_match(self, mock_ensure):
        from ida_code.doc_search import search

        mock_example_results = {"query": "test", "results": []}
        with patch("ida_code.example_search.search", return_value=mock_example_results):
            result = search("test", include_examples=True)
            assert "related_examples" not in result
