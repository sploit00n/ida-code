"""Unit tests for ida_code.doc_search.

Tests the scoring, excerpt extraction, and HTML stripping logic using
synthetic data — no IDA installation needed.
"""

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
        assert _score(["foo", "bar"], "foo", "bar baz") == 2

    def test_no_match(self):
        assert _score(["xyz"], "foo", "bar") == 0

    def test_partial_match(self):
        assert _score(["foo", "missing"], "foo", "bar") == 1

    def test_case_insensitive(self):
        assert _score(["foo"], "FOO", "BAR") == 1

    def test_title_match_counted(self):
        assert _score(["title"], "title word", "") == 1

    def test_body_match_counted(self):
        assert _score(["body"], "", "body text") == 1


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
