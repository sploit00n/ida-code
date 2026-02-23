"""Unit tests for ida_code.structures.

These tests work without idalib — they test pure-Python helpers
and session.require_open delegation (mocked).
"""

from unittest.mock import patch

import pytest
from fastmcp.exceptions import ToolError

from ida_code import structures


class TestExtractName:
    def test_basic_struct(self):
        assert structures._extract_name("struct foo { int x; };") == "foo"

    def test_basic_union(self):
        assert structures._extract_name("union bar { int a; float b; };") == "bar"

    def test_multiline(self):
        code = "struct my_struct {\n  int x;\n  char *y;\n};"
        assert structures._extract_name(code) == "my_struct"

    def test_extra_whitespace(self):
        assert structures._extract_name("struct   baz   {int x;};") == "baz"

    def test_leading_text(self):
        # e.g. a typedef or pragma before the struct
        code = "#pragma pack(1)\nstruct packed { int a; };"
        assert structures._extract_name(code) == "packed"

    def test_underscore_name(self):
        assert structures._extract_name("struct _internal_t { int x; };") == "_internal_t"

    def test_no_trailing_semicolon(self):
        assert structures._extract_name("struct foo { int x; }") == "foo"

    def test_no_match_empty(self):
        with pytest.raises(ToolError, match="Could not extract"):
            structures._extract_name("")

    def test_no_match_garbage(self):
        with pytest.raises(ToolError, match="Could not extract"):
            structures._extract_name("int x = 42;")

    def test_no_match_missing_brace(self):
        with pytest.raises(ToolError, match="Could not extract"):
            structures._extract_name("struct foo;")

    def test_typedef_struct_not_matched(self):
        # typedef without struct/union keyword before brace — no match
        with pytest.raises(ToolError, match="Could not extract"):
            structures._extract_name("typedef int myint;")


class TestRequireOpen:
    @patch("ida_code.structures.session")
    def test_list_structures_calls_require_open(self, mock_session):
        mock_session.require_open.side_effect = ToolError("No database is open.")
        with pytest.raises(ToolError, match="No database is open"):
            structures.list_structures()
        mock_session.require_open.assert_called_once()

    @patch("ida_code.structures.session")
    def test_get_structure_calls_require_open(self, mock_session):
        mock_session.require_open.side_effect = ToolError("No database is open.")
        with pytest.raises(ToolError, match="No database is open"):
            structures.get_structure("foo")
        mock_session.require_open.assert_called_once()

    @patch("ida_code.structures.session")
    def test_create_structure_calls_require_open(self, mock_session):
        mock_session.require_open.side_effect = ToolError("No database is open.")
        with pytest.raises(ToolError, match="No database is open"):
            structures.create_structure("struct foo { int x; };")
        mock_session.require_open.assert_called_once()

    @patch("ida_code.structures.session")
    def test_delete_structure_calls_require_open(self, mock_session):
        mock_session.require_open.side_effect = ToolError("No database is open.")
        with pytest.raises(ToolError, match="No database is open"):
            structures.delete_structure("foo")
        mock_session.require_open.assert_called_once()
