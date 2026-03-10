"""Unit tests for ida_code._search_utils."""

from ida_code._search_utils import term_matches


class TestTermMatches:
    # --- Positive matches (boundary present) ---

    def test_start_of_string(self):
        assert term_matches("set", "set_name") is True

    def test_underscore_boundary(self):
        assert term_matches("func", "get_func") is True

    def test_underscore_boundary_prefix(self):
        assert term_matches("func", "ida_funcs") is True

    def test_dot_boundary(self):
        assert term_matches("get_func", "ida_funcs.get_func_name") is True

    def test_whitespace_boundary(self):
        assert term_matches("set", "call set here") is True

    def test_case_insensitive(self):
        assert term_matches("set", "SET_NAME") is True

    def test_exact_match(self):
        assert term_matches("func", "func") is True

    # --- Negative matches (no boundary) ---

    def test_no_boundary_reset(self):
        assert term_matches("set", "reset") is False

    def test_no_boundary_offset(self):
        assert term_matches("set", "offset") is False

    def test_no_boundary_unset(self):
        """'unset' has no boundary before 'set'."""
        assert term_matches("set", "unset") is False

    def test_no_boundary_defunct(self):
        assert term_matches("func", "defunct") is False

    def test_no_match_at_all(self):
        assert term_matches("xyz", "abc def") is False

    # --- Dotted terms (substring match is sufficient) ---

    def test_dotted_term_matches_substring(self):
        assert term_matches("ida_funcs.get_func", "ida_funcs.get_func_name") is True

    def test_dotted_term_no_substring(self):
        assert term_matches("ida_funcs.set_func", "ida_funcs.get_func_name") is False

    # --- Edge cases ---

    def test_empty_text(self):
        assert term_matches("set", "") is False

    def test_term_at_end(self):
        assert term_matches("name", "set_name") is True

    def test_multiple_boundaries(self):
        assert term_matches("func", "get_func_name") is True

    def test_regex_special_chars(self):
        """Terms with regex special chars should be escaped properly."""
        assert term_matches("c++", "use c++ here") is True
        assert term_matches("c++", "xc++ bad") is False
