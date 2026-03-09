"""
test_input_handler.py
---------------------
Comprehensive test suite for input_handler.py
Tests for robustness, security, and error handling.

Tests cover:
  - File path validation and security (path traversal prevention)
  - Email parsing with malformed inputs
  - Empty and oversized inputs
  - File encoding handling
  - Edge cases in email parsing
  - Input sanitization
  - Error recovery

Authors: Test Suite
Course:  ITSC 203
"""

import pytest
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
from io import StringIO

# Import functions from input_handler
from input_handler import (
    parse_email,
    extract_body,
    extract_attachments,
    build_email_dict,
    load_from_file,
    collect_pasted_input,
    print_parsed_summary
)


# ─────────────────────────────────────────────
#  Test Suite 1: Email Parsing - Valid Inputs
# ─────────────────────────────────────────────

class TestEmailParsingValid:
    """Test email parsing with valid, well-formed emails."""

    def test_parse_simple_email(self):
        """Parse a basic email with headers and body."""
        raw = "From: sender@example.com\nTo: recipient@example.com\nSubject: Test\n\nHello World"
        result = parse_email(raw)
        
        assert result is not None
        assert result["headers"]["from"] == "sender@example.com"
        assert result["headers"]["to"] == "recipient@example.com"
        assert result["headers"]["subject"] == "Test"
        assert "Hello World" in result["body"]

    def test_parse_email_with_all_headers(self):
        """Parse email with complete set of headers."""
        raw = """From: alice@example.com
To: bob@example.com
Subject: Important Message
Reply-To: reply@example.com
Date: Mon, 09 Mar 2026 12:00:00 +0000
Return-Path: <bounce@example.com>

This is the body."""
        
        result = parse_email(raw)
        assert result["headers"]["from"] == "alice@example.com"
        assert result["headers"]["reply_to"] == "reply@example.com"
        assert result["headers"]["date"] == "Mon, 09 Mar 2026 12:00:00 +0000"
        assert result["headers"]["return_path"] == "<bounce@example.com>"

    def test_parse_email_multipart(self):
        """Parse multipart email with multiple content types."""
        raw = """From: test@example.com
To: user@example.com
Subject: Multipart Test
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain

Plain text version
--boundary123
Content-Type: text/html

<html><body>HTML version</body></html>
--boundary123--"""
        
        result = parse_email(raw)
        assert result is not None
        assert "Plain text version" in result["body"]

    def test_parse_email_with_attachment_headers(self):
        """Parse email with attachment metadata."""
        raw = """From: sender@example.com
To: recipient@example.com
Subject: Email with Attachment
Content-Type: multipart/mixed; boundary="boundary"

--boundary
Content-Type: text/plain

Body text
--boundary
Content-Type: application/pdf; name="document.pdf"
Content-Disposition: attachment; filename="document.pdf"

[binary data]
--boundary--"""
        
        result = parse_email(raw)
        assert len(result["attachments"]) > 0
        assert any("document.pdf" in att.get("filename", "") for att in result["attachments"])


# ─────────────────────────────────────────────
#  Test Suite 2: Email Parsing - Malformed Inputs
# ─────────────────────────────────────────────

class TestEmailParsingMalformed:
    """Test email parsing with invalid/malformed input."""

    def test_parse_empty_email(self):
        """Parse completely empty email."""
        result = parse_email("")
        assert result is not None
        assert result["body"] == ""

    def test_parse_whitespace_only_email(self):
        """Parse email with only whitespace."""
        result = parse_email("   \n\n   \t\t  ")
        assert result is not None
        assert result["body"].strip() == ""

    def test_parse_malformed_headers(self):
        """Parse email with malformed header syntax."""
        raw = "From sender@example.com\nTo: recipient@example.com\nSubject Test\n\nBody"
        result = parse_email(raw)
        assert result is not None
        # Should still extract what it can

    def test_parse_no_headers_only_body(self):
        """Parse raw text without email headers."""
        raw = "This is just plain text with no headers at all."
        result = parse_email(raw)
        assert result is not None
        assert "plain text" in result["body"]

    def test_parse_oversized_header(self):
        """Parse email with extremely long header value."""
        long_subject = "X" * 100000
        raw = f"From: test@example.com\nSubject: {long_subject}\n\nBody"
        result = parse_email(raw)
        assert result is not None

    def test_parse_null_bytes_in_email(self):
        """Handle null bytes in email content."""
        raw = "From: test@example.com\nSubject: Test\n\nBody with \x00 null byte"
        result = parse_email(raw)
        assert result is not None

    def test_parse_special_characters(self):
        """Parse email with special characters and unicode."""
        raw = "From: test@example.com\nSubject: Test with émojis 🔒🎉\n\nBody: Ñoño résumé"
        result = parse_email(raw)
        assert result is not None

    def test_parse_very_long_body(self):
        """Parse email with very large body."""
        huge_body = "A" * 10000000  # 10MB
        raw = f"From: test@example.com\nSubject: Huge\n\n{huge_body}"
        result = parse_email(raw)
        assert result is not None


# ─────────────────────────────────────────────
#  Test Suite 3: File Loading - Security
# ─────────────────────────────────────────────

class TestFileLoadingSecurity:
    """Test file loading with security concerns."""

    def test_load_path_traversal_attack(self):
        """Document path traversal vulnerability (currently not validated)."""
        # This test documents that the code currently doesn't validate
        # path traversal attacks like ../../etc/passwd
        # A secure implementation should restrict to safe directories
        pass

    def test_load_nonexistent_file(self):
        """Handle attempt to load nonexistent file."""
        with patch('builtins.input', return_value="/nonexistent/file.txt"):
            result = load_from_file()
            assert result is None

    def test_load_file_permission_denied(self):
        """Handle permission denied error gracefully."""
        with patch('builtins.input', return_value="/etc/shadow"):
            with patch('builtins.open', side_effect=PermissionError("Permission denied")):
                result = load_from_file()
                assert result is None

    def test_load_file_with_quotes(self):
        """Strip surrounding quotes from file paths."""
        test_content = "From: test@example.com\n\nBody"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(test_content)
            f.flush()
            temp_path = f.name

        try:
            # Test with double quotes
            with patch('builtins.input', return_value=f'"{temp_path}"'):
                result = load_from_file()
                assert result == test_content
            
            # Test with single quotes
            with patch('builtins.input', return_value=f"'{temp_path}'"):
                result = load_from_file()
                assert result == test_content
        finally:
            os.unlink(temp_path)

    def test_load_symlink_file(self):
        """Handle symlinked files safely."""
        test_content = "From: test@example.com\n\nBody"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
            f.write(test_content)
            f.flush()
            temp_path = f.name

        try:
            symlink_path = temp_path + "_symlink.eml"
            if not os.path.exists(symlink_path):
                os.symlink(temp_path, symlink_path)
                with patch('builtins.input', return_value=symlink_path):
                    result = load_from_file()
                    assert result == test_content
                os.unlink(symlink_path)
        finally:
            os.unlink(temp_path)


# ─────────────────────────────────────────────
#  Test Suite 4: File Loading - Format Validation
# ─────────────────────────────────────────────

class TestFileFormatValidation:
    """Test file format validation (.txt and .eml only)."""

    def test_load_txt_file(self):
        """Successfully load .txt file."""
        content = "Email content in plain text"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            f.flush()
            temp_path = f.name

        try:
            with patch('builtins.input', return_value=temp_path):
                result = load_from_file()
                assert result == content
        finally:
            os.unlink(temp_path)

    def test_load_eml_file(self):
        """Successfully load .eml file."""
        content = "From: test@example.com\n\nBody"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
            f.write(content)
            f.flush()
            temp_path = f.name

        try:
            with patch('builtins.input', return_value=temp_path):
                result = load_from_file()
                assert result == content
        finally:
            os.unlink(temp_path)

    def test_load_unsupported_format_pdf(self):
        """Reject .pdf files."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pdf', delete=False) as f:
            f.write("fake pdf")
            temp_path = f.name

        try:
            with patch('builtins.input', return_value=temp_path):
                result = load_from_file()
                assert result is None
        finally:
            os.unlink(temp_path)

    def test_load_unsupported_format_docx(self):
        """Reject .docx files."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.docx', delete=False) as f:
            f.write("fake docx")
            temp_path = f.name

        try:
            with patch('builtins.input', return_value=temp_path):
                result = load_from_file()
                assert result is None
        finally:
            os.unlink(temp_path)

    def test_load_no_extension(self):
        """Reject files without extension."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("content")
            temp_path = f.name

        try:
            with patch('builtins.input', return_value=temp_path):
                result = load_from_file()
                assert result is None
        finally:
            os.unlink(temp_path)

    def test_load_case_insensitive_extension(self):
        """Handle .TXT, .EML in uppercase."""
        content = "Test content"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.TXT', delete=False) as f:
            f.write(content)
            f.flush()
            temp_path = f.name

        try:
            with patch('builtins.input', return_value=temp_path):
                result = load_from_file()
                assert result == content
        finally:
            os.unlink(temp_path)


# ─────────────────────────────────────────────
#  Test Suite 5: File Encoding Handling
# ─────────────────────────────────────────────

class TestFileEncodingHandling:
    """Test handling of different file encodings."""

    def test_load_utf8_file(self):
        """Load UTF-8 encoded file successfully."""
        content = "Hello with UTF-8: café, 你好, العربية"
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.txt', delete=False) as f:
            f.write(content)
            f.flush()
            temp_path = f.name

        try:
            with patch('builtins.input', return_value=temp_path):
                result = load_from_file()
                assert result is not None
        finally:
            os.unlink(temp_path)

    def test_load_latin1_file(self):
        """Load Latin-1 encoded file (should be replaced on error)."""
        content = "Latin-1 content"
        with tempfile.NamedTemporaryFile(mode='w', encoding='latin-1', suffix='.txt', delete=False) as f:
            f.write(content)
            f.flush()
            temp_path = f.name

        try:
            with patch('builtins.input', return_value=temp_path):
                result = load_from_file()
                # Should still succeed due to errors="replace"
                assert result is not None
        finally:
            os.unlink(temp_path)

    def test_load_empty_file(self):
        """Load empty file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.flush()
            temp_path = f.name

        try:
            with patch('builtins.input', return_value=temp_path):
                result = load_from_file()
                assert result == ""
        finally:
            os.unlink(temp_path)

    def test_load_very_large_file(self):
        """Load very large file (5MB+)."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("X" * 5000000)  # 5MB
            f.flush()
            temp_path = f.name

        try:
            with patch('builtins.input', return_value=temp_path):
                result = load_from_file()
                assert result is not None
                assert len(result) == 5000000
        finally:
            os.unlink(temp_path)


# ─────────────────────────────────────────────
#  Test Suite 6: Body Extraction
# ─────────────────────────────────────────────

class TestBodyExtraction:
    """Test email body extraction from various formats."""

    def test_extract_body_simple(self):
        """Extract body from simple email."""
        import email
        raw = "From: test@example.com\n\nThis is the body"
        msg = email.message_from_string(raw)
        body = extract_body(msg, raw)
        assert "This is the body" in body

    def test_extract_body_multipart(self):
        """Extract body from multipart email (should get text/plain)."""
        import email
        raw = """Content-Type: multipart/alternative; boundary="boundary"

--boundary
Content-Type: text/plain

Plain text body
--boundary
Content-Type: text/html

<html>HTML body</html>
--boundary--"""
        msg = email.message_from_string(raw)
        body = extract_body(msg, raw)
        assert "Plain text body" in body

    def test_extract_body_fallback_to_raw(self):
        """Fallback to raw text if no structured body found."""
        import email
        raw = "This is raw email text without headers"
        msg = email.message_from_string(raw)
        body = extract_body(msg, raw)
        assert "raw email text" in body

    def test_extract_body_with_attachments(self):
        """Ignore attachments when extracting body."""
        import email
        raw = """Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/plain

Email body
--b
Content-Type: application/pdf; name="file.pdf"
Content-Disposition: attachment; filename="file.pdf"

[binary]
--b--"""
        msg = email.message_from_string(raw)
        body = extract_body(msg, raw)
        assert "Email body" in body
        assert "[binary]" not in body


# ─────────────────────────────────────────────
#  Test Suite 7: Attachment Extraction
# ─────────────────────────────────────────────

class TestAttachmentExtraction:
    """Test email attachment detection and extraction."""

    def test_extract_no_attachments(self):
        """Email with no attachments returns empty list."""
        import email
        raw = "From: test@example.com\n\nJust body, no attachments"
        msg = email.message_from_string(raw)
        attachments = extract_attachments(msg)
        assert attachments == []

    def test_extract_single_attachment(self):
        """Extract single attachment metadata."""
        import email
        raw = """Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/plain

Body
--b
Content-Type: application/pdf
Content-Disposition: attachment; filename="report.pdf"

[binary pdf data]
--b--"""
        msg = email.message_from_string(raw)
        attachments = extract_attachments(msg)
        assert len(attachments) >= 1

    def test_extract_multiple_attachments(self):
        """Extract metadata for multiple attachments."""
        import email
        raw = """Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/plain

Body
--b
Content-Type: image/png
Content-Disposition: attachment; filename="image.png"

[binary]
--b
Content-Type: application/zip
Content-Disposition: attachment; filename="archive.zip"

[binary]
--b--"""
        msg = email.message_from_string(raw)
        attachments = extract_attachments(msg)
        assert len(attachments) >= 2

    def test_extract_attachment_without_filename(self):
        """Handle attachment without explicit filename."""
        import email
        raw = """Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/plain

Body
--b
Content-Type: application/octet-stream
Content-Disposition: attachment

[binary data]
--b--"""
        msg = email.message_from_string(raw)
        attachments = extract_attachments(msg)
        # Should still work, using "unknown_filename"
        assert any("unknown" in att.get("filename", "") for att in attachments)


# ─────────────────────────────────────────────
#  Test Suite 8: Build Email Dict
# ─────────────────────────────────────────────

class TestBuildEmailDict:
    """Test building the final email dictionary structure."""

    def test_build_complete_email_dict(self):
        """Build complete email dict with all fields."""
        result = build_email_dict(
            sender="from@example.com",
            recipient="to@example.com",
            subject="Subject",
            reply_to="reply@example.com",
            date="Mon, 09 Mar 2026 12:00:00 +0000",
            return_path="<bounce@example.com>",
            body="Email body",
            attachments=[],
            raw_text="Full raw email"
        )
        
        assert result["headers"]["from"] == "from@example.com"
        assert result["headers"]["to"] == "to@example.com"
        assert result["body"] == "Email body"
        assert result["raw"] == "Full raw email"

    def test_build_email_dict_with_attachments(self):
        """Build dict with attachment metadata."""
        attachments = [
            {"filename": "file1.pdf", "mime_type": "application/pdf"},
            {"filename": "image.png", "mime_type": "image/png"}
        ]
        result = build_email_dict(
            sender="from@example.com",
            recipient="to@example.com",
            subject="With attachments",
            reply_to="",
            date="",
            return_path="",
            body="Body",
            attachments=attachments,
            raw_text="Raw"
        )
        
        assert len(result["attachments"]) == 2

    def test_build_email_dict_empty_fields(self):
        """Build dict with empty/missing fields."""
        result = build_email_dict(
            sender="",
            recipient="",
            subject="",
            reply_to="",
            date="",
            return_path="",
            body="",
            attachments=[],
            raw_text=""
        )
        
        assert result is not None
        assert result["body"] == ""


# ─────────────────────────────────────────────
#  Test Suite 9: Input Validation Edge Cases
# ─────────────────────────────────────────────

class TestInputValidationEdgeCases:
    """Test edge cases in user input validation."""

    def test_collect_pasted_input_basic(self):
        """Collect basic pasted input."""
        inputs = iter(["Line 1", "Line 2", "END"])
        with patch('builtins.input', side_effect=inputs):
            result = collect_pasted_input()
            assert "Line 1" in result
            assert "Line 2" in result

    def test_collect_pasted_input_empty(self):
        """Collect empty pasted input."""
        inputs = iter(["END"])
        with patch('builtins.input', side_effect=inputs):
            result = collect_pasted_input()
            assert result.strip() == ""

    def test_collect_pasted_input_case_insensitive_end(self):
        """END keyword should be case-insensitive."""
        inputs = iter(["Content", "end"])  # lowercase 'end'
        with patch('builtins.input', side_effect=inputs):
            result = collect_pasted_input()
            assert "Content" in result

    def test_collect_pasted_input_with_spaces_in_end(self):
        """Handle END with leading/trailing spaces."""
        inputs = iter(["Content", "  END  "])
        with patch('builtins.input', side_effect=inputs):
            result = collect_pasted_input()
            assert "Content" in result

    def test_collect_pasted_input_eof(self):
        """Handle EOF (Ctrl+D) during paste."""
        inputs = iter(["Line 1", "Line 2"])
        # Second iteration will raise EOFError
        def side_effect_func(*args):
            try:
                return next(inputs)
            except StopIteration:
                raise EOFError()
        
        with patch('builtins.input', side_effect=side_effect_func):
            result = collect_pasted_input()
            assert result is not None

    def test_collect_pasted_input_very_long(self):
        """Handle very long pasted input."""
        long_lines = ["X" * 10000 for _ in range(1000)]  # 10MB of input
        inputs = iter(long_lines + ["END"])
        with patch('builtins.input', side_effect=inputs):
            result = collect_pasted_input()
            assert len(result) > 1000000

    def test_collect_pasted_input_special_chars(self):
        """Handle special characters in pasted input."""
        inputs = iter([
            "Line with special chars: !@#$%^&*()",
            "Unicode: café 中文 العربية",
            "END"
        ])
        with patch('builtins.input', side_effect=inputs):
            result = collect_pasted_input()
            assert "special chars" in result
            assert "Unicode" in result


# ─────────────────────────────────────────────
#  Test Suite 10: Print Output Function
# ─────────────────────────────────────────────

class TestPrintParsedSummary:
    """Test print output formatting."""

    def test_print_summary_with_none(self):
        """Handle None input gracefully."""
        captured_output = StringIO()
        with patch('sys.stdout', captured_output):
            print_parsed_summary(None)
        output = captured_output.getvalue()
        assert "No email data" in output

    def test_print_summary_with_data(self):
        """Print summary with complete email data."""
        data = {
            "headers": {
                "from": "test@example.com",
                "to": "user@example.com",
                "subject": "Test",
                "reply_to": "",
                "date": "",
                "return_path": ""
            },
            "body": "Test body content",
            "attachments": [
                {"filename": "file.pdf", "mime_type": "application/pdf"}
            ],
            "raw": "Raw content"
        }
        
        captured_output = StringIO()
        with patch('sys.stdout', captured_output):
            print_parsed_summary(data)
        output = captured_output.getvalue()
        assert "test@example.com" in output
        assert "file.pdf" in output

    def test_print_summary_with_no_attachments(self):
        """Print summary with no attachments."""
        data = {
            "headers": {
                "from": "test@example.com",
                "to": "user@example.com",
                "subject": "No attachments",
                "reply_to": "",
                "date": "",
                "return_path": ""
            },
            "body": "Just text",
            "attachments": [],
            "raw": "Raw"
        }
        
        captured_output = StringIO()
        with patch('sys.stdout', captured_output):
            print_parsed_summary(data)
        output = captured_output.getvalue()
        assert "0" in output  # No attachments


# ─────────────────────────────────────────────
#  Test Suite 11: Integration Tests
# ─────────────────────────────────────────────

class TestIntegration:
    """Integration tests for complete workflows."""

    def test_end_to_end_parse_valid_email(self):
        """Complete workflow: parse valid email."""
        raw = "From: alice@example.com\nTo: bob@example.com\nSubject: Hi\n\nHello Bob!"
        result = parse_email(raw)
        assert result is not None
        assert result["headers"]["from"] == "alice@example.com"
        assert "Hello Bob" in result["body"]

    def test_end_to_end_load_and_parse_file(self):
        """Complete workflow: load file and parse."""
        content = "From: test@example.com\n\nBody content"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            f.flush()
            temp_path = f.name

        try:
            with patch('builtins.input', return_value=temp_path):
                loaded = load_from_file()
                result = parse_email(loaded)
                assert result is not None
                assert result["headers"]["from"] == "test@example.com"
        finally:
            os.unlink(temp_path)

    def test_error_recovery_malformed_then_valid(self):
        """Recover from malformed input and handle valid input."""
        malformed = "Not a valid email"
        result1 = parse_email(malformed)
        
        valid = "From: test@example.com\n\nValid body"
        result2 = parse_email(valid)
        
        assert result1 is not None
        assert result2 is not None
        assert result2["headers"]["from"] == "test@example.com"


# ─────────────────────────────────────────────
#  Pytest Configuration & Fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def temp_email_file():
    """Fixture for temporary email file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("From: fixture@example.com\nTo: user@example.com\n\nFixture email body")
        f.flush()
        yield f.name
    os.unlink(f.name)


def test_with_fixture(temp_email_file):
    """Example test using fixture."""
    with patch('builtins.input', return_value=temp_email_file):
        result = load_from_file()
        assert "fixture@example.com" in result


# ─────────────────────────────────────────────
#  Run tests with pytest
# ─────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
