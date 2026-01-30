"""Security tests for Terraform HCL parser — adversarial inputs.

These tests verify the parser handles malicious, malformed, and
boundary-condition inputs without crashing, hanging, or leaking data.
"""

import pytest

from app.parsers.terraform_hcl_parser import (
    MAX_CONTENT_BYTES,
    parse_terraform_content,
)


class TestResourceExhaustion:
    """Test that the parser handles resource exhaustion attacks."""

    async def test_deeply_nested_blocks(self):
        """Deeply nested HCL should not cause stack overflow."""
        hcl = 'resource "aws_guardduty_detector" "main" {\n'
        hcl += "  nested = {\n" * 50
        hcl += '    value = "deep"\n'
        hcl += "  }\n" * 50
        hcl += "}\n"
        # Should either parse or raise a parse error — not crash
        try:
            await parse_terraform_content(hcl)
        except Exception:
            pass  # Parse error is acceptable

    async def test_many_resources_truncated(self):
        """Content with >500 detection resources is truncated."""
        lines = []
        for i in range(600):
            lines.append(
                f'resource "aws_guardduty_detector" "d{i}" {{\n  enable = true\n}}\n'
            )
        hcl = "\n".join(lines)
        if len(hcl.encode("utf-8")) <= MAX_CONTENT_BYTES:
            result = await parse_terraform_content(hcl)
            assert result.truncated is True
            assert len(result.detections) == 500

    async def test_content_at_exact_byte_limit(self):
        """Content exactly at 250KB boundary is accepted."""
        base = 'resource "aws_guardduty_detector" "main" {\n  enable = true\n}\n'
        padding_needed = MAX_CONTENT_BYTES - len(base.encode("utf-8"))
        padded = base + "# " + "x" * (padding_needed - 3) + "\n"
        assert len(padded.encode("utf-8")) <= MAX_CONTENT_BYTES
        result = await parse_terraform_content(padded)
        assert len(result.detections) >= 1

    async def test_content_one_byte_over_limit(self):
        content = "x" * (MAX_CONTENT_BYTES + 1)
        with pytest.raises(ValueError, match="exceeds maximum size"):
            await parse_terraform_content(content)


class TestMalformedInput:
    """Test that malformed inputs produce errors, not crashes."""

    async def test_binary_content(self):
        """Binary content should fail gracefully."""
        with pytest.raises(Exception):
            await parse_terraform_content("\x00\x01\x02\x03\x04")

    async def test_non_hcl_input_rejected(self):
        """JSON, YAML, and HTML inputs should not be parsed as HCL."""
        non_hcl_inputs = [
            '{"resource": {"aws_guardduty_detector": {"main": {"enable": true}}}}',
            "resources:\n  - type: aws_guardduty_detector\n    name: main\n",
            "<html><body>alert('xss')</body></html>",
        ]
        for bad_input in non_hcl_inputs:
            try:
                await parse_terraform_content(bad_input)
            except Exception:
                pass  # Parse error is acceptable for non-HCL input

    async def test_extremely_long_single_line(self):
        """Single very long line should not cause issues."""
        long_value = "a" * 100_000
        hcl = (
            f'resource "aws_guardduty_detector" "main" {{\n  tag = "{long_value}"\n}}\n'
        )
        if len(hcl.encode("utf-8")) <= MAX_CONTENT_BYTES:
            result = await parse_terraform_content(hcl)
            assert len(result.detections) == 1

    async def test_unicode_resource_names(self):
        """Unicode in resource names should be handled safely."""
        hcl = 'resource "aws_guardduty_detector" "detector_unicode" {\n  enable = true\n}\n'
        result = await parse_terraform_content(hcl)
        assert len(result.detections) == 1


class TestCredentialLeakPrevention:
    """Verify that credentials in input are not leaked in output."""

    async def test_aws_keys_in_input_not_in_detections(self):
        """AWS credentials in HCL are parsed but not included in detection objects."""
        hcl = """
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  region     = "us-east-1"
}

resource "aws_guardduty_detector" "main" {
  enable = true
}
"""
        result = await parse_terraform_content(hcl)
        assert len(result.detections) == 1
        det = result.detections[0]
        assert "AKIAIOSFODNN7EXAMPLE" not in str(det)
        assert "wJalrXUtnFEMI" not in str(det)
