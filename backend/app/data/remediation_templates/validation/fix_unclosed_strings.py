#!/usr/bin/env python3
"""
Fix unclosed triple-quoted strings in CloudFormation templates.

The issue is that CloudFormation templates end without closing triple-quotes
before the terraform_template parameter begins. This script finds and fixes
all instances where AlarmActions references are not properly closed.
"""

import re
from pathlib import Path


def fix_unclosed_cfn_strings(content: str) -> tuple[str, int]:
    """Fix unclosed CloudFormation template strings.

    Returns: (fixed_content, fix_count)
    """
    fix_count = 0

    # Pattern: line ending with !Ref SomeTopic or similar, followed by terraform_template="""
    # We need to add the closing """ after the !Ref line
    pattern = r'(        - !Ref \w+)\n(\s+terraform_template=""")'

    def add_closing_quote(match: re.Match[str]) -> str:
        nonlocal fix_count
        fix_count += 1
        return match.group(1) + '""",\n' + match.group(2)

    fixed = re.sub(pattern, add_closing_quote, content)

    # Also fix similar patterns with !GetAtt
    pattern2 = r'(        - !GetAtt \w+\.\w+)\n(\s+terraform_template=""")'

    def add_closing_quote2(match: re.Match[str]) -> str:
        nonlocal fix_count
        fix_count += 1
        return match.group(1) + '""",\n' + match.group(2)

    fixed = re.sub(pattern2, add_closing_quote2, fixed)

    return fixed, fix_count


def main() -> None:
    templates_dir = Path(__file__).parent.parent

    fixed_files = []

    for template_path in templates_dir.glob("t*.py"):
        if "validation" in str(template_path):
            continue

        content = template_path.read_text()
        fixed_content, fix_count = fix_unclosed_cfn_strings(content)

        if fix_count > 0:
            template_path.write_text(fixed_content)
            fixed_files.append((template_path.name, fix_count))
            print(f"  Fixed {fix_count} unclosed string(s) in {template_path.name}")

    print(
        f"\nFixed {len(fixed_files)} files with {sum(c for _, c in fixed_files)} total fixes"
    )


if __name__ == "__main__":
    main()
