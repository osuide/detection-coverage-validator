#!/usr/bin/env python3
"""Pre-commit hook to check for untyped functions.

This script ensures all functions have return type annotations.
It runs as part of pre-commit to prevent commits with untyped functions.
"""

import ast
import sys
from pathlib import Path


def check_file(filepath: Path) -> list[tuple[int, str]]:
    """Check a file for functions without return type annotations.

    Args:
        filepath: Path to the Python file to check.

    Returns:
        List of (line_number, function_name) tuples for untyped functions.
    """
    try:
        with open(filepath) as f:
            content = f.read()
        tree = ast.parse(content)
    except SyntaxError as e:
        print(f"Syntax error in {filepath}: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"Error reading {filepath}: {e}", file=sys.stderr)
        return []

    untyped = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Skip dunder methods (they often have implied return types)
            if node.name.startswith("__"):
                continue
            # Check if return annotation is missing
            if node.returns is None:
                untyped.append((node.lineno, node.name))

    return untyped


def main() -> int:
    """Main entry point.

    Returns:
        Exit code: 0 if all functions are typed, 1 if any are untyped.
    """
    # Get files from command line args (passed by pre-commit)
    files = sys.argv[1:]

    if not files:
        # If no files specified, check all Python files in app/
        app_dir = Path("app")
        if app_dir.exists():
            files = [str(f) for f in app_dir.rglob("*.py")]

    total_untyped = 0
    for filepath in files:
        # Only check files in the app/ directory
        if not filepath.startswith("app/") and not filepath.startswith("backend/app/"):
            continue

        # Skip __pycache__ and .venv
        if "__pycache__" in filepath or ".venv" in filepath:
            continue

        untyped = check_file(Path(filepath))
        if untyped:
            total_untyped += len(untyped)
            for lineno, func_name in untyped:
                print(
                    f"{filepath}:{lineno}: Function '{func_name}' is missing return type annotation"
                )

    if total_untyped > 0:
        print(f"\nFound {total_untyped} function(s) without return type annotations.")
        print(
            "Please add return type hints to all functions (e.g., '-> None:', '-> str:', etc.)"
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
