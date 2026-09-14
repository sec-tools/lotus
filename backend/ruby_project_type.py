"""Bounded source hints for Ruby planning; no execution or coverage admission."""
from itertools import islice
from pathlib import Path
import re


def _text(root, path):
    try:
        root = Path(root).resolve()
        path = Path(path).resolve(strict=True)
        path.relative_to(root)
        if not path.is_file() or path.stat().st_size > 256 * 1024:
            return ""
        with path.open(encoding="utf-8", errors="replace") as handle:
            return handle.read(256 * 1024)
    except (OSError, ValueError, RuntimeError):
        return ""


def has_ruby_web_contract(root):
    root = Path(root)
    # A captured Rack entrypoint or an explicit framework dependency is a
    # positive planning signal. Unknown/dynamic declarations are not evaluated.
    rack = _text(root, root / "config.ru")
    if re.search(r"(?m)^\s*(?:run|map)\s+", rack):
        return True
    gemfile = _text(root, root / "Gemfile")
    return bool(re.search(r"(?m)^\s*gem\s*(?:\(\s*)?['\"](?:rails|railties|sinatra|hanami|roda)['\"]", gemfile))


def is_formula_catalog(root):
    root = Path(root)
    readme = "\n".join(_text(root, root / name) for name in ("README.md", "README.rst", "README"))
    if not re.search(r"\bhomebrew\b", readme, re.I):
        return False
    formula = root / "Formula"
    try:
        if not formula.resolve(strict=True).is_relative_to(root.resolve()) or not formula.is_dir():
            return False
        # A positive declaration suffices for planning this component. This is
        # not an absence scan and does not exclude companion code or services.
        for path in islice(formula.glob("**/*.rb"), 32):
            if re.search(r"(?m)^\s*class\s+[A-Z]\w*\s*<\s*(?:Formula|GnuFormula)\b", _text(root, path)):
                return True
    except (OSError, ValueError, RuntimeError):
        return False
    return False
