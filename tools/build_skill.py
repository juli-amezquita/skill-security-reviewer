#!/usr/bin/env python3
"""Build ``skill-security-reviewer/SKILL.md`` from its templates and the preflight source.

The script in ``src/skill_preflight.py`` is the single source of truth. It is embedded
verbatim in Annex A of SKILL.md together with its sha256, so a skill installed from a
single file can still verify the integrity of the code it extracts.

Usage:
    python tools/build_skill.py          # (re)write SKILL.md
    python tools/build_skill.py --check  # exit 1 if SKILL.md is stale or unsafe (CI)
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import unicodedata
from collections.abc import Sequence
from pathlib import Path

ROOT: Path = Path(__file__).resolve().parents[1]
SOURCE: Path = ROOT / "src" / "skill_preflight.py"
HEAD: Path = ROOT / "templates" / "skill_head.md"
TAIL: Path = ROOT / "templates" / "skill_tail.md"
OUTPUT: Path = ROOT / "skill-security-reviewer" / "SKILL.md"
PLACEHOLDER: str = "__SHA256__"
ANNEX_HEADING: str = "## Annex A \N{EM DASH} skill_preflight.py"
MAX_DESCRIPTION: int = 1024

# Claude Code runs these on skill load; built from hex escapes so this file never contains them.
SHELL_INLINE_RE = re.compile(r"(?:^|(?<=\s))\x21\x60", re.MULTILINE)
SHELL_BLOCK_RE = re.compile(r"^[ \t]*\x60{3,}\x21", re.MULTILINE)


class BuildError(Exception):
    """Raised when the inputs cannot produce a valid SKILL.md."""


def sha256_text(text: str) -> str:
    """Return the hex sha256 of ``text`` encoded as UTF-8."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def render() -> str:
    """Assemble SKILL.md from the head template, the preflight source and the tail."""
    code = SOURCE.read_text(encoding="utf-8")
    if not code.isascii():
        raise BuildError("src/skill_preflight.py must be pure ASCII (use escapes or chr())")
    if not code.endswith("\n") or code.endswith("\n\n"):
        raise BuildError("src/skill_preflight.py must end with exactly one newline")
    head = HEAD.read_text(encoding="utf-8")
    if head.count(PLACEHOLDER) != 1:
        raise BuildError(f"templates/skill_head.md must contain {PLACEHOLDER} exactly once")
    return head.replace(PLACEHOLDER, sha256_text(code)) + code + TAIL.read_text(encoding="utf-8")


def extract_annex(skill_md: str) -> str:
    """Extract Annex A exactly as SKILL.md instructs Claude to do it."""
    lines = skill_md.splitlines()
    start = lines.index(ANNEX_HEADING)
    opening = lines.index("```python", start)
    closing = lines.index("```", opening + 1)
    return "\n".join(lines[opening + 1 : closing]) + "\n"


def frontmatter(skill_md: str) -> dict[str, str]:
    """Parse the flat ``key: value`` frontmatter block of SKILL.md."""
    lines = skill_md.splitlines()
    if not lines or lines[0] != "---":
        raise BuildError("SKILL.md must start with a frontmatter block")
    end = lines.index("---", 1)
    pairs = (line.split(":", 1) for line in lines[1:end] if ":" in line)
    return {key.strip(): value.strip() for key, value in pairs}


def safety_problems(skill_md: str) -> list[str]:
    """Return every reason why ``skill_md`` must not be published."""
    problems: list[str] = []
    for number, line in enumerate(skill_md.splitlines(), start=1):
        for char in line:
            code = ord(char)
            hidden = unicodedata.category(char) in {"Cf", "Co", "Cn"}
            selector = 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF
            if hidden or selector:
                problems.append(f"line {number}: invisible character U+{code:04X}")
    if SHELL_INLINE_RE.search(skill_md):
        problems.append("inline shell placeholder (runs on load in Claude Code)")
    if SHELL_BLOCK_RE.search(skill_md):
        problems.append("fenced shell block (runs on load in Claude Code)")
    meta = frontmatter(skill_md)
    if set(meta) != {"name", "description"}:
        problems.append(f"frontmatter keys must be name and description, got {sorted(meta)}")
    description = meta.get("description", "")
    if len(description) > MAX_DESCRIPTION or "<" in description or ">" in description:
        problems.append("description too long or contains angle brackets")
    annex = extract_annex(skill_md)
    if sha256_text(annex) not in skill_md:
        problems.append("Annex A hash does not match the embedded script")
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--check", action="store_true", help="verify instead of writing")
    args = parser.parse_args(argv)
    try:
        rendered = render()
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    problems = safety_problems(rendered)
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != rendered:
            problems.append("SKILL.md is stale: run python tools/build_skill.py")
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    if not args.check:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"ok: SKILL.md {'up to date' if args.check else 'written'}; "
          f"script sha256 {sha256_text(SOURCE.read_text(encoding='utf-8'))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
