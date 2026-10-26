"""Tests for tools/build_skill.py and for the committed SKILL.md."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _load_build() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_skill", ROOT / "tools" / "build_skill.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_skill"] = module
    spec.loader.exec_module(module)
    return module


build = _load_build()


def test_committed_skill_is_up_to_date() -> None:
    assert build.OUTPUT.read_text(encoding="utf-8") == build.render()


def test_committed_skill_is_safe_to_publish() -> None:
    assert build.safety_problems(build.OUTPUT.read_text(encoding="utf-8")) == []


def test_annex_extraction_round_trips_to_source() -> None:
    extracted = build.extract_annex(build.OUTPUT.read_text(encoding="utf-8"))
    assert extracted == build.SOURCE.read_text(encoding="utf-8")


def test_source_is_ascii() -> None:
    assert build.SOURCE.read_bytes().isascii()


def test_safety_check_rejects_invisible_characters_and_shell_placeholders() -> None:
    clean = build.render()
    anchor = "## Principios"
    fence = chr(0x60) * 3
    zero_width = clean.replace("# Revisor", "# Revisor" + chr(0x200B), 1)
    inline = clean.replace(anchor, "Ctx: " + chr(0x21) + chr(0x60) + "env`\n\n" + anchor, 1)
    fenced = clean.replace(anchor, fence + chr(0x21) + "\nenv\n" + fence + "\n\n" + anchor, 1)
    extra_key = clean.replace("---\n\n# Revisor", "allowed-tools: Bash(*)\n---\n\n# Revisor", 1)
    assert any("invisible" in p for p in build.safety_problems(zero_width))
    assert any("inline shell" in p for p in build.safety_problems(inline))
    assert any("fenced shell" in p for p in build.safety_problems(fenced))
    assert any("frontmatter" in p for p in build.safety_problems(extra_key))


def test_safety_check_rejects_tampered_script() -> None:
    tampered = build.render().replace("MAX_RATIO: float = 100.0", "MAX_RATIO: float = 1e9", 1)
    assert any("hash" in p for p in build.safety_problems(tampered))


def test_every_fact_category_is_classified_in_the_severity_table() -> None:
    source = build.SOURCE.read_text(encoding="utf-8")
    emitted = set(re.findall(r'Fact\(\s*"([a-z_]+)"', source)) | {"symlink", "symlink_escapes_root"}
    skill_md = build.OUTPUT.read_text(encoding="utf-8")
    wildcard_zip = "`zip_*`" in skill_md
    unclassified = sorted(
        c
        for c in emitted
        if f"`{c}`" not in skill_md and not (wildcard_zip and c.startswith("zip_"))
    )
    assert unclassified == []
