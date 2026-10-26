#!/usr/bin/env python3
"""Deterministic preflight for third-party Claude skills and plugins.

Reports verifiable facts that a reader (human or LLM) tends to miss: hidden
files, symlinks, binaries, invisible Unicode (with decoded payloads), HTML
comments, URLs, shell placeholders and execution surfaces. It never executes,
imports or follows anything from the audited package and emits no verdicts.

Usage:
    python3 -I skill_preflight.py <skill_dir | file>
    python3 -I skill_preflight.py <package.zip|.skill> [--extract-to NEW_DIR]

Exit codes: 0 report produced, 1 usage error, 2 blocking archive issue.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
import zipfile
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

MAX_TOTAL_BYTES: int = 50 * 1024 * 1024
MAX_RATIO: float = 100.0
MAX_ENTRIES: int = 2_000
MAX_SCAN_BYTES: int = 5 * 1024 * 1024
MAX_FACTS_PER_KIND: int = 25
LONG_LINE: int = 1_000
DETAIL_MAX: int = 200

MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "ELF"),
    (b"\xcf\xfa\xed\xfe", "Mach-O"),
    (b"\xfe\xed\xfa\xcf", "Mach-O"),
    (b"\xca\xfe\xba\xbe", "Mach-O/Java"),
    (b"MZ", "PE"),
    (b"PK\x03\x04", "ZIP"),
    (b"\x1f\x8b", "GZIP"),
    (b"7z\xbc\xaf", "7Z"),
    (b"%PDF", "PDF"),
    (b"\x89PNG", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF8", "GIF"),
    (b"\x00\x01\x00\x00", "TTF"),
    (b"OTTO", "OTF"),
    (b"ttcf", "TTC"),
    (b"wOFF", "WOFF"),
    (b"wOF2", "WOFF2"),
)
EXECUTABLE_MAGIC: frozenset[str] = frozenset({"ELF", "Mach-O", "Mach-O/Java", "PE"})
ARCHIVE_MAGIC: frozenset[str] = frozenset({"ZIP", "GZIP", "7Z"})
MEDIA_SUFFIXES: dict[str, frozenset[str]] = {
    "PDF": frozenset({".pdf"}),
    "PNG": frozenset({".png"}),
    "JPEG": frozenset({".jpg", ".jpeg"}),
    "GIF": frozenset({".gif"}),
    "TTF": frozenset({".ttf"}),
    "OTF": frozenset({".otf"}),
    "TTC": frozenset({".ttc"}),
    "WOFF": frozenset({".woff"}),
    "WOFF2": frozenset({".woff2"}),
}
OFFICE_SUFFIXES: frozenset[str] = frozenset({".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"})
SCRIPT_SUFFIXES: frozenset[str] = frozenset(
    {
        ".py",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".rb",
        ".pl",
        ".php",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".vbs",
        ".lua",
        ".r",
        ".command",
        ".applescript",
    }
)
DOC_SUFFIXES: frozenset[str] = frozenset(
    {".md", ".txt", ".pdf", ".png", ".jpg", ".jpeg", ".csv", ".json", ".doc", ".docx"}
)
EXECUTION_SURFACES: dict[str, str] = {
    "hooks.json": "plugin hooks: commands run on client events",
    ".mcp.json": "MCP servers launched by the client",
    "mcp.json": "MCP servers launched by the client",
    "plugin.json": "plugin manifest (may declare hooks, MCP servers, commands)",
    "marketplace.json": "plugin marketplace manifest",
    "settings.json": "client settings (permissions, hooks, env)",
    "settings.local.json": "client settings (permissions, hooks, env)",
    "setup.py": "runs arbitrary code on pip install",
    "conftest.py": "auto-executed by pytest",
    "makefile": "build commands",
    "dockerfile": "container build commands",
}
DEPENDENCY_MANIFEST_RE = re.compile(
    r"^(requirements[\w.-]*\.txt|pyproject\.toml|setup\.cfg|pipfile(\.lock)?|poetry\.lock|"
    r"uv\.lock|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|environment\.ya?ml)$",
    re.IGNORECASE,
)
LIFECYCLE_KEYS: frozenset[str] = frozenset(
    {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepack", "postpack"}
)
NAME_DESCRIPTION: frozenset[str] = frozenset({"name", "description"})
EXTRA_INVISIBLE: frozenset[int] = frozenset(
    {0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x180E}
)
SCRIPT_PREFIXES: tuple[str, ...] = (
    "LATIN",
    "CYRILLIC",
    "GREEK",
    "ARMENIAN",
    "CHEROKEE",
    "FULLWIDTH",
    "MATHEMATICAL",
)

URL_RE = re.compile(r"https?://[^\s<>\"'\x60)\]}]+", re.IGNORECASE)
REMOTE_IMAGE_RE = re.compile(
    r"\x21\[[^\]]*\]\(\s*<?https?://|<img\b[^>]*\bsrc\s*=\s*[\"']?https?://", re.IGNORECASE
)
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
SHELL_PLACEHOLDER_RE = re.compile(r"(?:^|(?<=\s))\x21\x60[^\x60\n]+\x60", re.MULTILINE)
SHELL_BLOCK_RE = re.compile(r"^[ \t]*\x60{3,}\x21", re.MULTILINE)
BLOB_RE = re.compile(r"[A-Za-z0-9+/=_-]{160,}")
HEX_ESCAPES_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}")
REVIEWER_RE = re.compile(
    r"\b(?:auditor(?:es|[i\xed]a)?|revisor(?:es)?|reviewers?|security review|veredicto|verdict|"
    r"safe to install|verified by anthropic|anthropic[- ]verified|official anthropic)\b"
    r"|(?-i:\bAPTA\b)",
    re.IGNORECASE,
)
ACTIVE_MARKUP_RE = re.compile(r"<script\b|<iframe\b|<foreignObject\b|\son\w+\s*=", re.IGNORECASE)
PDF_ACTIVE: tuple[bytes, ...] = (
    b"/JavaScript",
    b"/JS",
    b"/Launch",
    b"/OpenAction",
    b"/EmbeddedFile",
)
FACTS_NOTE: str = (
    "Facts, not verdicts: interpret each one against the skill's declared purpose. "
    "An empty report does not mean the package is safe."
)


@dataclass(frozen=True)
class Fact:
    """A verifiable observation about the audited package."""

    category: str
    path: str
    line: int
    detail: str


@dataclass(frozen=True)
class FileInfo:
    """Inventory entry for one filesystem object inside the package."""

    path: str
    kind: str
    size: int
    sha256: str | None
    executable: bool
    magic: str | None
    shebang: str | None


@dataclass(frozen=True)
class ArchiveInspection:
    """Result of inspecting a zip package before extraction."""

    sha256: str
    facts: list[Fact]
    blocking: bool


@dataclass
class Report:
    """Full preflight report; serialised to JSON by :func:`main`."""

    target: str
    package_sha256: str | None = None
    tree_sha256: str = ""
    archive_facts: list[Fact] = field(default_factory=list)
    files: list[FileInfo] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)
    urls: dict[str, list[str]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        counts: dict[str, int] = {}
        for fact in self.facts:
            counts[fact.category] = counts.get(fact.category, 0) + 1
        return {
            "target": self.target,
            "package_sha256": self.package_sha256,
            "tree_sha256": self.tree_sha256,
            "file_count": len(self.files),
            "fact_counts": dict(sorted(counts.items())),
            "archive_facts": [asdict(f) for f in self.archive_facts],
            "files": [asdict(f) for f in self.files],
            "facts": [asdict(f) for f in self.facts],
            "urls": {domain: sorted(locs) for domain, locs in sorted(self.urls.items())},
            "notes": self.notes,
        }


def _clip(text: str) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= DETAIL_MAX else flat[: DETAIL_MAX - 3] + "..."


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


# --------------------------------------------------------------------------- archives


def inspect_zip(pkg: Path) -> ArchiveInspection:
    """Inspect a zip/.skill package without extracting it."""
    sha = _sha256_file(pkg)
    facts: list[Fact] = []
    blocking = False
    try:
        archive = zipfile.ZipFile(pkg)
    except zipfile.BadZipFile as exc:
        return ArchiveInspection(sha, [Fact("zip_invalid", pkg.name, 0, str(exc))], True)
    with archive:
        infos = archive.infolist()
        total = sum(info.file_size for info in infos)
        ratio = total / max(1, sum(info.compress_size for info in infos))
        if len(infos) > MAX_ENTRIES:
            blocking = True
            facts.append(Fact("zip_too_many_entries", pkg.name, 0, f"{len(infos)} entries"))
        if total > MAX_TOTAL_BYTES or (ratio > MAX_RATIO and total > 1024 * 1024):
            blocking = True
            facts.append(
                Fact("zip_bomb", pkg.name, 0, f"{total} bytes uncompressed, ratio {ratio:.0f}x")
            )
        seen: set[str] = set()
        for info in infos:
            name = info.filename.replace("\\", "/")
            mode = (info.external_attr >> 16) & 0xFFFF
            if (
                name.startswith("/")
                or re.match(r"^[A-Za-z]:", name)
                or ".." in PurePosixPath(name).parts
            ):
                blocking = True
                facts.append(Fact("zip_path_traversal", info.filename, 0, "absolute path or '..'"))
            if stat.S_ISLNK(mode):
                target = archive.read(info)[:DETAIL_MAX].decode("utf-8", errors="replace")
                facts.append(
                    Fact("zip_symlink_entry", info.filename, 0, f"-> {target} (never extracted)")
                )
            elif mode & 0o111 and not info.is_dir():
                facts.append(Fact("zip_executable_entry", info.filename, 0, oct(mode & 0o777)))
            if info.flag_bits & 0x1:
                blocking = True
                facts.append(Fact("zip_encrypted_entry", info.filename, 0, "cannot be inspected"))
            if name.lower() in seen:
                blocking = True
                facts.append(
                    Fact(
                        "zip_duplicate_entry", info.filename, 0, "duplicate name (case-insensitive)"
                    )
                )
            seen.add(name.lower())
        if archive.comment:
            facts.append(
                Fact("zip_comment", pkg.name, 0, _clip(archive.comment.decode("utf-8", "replace")))
            )
    return ArchiveInspection(sha, facts, blocking)


def safe_extract(pkg: Path, dest: Path) -> None:
    """Extract regular files only into a new directory; never symlinks or exec bits."""
    dest.mkdir(parents=True, exist_ok=False)
    root = dest.resolve()
    written = 0
    with zipfile.ZipFile(pkg) as archive:
        for info in archive.infolist():
            if stat.S_ISLNK((info.external_attr >> 16) & 0xFFFF):
                continue
            target = (root / info.filename).resolve()
            if not target.is_relative_to(root):
                raise ValueError(f"unsafe path in archive: {info.filename!r}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if target == root:
                raise ValueError(f"unsafe path in archive: {info.filename!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, target.open("xb") as dst:
                for chunk in iter(lambda: src.read(1 << 20), b""):
                    written += len(chunk)
                    if written > MAX_TOTAL_BYTES:
                        raise ValueError("archive expands beyond MAX_TOTAL_BYTES")
                    dst.write(chunk)


# --------------------------------------------------------------------------- text scanning


def _pictographic(char: str) -> bool:
    code = ord(char)
    return code >= 0x2000 and (
        unicodedata.category(char) in {"So", "Sk"} or 0x1F000 <= code <= 0x1FAFF
    )


def _variation_selector(code: int) -> bool:
    return 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF


def _suspicious_codepoints(line: str, first_line: bool) -> list[int]:
    found: list[int] = []
    in_flag = False
    for index, char in enumerate(line):
        code = ord(char)
        prev = line[index - 1] if index else None
        nxt = line[index + 1] if index + 1 < len(line) else None
        legit = False
        if 0xE0000 <= code <= 0xE007F:
            legit = in_flag
            in_flag = in_flag and code != 0xE007F
        else:
            in_flag = code == 0x1F3F4
        if code in (0xFE0E, 0xFE0F):
            legit = prev is not None and (_pictographic(prev) or prev in "0123456789#*")
        elif code == 0x200D:
            legit = (
                prev is not None
                and nxt is not None
                and _pictographic(nxt)
                and (_pictographic(prev) or ord(prev) == 0xFE0F)
            )
        elif code == 0xFEFF and first_line and index == 0:
            legit = True
        invisible = (
            unicodedata.category(char) == "Cf"
            or _variation_selector(code)
            or code in EXTRA_INVISIBLE
        )
        if invisible and not legit:
            found.append(code)
    return found


def _decode_hidden(codes: Iterable[int]) -> str:
    codes = list(codes)
    tags = "".join(chr(c - 0xE0000) for c in codes if 0xE0020 <= c <= 0xE007E)
    payload = bytes(
        c - 0xFE00 if c <= 0xFE0F else c - 0xE0100 + 16 for c in codes if _variation_selector(c)
    )
    parts = [f"tags={tags!r}"] if tags else []
    if len(payload) > 1:
        parts.append(f"variation_selectors={payload.decode('utf-8', errors='replace')!r}")
    return "; ".join(parts)


def _word_scripts(word: str) -> set[str]:
    scripts: set[str] = set()
    for char in word:
        if char.isalpha():
            name = unicodedata.name(char, "")
            scripts.update(p for p in SCRIPT_PREFIXES if name.startswith(p))
    return scripts


def _frontmatter_facts(rel: str, text: str) -> list[Fact]:
    body = text.lstrip(chr(0xFEFF))
    if not body.startswith("---"):
        return []
    lines = body.splitlines()
    facts: list[Fact] = []
    for number, line in enumerate(lines[1:], start=2):
        if line.strip() == "---":
            break
        match = re.match(r"^([A-Za-z0-9_-]+)\s*:(.*)$", line)
        if match and match.group(1).lower() not in NAME_DESCRIPTION:
            facts.append(
                Fact("frontmatter_key", rel, number, _clip(f"{match.group(1)}:{match.group(2)}"))
            )
    return facts


def scan_text(rel: str, text: str, urls: dict[str, list[str]]) -> list[Fact]:
    """Return facts for one decoded text file and record its URLs in ``urls``."""
    facts: list[Fact] = []
    suffix = PurePosixPath(rel).suffix.lower()
    for number, line in enumerate(text.splitlines(), start=1):
        codes = _suspicious_codepoints(line, number == 1)
        if codes:
            labels = sorted({f"U+{c:04X} {unicodedata.name(chr(c), '?')}" for c in codes})
            decoded = _decode_hidden(codes)
            prefix = f"DECODED {decoded}; " if decoded else ""
            detail = f"{prefix}{len(codes)} char(s): {', '.join(labels[:3])}"
            facts.append(Fact("invisible_unicode", rel, number, _clip(detail)))
        for word in re.findall(r"\w{2,}", line):
            if len(_word_scripts(word)) > 1:
                facts.append(Fact("homoglyph", rel, number, f"mixed scripts in {word!r}"))
        if len(line) > LONG_LINE:
            facts.append(Fact("long_line", rel, number, f"{len(line)} characters"))
        for match in BLOB_RE.finditer(line):
            if len(set(match.group(0))) >= 16:
                facts.append(
                    Fact("encoded_blob", rel, number, f"{len(match.group(0))}-char encoded literal")
                )
        if HEX_ESCAPES_RE.search(line):
            facts.append(Fact("encoded_blob", rel, number, "long run of \\x escapes"))
        if REVIEWER_RE.search(line):
            facts.append(Fact("reviewer_mention", rel, number, _clip(line)))
        for match in URL_RE.finditer(line):
            host = (urlsplit(match.group(0)).hostname or "?").lower()
            urls.setdefault(host, []).append(f"{rel}:{number}")
    for match in HTML_COMMENT_RE.finditer(text):
        facts.append(
            Fact("html_comment", rel, _line_of(text, match.start()), _clip(match.group(1)))
        )
    for match in REMOTE_IMAGE_RE.finditer(text):
        facts.append(
            Fact("remote_image", rel, _line_of(text, match.start()), _clip(match.group(0)))
        )
    for match in SHELL_PLACEHOLDER_RE.finditer(text):
        facts.append(
            Fact("shell_placeholder", rel, _line_of(text, match.start()), _clip(match.group(0)))
        )
    for match in SHELL_BLOCK_RE.finditer(text):
        facts.append(
            Fact(
                "shell_block", rel, _line_of(text, match.start()), "fenced shell block run on load"
            )
        )
    if suffix in {".svg", ".html", ".htm", ".xhtml"}:
        for match in ACTIVE_MARKUP_RE.finditer(text):
            facts.append(
                Fact("active_markup", rel, _line_of(text, match.start()), _clip(match.group(0)))
            )
    if suffix in {".md", ".markdown"}:
        facts.extend(_frontmatter_facts(rel, text))
    return _cap(facts)


def _cap(facts: list[Fact]) -> list[Fact]:
    kept: list[Fact] = []
    counts: dict[str, int] = {}
    for fact in facts:
        counts[fact.category] = counts.get(fact.category, 0) + 1
        if counts[fact.category] <= MAX_FACTS_PER_KIND:
            kept.append(fact)
    for category, count in counts.items():
        if count > MAX_FACTS_PER_KIND:
            kept.append(
                Fact(category, facts[0].path, 0, f"{count - MAX_FACTS_PER_KIND} more omitted")
            )
    return kept


# --------------------------------------------------------------------------- inventory


def _walk(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        base = Path(dirpath)
        found.extend(base / d for d in dirnames if (base / d).is_symlink())
        found.extend(base / f for f in sorted(filenames))
    return found


def _decode(data: bytes) -> tuple[str | None, str | None]:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16"), "utf-16"
        except UnicodeDecodeError:
            return None, None
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, None


def _detect_magic(data: bytes) -> str | None:
    for prefix, label in MAGIC:
        if not data.startswith(prefix):
            continue
        if label == "PE":  # "MZ" alone is too weak: require the PE header
            offset = int.from_bytes(data[0x3C:0x40], "little") if len(data) >= 0x40 else -1
            if offset < 0 or data[offset : offset + 4] != b"PE\0\0":
                continue
        return label
    return None


def _office_fact(path: Path, rel: str) -> Fact:
    try:
        with zipfile.ZipFile(path) as office:
            macro = any(n.lower().endswith("vbaproject.bin") for n in office.namelist())
    except zipfile.BadZipFile:
        return Fact("office_document", rel, 0, "corrupt office container")
    return Fact("office_document", rel, 0, "contains VBA macros" if macro else "office file")


def _file_facts(path: Path, rel: str, report: Report) -> None:
    info = path.stat()
    with path.open("rb") as handle:
        data = handle.read(MAX_SCAN_BYTES)
    name = PurePosixPath(rel).name
    suffixes = [s.lower() for s in PurePosixPath(rel).suffixes]
    suffix = suffixes[-1] if suffixes else ""
    magic = _detect_magic(data)
    first = data.split(b"\n", 1)[0][:DETAIL_MAX]
    shebang = first.decode("utf-8", "replace") if data.startswith(b"#!") else None
    executable = bool(info.st_mode & 0o111)
    sha = _sha256_file(path)
    report.files.append(FileInfo(rel, "file", info.st_size, sha, executable, magic, shebang))
    facts = report.facts
    if info.st_size > MAX_SCAN_BYTES:
        facts.append(Fact("large_file", rel, 0, f"{info.st_size} bytes; partially scanned"))
    if magic in EXECUTABLE_MAGIC:
        facts.append(Fact("binary", rel, 0, f"{magic} executable; not auditable statically"))
    elif magic == "ZIP" and suffix in OFFICE_SUFFIXES:
        facts.append(_office_fact(path, rel))
    elif magic in ARCHIVE_MAGIC:
        facts.append(Fact("embedded_archive", rel, 0, f"{magic} archive inside the package"))
    elif magic in MEDIA_SUFFIXES and suffix not in MEDIA_SUFFIXES[magic]:
        facts.append(Fact("magic_mismatch", rel, 0, f"{magic} content with '{suffix}' extension"))
    if magic == "PDF":
        active = [token.decode() for token in PDF_ACTIVE if token in data]
        if active:
            facts.append(Fact("pdf_active_content", rel, 0, ", ".join(active)))
    if shebang and suffix not in SCRIPT_SUFFIXES:
        facts.append(Fact("unexpected_script", rel, 0, f"shebang {shebang!r}, no script extension"))
    risky_last = suffix in SCRIPT_SUFFIXES | {".exe", ".scr", ".app"}
    if len(suffixes) >= 2 and risky_last and suffixes[-2] in DOC_SUFFIXES:
        facts.append(Fact("double_extension", rel, 0, name))
    if name.lower() in EXECUTION_SURFACES:
        facts.append(Fact("execution_surface", rel, 0, EXECUTION_SURFACES[name.lower()]))
    elif suffix == ".pth":
        facts.append(Fact("execution_surface", rel, 0, ".pth runs code at Python startup"))
    if DEPENDENCY_MANIFEST_RE.match(name):
        facts.append(
            Fact("dependency_manifest", rel, 0, "declares dependencies: check names, pins")
        )
    if magic is not None:
        return
    text, encoding = _decode(data)
    if text is None:
        facts.append(Fact("undecodable", rel, 0, "binary or unknown encoding; not scanned"))
        return
    if encoding:
        facts.append(Fact("non_utf8_text", rel, 0, f"{encoding} text (evades naive grep)"))
    if name.lower() == "package.json":
        try:
            scripts = json.loads(text).get("scripts", {})
        except (json.JSONDecodeError, AttributeError):
            scripts = {}
        for key in sorted(set(scripts) & LIFECYCLE_KEYS):
            facts.append(Fact("lifecycle_script", rel, 0, _clip(f"{key}: {scripts[key]}")))
    facts.extend(scan_text(rel, text, report.urls))


def _analyze(root: Path, paths: Iterable[Path], target: str) -> Report:
    report = Report(target=target)
    real_root = root.resolve()
    tree = hashlib.sha256()
    for path in paths:
        rel = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if any(part.startswith(".") for part in PurePosixPath(rel).parts):
            report.facts.append(Fact("hidden_path", rel, 0, "hidden file or directory"))
        if stat.S_ISLNK(mode):
            link = os.readlink(path)
            try:
                escapes = not (path.parent.resolve() / link).resolve().is_relative_to(real_root)
            except (OSError, RuntimeError):
                escapes = True
            report.files.append(FileInfo(rel, "symlink", 0, None, False, None, None))
            report.facts.append(
                Fact("symlink_escapes_root" if escapes else "symlink", rel, 0, f"-> {link}")
            )
            tree.update(f"{rel}\0link\0{link}\n".encode())
        elif stat.S_ISREG(mode):
            _file_facts(path, rel, report)
            tree.update(f"{rel}\0file\0{report.files[-1].sha256}\n".encode())
        else:
            report.files.append(FileInfo(rel, "other", 0, None, False, None, None))
            report.facts.append(Fact("special_file", rel, 0, "not a regular file; not read"))
    report.tree_sha256 = tree.hexdigest()
    return report


def analyze_dir(root: Path) -> Report:
    """Inventory and scan every entry under ``root`` (hidden ones included)."""
    return _analyze(root, _walk(root), str(root))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic preflight for third-party skills.")
    parser.add_argument(
        "target", type=Path, help="skill directory, single file, or .zip/.skill package"
    )
    parser.add_argument(
        "--extract-to", type=Path, default=None, help="NEW directory for safe extraction"
    )
    args = parser.parse_args(argv)
    target: Path = args.target
    if not target.exists() and not target.is_symlink():
        print(f"error: {target} does not exist", file=sys.stderr)
        return 1
    code = 0
    if target.is_dir():
        report = analyze_dir(target)
    elif zipfile.is_zipfile(target):
        inspection = inspect_zip(target)
        if inspection.blocking or args.extract_to is None:
            report = Report(str(target), inspection.sha256, archive_facts=inspection.facts)
            report.notes.append(
                "Blocking archive issue: NOT extracted."
                if inspection.blocking
                else "Archive inspected only; pass --extract-to NEW_DIR to scan contents."
            )
            code = 2 if inspection.blocking else 0
        else:
            safe_extract(target, args.extract_to)
            report = analyze_dir(args.extract_to)
            report.target, report.package_sha256 = str(target), inspection.sha256
            report.archive_facts = inspection.facts
    else:
        report = _analyze(target.parent, [target], str(target))
    report.notes.append(FACTS_NOTE)
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
