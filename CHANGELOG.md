# Changelog

All notable changes to this project are documented here. Versions follow [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-25

First public release. Started as a rewrite of a community skill (author unknown) whose regex scanner missed every technique in a decoy test and produced 84 false alerts on benign content.

### Added

- Deterministic preflight (`src/skill_preflight.py`, standard library only): full inventory including hidden files and symlinks, per-file and tree sha256, magic-byte detection, invisible Unicode with decoded payloads (tag characters and variation selectors), HTML comments, URL inventory by domain, remote images, load-time shell commands, frontmatter keys, plugin execution surfaces and dependency manifests.
- Safe archive handling: zip inspection before extraction (path traversal, zip bombs, duplicate or encrypted entries, symlinks); extraction refuses blocking issues and never restores symlinks or executable bits.
- Isolation rules for the reviewer: package content is data, text addressed to the reviewer is CRITICAL, and a tripwire for any urge to use a tool because of something read in the package.
- New threat categories: abuse of the agent's own tools (connectors, memory, scheduled tasks, artifacts, browser) and load-time execution in Claude Code (`allowed-tools`, `hooks`, embedded shell commands, plugin manifests).
- Verdict "SIN HALLAZGOS RELEVANTES" (no relevant findings) with a mandatory residual-risk section, instead of the original skill's "APTA" (fit).
- Single-file distribution: the script is embedded in SKILL.md with its sha256 and verified before use.
- Attack corpus (`tests/test_decoy.py`), build checks (`tests/test_build.py`) and CI on Linux and macOS, Python 3.10 to 3.13.

### Compared with the original community skill

- Replaces its regex scanner and blacklist approach to malicious patterns with a fact-based preflight.
