# Security policy · Política de seguridad

## English

This project is a **review aid, not a guarantee**. A clean report means "no relevant findings", never "safe".

### Reporting a bypass

- **A new pattern that is fine to discuss publicly** (an attack idea, a false positive, a missing category): open an issue, or a pull request that adds it to the attack corpus in `tests/test_decoy.py`.
- **A reliable bypass that could hurt users if published**: use GitHub's private vulnerability reporting (**Security → Report a vulnerability**) instead of a public issue.

### Integrity of this repository

- `skill-security-reviewer/SKILL.md` is generated. It embeds `src/skill_preflight.py` verbatim together with its sha256, and the agent verifies that hash before running the script.
- CI fails if `SKILL.md` is stale, if the embedded hash does not match, if any invisible Unicode character appears, if the frontmatter declares anything beyond `name` and `description`, or if `SKILL.md` contains commands that Claude Code would run at load time.
- Before installing or updating, run `python3 tools/build_skill.py --check` locally.

## Español

Este proyecto es una **ayuda para revisar, no una garantía**. Un informe limpio significa "sin hallazgos relevantes", nunca "segura".

### Reportar una evasión

- **Un patrón nuevo que se puede discutir en público** (idea de ataque, falso positivo, categoría faltante): abre un issue o un pull request que lo agregue al corpus de ataques en `tests/test_decoy.py`.
- **Una evasión confiable que podría dañar a usuarios si se publica**: usa el reporte privado de vulnerabilidades de GitHub (**Security → Report a vulnerability**) en lugar de un issue público.

### Integridad de este repositorio

- `skill-security-reviewer/SKILL.md` se genera automáticamente. Incluye `src/skill_preflight.py` literal junto con su sha256, y el agente verifica ese hash antes de ejecutar el script.
- El CI falla si `SKILL.md` está desactualizado, si el hash no coincide, si aparece cualquier carácter Unicode invisible, si el frontmatter declara algo más que `name` y `description`, o si `SKILL.md` contiene comandos que Claude Code ejecutaría al cargar la skill.
- Antes de instalar o actualizar, corre `python3 tools/build_skill.py --check` en tu computador.
