# skill-security-reviewer

[![CI](https://github.com/juli-amezquita/skill-security-reviewer/actions/workflows/ci.yml/badge.svg)](https://github.com/juli-amezquita/skill-security-reviewer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Security review for third-party Claude skills and plugins, **before** you install them.
Revisión de seguridad para skills y plugins de terceros de Claude, **antes** de instalarlos.

**[English](#english) · [Español](#español)**

---

## English

### The problem

A skill is mostly instructions that the model follows almost as if they were part of its own configuration, plus optional scripts that run with the agent's permissions. Installing one from a forum or a random repository is closer to running someone else's code than to reading a document.

The attack surface has also moved. A malicious skill no longer needs a script: it can ask the agent to use its own connectors, memory, scheduled tasks or browser. In Claude Code it can run shell commands at load time through `allowed-tools`, `hooks` or embedded commands, without a permission prompt.

### How it works

Two layers, because each one catches what the other misses:

| Layer | What it does | What it catches |
|---|---|---|
| **Deterministic preflight** (`src/skill_preflight.py`) | Inventories every file (hidden ones and symlinks included), hashes them, decodes invisible Unicode and flags load-time execution surfaces | What a reader misses: hidden directories, smuggled Unicode payloads, symlinks out of the package, binaries disguised as text, shebang-only scripts |
| **Guided semantic review** (`SKILL.md`) | Isolation rules, a 12-category threat catalog, severity rules and a report template that the agent follows | What a regex misses: intent, instructions aimed at the model or at the reviewer, abuse of the agent's own tools |

Design decisions:

- **Facts, not verdicts.** The script never says "safe", and an empty report explicitly means nothing.
- **The reviewer is part of the attack surface.** Everything in the package is data. Text addressed to the reviewer is CRITICAL, and a tripwire treats any urge to use a tool because of something read in the package as evidence of injection.
- **Zero dependencies, zero execution.** Standard library only. The package under review is never imported, executed or followed through symlinks.
- **Safe extraction.** Zip archives are inspected before extraction (path traversal, zip bombs, duplicate or encrypted entries, symlinks) and refused when a blocking issue exists.
- **Self-verifying single file.** The skill ships as one `SKILL.md` with the script and its sha256 embedded. The agent extracts the script and checks the hash before running it.

### Results

A small, reproducible test, not a benchmark:

- **Decoy skill.** On the original 15-technique decoy, the regex scanner of the course exercise this project started from (a teaching example, never meant as a production tool) flagged none of the planted techniques (it only caught an obvious `curl | bash` control case). This preflight surfaces 9 of those 15 plus the frontmatter tool pre-approval. The corpus in `tests/test_decoy.py` has since grown to 17 techniques: 11 surfaced by the preflight and 6 left to the guided reading.
- **Noise.** On the course exercise's own package: 84 alerts (36 CRITICAL) from its scanner versus 4 facts from this preflight, each pointing to a documented example. Across 40 benign skills: median of 1 fact per skill, and 14 with none.

### Install

**Claude Code**

```bash
git clone https://github.com/juli-amezquita/skill-security-reviewer.git
cd skill-security-reviewer
python3 tools/build_skill.py --check   # hash, hidden characters, load-time commands
mkdir -p ~/.claude/skills
cp -R skill-security-reviewer ~/.claude/skills/
```

Copy instead of symlinking: a copy pins the exact version you verified. To update, run `git pull`, the check, and the copy again.

Optional hardening: setting `"disableSkillShellExecution": true` in your Claude Code settings stops embedded shell commands in user, project and plugin skills from running at load time.

**Claude apps (web, desktop)**

Zip the `skill-security-reviewer` folder that lives inside this repository and upload it as a custom skill from your Skills settings. Do not upload the archive from GitHub's **Code → Download ZIP** as is: it nests the skill one folder too deep and the upload is rejected ("SKILL.md file must be in the top-level folder"). Unzip it first and compress only the `skill-security-reviewer` folder.

### Usage

Ask *"audit this skill"* (or *"revisa esta skill"*) and attach the `.zip` or `.skill`, point to a folder, or paste a `SKILL.md`. The skill replies in the language you write in. For packages of unknown origin, run the review in a session without connectors.

The preflight also works on its own:

```bash
python3 -I src/skill_preflight.py path/to/skill-folder
python3 -I src/skill_preflight.py package.zip --extract-to /tmp/new-empty-dir
```

Exit codes: `0` report produced, `1` usage error, `2` blocking archive issue (nothing extracted).

### Repository layout

```text
src/skill_preflight.py      Source of truth for the preflight (standard library only)
templates/                  SKILL.md text before and after Annex A
tools/build_skill.py        Builds SKILL.md, embeds the script and its sha256, runs safety checks
skill-security-reviewer/    The installable skill (generated and committed)
tests/                      Unit tests, build checks and the attack corpus
```

### Development

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest
ruff check . && mypy
python3 tools/build_skill.py           # after editing src/ or templates/
```

Rules of the house:

- Never edit `skill-security-reviewer/SKILL.md` by hand. Edit `src/` or `templates/` and rebuild.
- Keep `src/` pure ASCII and write special characters with `chr()`. Some editors and AI writing tools silently turn Unicode escape sequences into the real invisible characters; the build refuses them.

### Adding an attack you learned about

1. Append a `Technique` to `tests/test_decoy.py` with the fact the preflight must raise, or `None` if only semantic reading can catch it.
2. Run `python3 -m pytest`. If a technique that should be deterministic is not surfaced, extend the preflight in `src/`.
3. If it is a new kind of threat, add it to the catalog in `templates/skill_tail.md` and rebuild.

### Limitations

- **Static only.** It cannot see what a skill downloads at runtime, future updates, the code of its dependencies, or inside binaries.
- **The semantic layer depends on the model.** Injection against the reviewer is mitigated, not solved. For high-risk packages, read the code yourself too.
- **Language.** The instructions are in English and the skill is told to reply in the user's language. The model translates headings and verdict labels at answer time; fact categories stay in English.

### Acknowledgments

This project started from a hands-on exercise in Santiago Hernández's Claude course on Udemy: a security-review skill designed for learning. I studied it, stress-tested it and rewrote it from scratch with a different architecture (deterministic preflight plus guided semantic review). The four-level severity scale and the structured audit report come from that exercise.

### License

[MIT](LICENSE) © 2026 Juliana Amézquita

---

## Español

### El problema

Una skill es, sobre todo, un conjunto de instrucciones que el modelo sigue casi como si fueran parte de su propia configuración, más scripts opcionales que corren con los permisos del agente. Instalar una desde un foro o un repositorio cualquiera se parece más a ejecutar código ajeno que a leer un documento.

Además, la superficie de ataque cambió. Una skill maliciosa ya no necesita un script: le basta con pedirle al agente que use sus propios conectores, su memoria, tareas programadas o el navegador. En Claude Code puede ejecutar comandos de shell al cargarse mediante `allowed-tools`, `hooks` o comandos embebidos, sin pedir permiso.

### Cómo funciona

Dos capas, porque cada una detecta lo que la otra no ve:

| Capa | Qué hace | Qué detecta |
|---|---|---|
| **Preflight determinista** (`src/skill_preflight.py`) | Inventaría todos los archivos (incluidos ocultos y enlaces simbólicos), calcula sus hashes, descifra Unicode invisible y marca lo que se ejecuta al cargar | Lo que una lectura pasa por alto: carpetas ocultas, contenido escondido en Unicode, enlaces que salen del paquete, binarios disfrazados de texto, scripts sin extensión |
| **Revisión semántica guiada** (`SKILL.md`) | Reglas de aislamiento, catálogo de 12 categorías de amenazas, criterios de severidad y plantilla de informe que sigue el agente | Lo que una expresión regular no ve: intención, instrucciones dirigidas al modelo o al revisor, uso indebido de las herramientas del agente |

Decisiones de diseño:

- **Hechos, no veredictos.** El script nunca dice "segura", y un informe vacío no significa nada.
- **El revisor también es superficie de ataque.** Todo lo que trae el paquete es dato. Un texto dirigido al revisor es CRÍTICO, y si el agente siente ganas de usar una herramienta por algo que leyó en el paquete, eso cuenta como evidencia de inyección.
- **Cero dependencias, cero ejecución.** Solo biblioteca estándar. El paquete revisado nunca se importa, se ejecuta ni se siguen sus enlaces simbólicos.
- **Extracción segura.** Los zip se inspeccionan antes de extraerlos (rutas con `..`, zip bombs, entradas duplicadas o cifradas, enlaces simbólicos), y si hay un problema bloqueante no se extraen.
- **Un solo archivo que se verifica a sí mismo.** La skill es un único `SKILL.md` que lleva dentro el script y su sha256. El agente extrae el script y verifica el hash antes de ejecutarlo.

### Resultados

Una prueba pequeña y reproducible, no un benchmark:

- **Skill trampa.** Con las 15 técnicas originales, el escáner de expresiones regulares del ejercicio del curso del que partió este proyecto (un ejemplo didáctico, que nunca pretendió ser una herramienta de producción) no detectó ninguna (solo un caso de control obvio con `curl | bash`). Este preflight deja expuestas 9 de esas 15, más la pre-aprobación de herramientas en el frontmatter. El corpus de `tests/test_decoy.py` ya va en 17 técnicas: 11 las expone el preflight y 6 quedan para la lectura guiada.
- **Ruido.** Sobre el paquete del ejercicio del curso: 84 alertas (36 CRÍTICAS) de su escáner, contra 4 hechos de este preflight, cada uno apuntando a un ejemplo documentado. Sobre 40 skills normales: mediana de 1 hecho por skill, y 14 sin ninguno.

### Instalación

**Claude Code**

```bash
git clone https://github.com/juli-amezquita/skill-security-reviewer.git
cd skill-security-reviewer
python3 tools/build_skill.py --check   # hash, caracteres ocultos, comandos al cargar
mkdir -p ~/.claude/skills
cp -R skill-security-reviewer ~/.claude/skills/
```

Copia la carpeta en vez de crear un enlace simbólico: así queda fija exactamente la versión que verificaste. Para actualizar, repite `git pull`, la verificación y la copia.

Protección adicional opcional: con `"disableSkillShellExecution": true` en la configuración de Claude Code, los comandos de shell embebidos en skills de usuario, de proyecto y de plugins no se ejecutan al cargar.

**Apps de Claude (web y escritorio)**

Comprime en un zip la carpeta `skill-security-reviewer` que está dentro de este repositorio y súbela como skill personalizada desde la configuración de Skills. No subas tal cual el archivo de **Code → Download ZIP** de GitHub: deja la skill una carpeta más adentro de lo permitido y la carga falla ("SKILL.md file must be in the top-level folder"). Descomprímelo primero y comprime solo la carpeta `skill-security-reviewer`.

### Uso

Pide *"revisa esta skill"* (o *"audit this skill"*) y adjunta el `.zip` o `.skill`, indica una carpeta o pega un `SKILL.md`. La skill responde en el idioma en que le escribas. Para paquetes de origen desconocido, haz la revisión en una sesión sin conectores.

El preflight también funciona por sí solo:

```bash
python3 -I src/skill_preflight.py ruta/a/la/skill
python3 -I src/skill_preflight.py paquete.zip --extract-to /tmp/directorio-nuevo-vacio
```

Códigos de salida: `0` informe generado, `1` error de uso, `2` problema bloqueante en el archivo comprimido (no se extrae nada).

### Estructura del repositorio

```text
src/skill_preflight.py      Código fuente del preflight (solo biblioteca estándar)
templates/                  Texto del SKILL.md antes y después del Anexo A
tools/build_skill.py        Genera el SKILL.md, incrusta el script y su sha256, y corre los controles de seguridad
skill-security-reviewer/    La skill instalable (generada y versionada)
tests/                      Pruebas unitarias, controles del build y corpus de ataques
```

### Desarrollo

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest
ruff check . && mypy
python3 tools/build_skill.py           # después de editar src/ o templates/
```

Reglas de la casa:

- Nunca edites `skill-security-reviewer/SKILL.md` a mano. Edita `src/` o `templates/` y vuelve a generar.
- Mantén `src/` en ASCII puro y escribe los caracteres especiales con `chr()`. Algunos editores y herramientas de escritura con IA convierten en silencio las secuencias de escape Unicode en los caracteres invisibles reales; el build los rechaza.

### Agregar un ataque que aprendiste

1. Agrega una `Technique` en `tests/test_decoy.py` con el hecho que el preflight debe reportar, o `None` si solo la lectura semántica puede detectarlo.
2. Corre `python3 -m pytest`. Si una técnica que debería ser determinista no aparece, amplía el preflight en `src/`.
3. Si es un tipo de amenaza nuevo, agrégalo al catálogo en `templates/skill_tail.md` y vuelve a generar.

### Limitaciones

- **Solo análisis estático.** No ve lo que una skill descarga en tiempo de ejecución, sus actualizaciones futuras, el código de sus dependencias ni el interior de binarios.
- **La capa semántica depende del modelo.** La inyección contra el revisor está mitigada, no resuelta. Para paquetes de alto riesgo, lee el código tú también.
- **Idioma.** Las instrucciones están en inglés y la skill tiene la orden de responder en el idioma del usuario. El modelo traduce los títulos y las etiquetas de veredicto al responder; las categorías de hechos quedan en inglés.

### Agradecimientos

Este proyecto partió de un ejercicio práctico del curso de Claude de Santiago Hernández en Udemy: una skill de revisión de seguridad pensada para aprender. La estudié, la puse a prueba y la reescribí desde cero con otra arquitectura (preflight determinista más revisión semántica guiada). De ese ejercicio vienen la escala de severidad de cuatro niveles y el informe estructurado.

### Licencia

[MIT](LICENSE) © 2026 Juliana Amézquita
