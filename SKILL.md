---
name: python-artifact-audit
description: Inspect built Python wheels and source distributions offline for accidental sensitive-looking filenames, risky archive member paths, links, duplicate entries and missing distribution metadata. Use before publishing to PyPI or attaching release artifacts to CI, without installing or extracting packages.
license: MIT
compatibility: Python 3.10+ standard library. Local .whl, .tar.gz, .tgz or .zip artifacts; no PyPI, credentials or network access.
metadata:
  author: AREAZERO Skill Lab
  version: "1.0.0"
---

# Python artifact release audit

## Trigger
Use when an agent has **built** Python wheel/source archives ready for a publish review, or a maintainer wants a filename/metadata inventory before a trusted release. Prefer scanning exactly the artifacts from the release pipeline, not the Git working tree.

## Non-trigger
Do not use for dependency malware detection, package installation, signature verification, dependency resolution, SBOM generation, or a guarantee that a credential's **contents** are not present in a file. This tool does not examine source code or record hashes.

## Workflow
1. Build the wheel and sdist with the project's standard build pipeline. Never execute untrusted distributions as part of this audit.
2. Run `python scripts/audit.py dist/*.whl dist/*.tar.gz --format markdown --fail-on high`. A single artifact path is also accepted.
3. Review `PA001–PA007` findings and locate each member in the corresponding build pipeline. See [rule reference](references/RULES.md) and [primary packaging sources](references/SOURCES.md).
4. If a sensitive-looking path is included, investigate the build config and clean the **published artifact**; do not paste or expose the secret's bytes. A name-only hit is not proof a credential exists.
5. If `PA004` appears, inspect the wheel build backend and ensure exactly one `.dist-info` directory containing `METADATA`, `WHEEL` and `RECORD`. If `PA007` appears, check modern sdist layout and legacy exceptions.
6. Rebuild from a clean workspace, audit the new exact artifacts, and report command, filenames, warnings and exit code. Do not claim a passed audit without running the command.

## Examples and exit statuses
Run `python scripts/audit.py examples/safe-1.0-py3-none-any.whl --format json --fail-on high` (exit **0**); run `python scripts/audit.py examples/unsafe-1.0-py3-none-any.whl --format json --fail-on none` to inspect synthetic findings without blocking. Check real thresholds: **0** no findings at/above threshold; **2** review findings; **1** invalid input/malformed archive. `--fail-on none` is reporting only.

## Safety limits
Archive members are **never extracted or executed**; only ZIP/tar headers, names, size and flags are read. Declared uncompressed bytes, compressed archive size and member count have conservative caps; CLI aborts on unreadable/oversize files, encrypted ZIP members and symlinked input archives. Tar/ZIP parser behavior and package formats are more complex than these checks: a clean result is **not** a security guarantee. Inspect only release candidates from reasonably trusted sources. `sdist .zip` is supported as a legacy preview, not a claim that it conforms to the modern `.tar.gz` standard.
