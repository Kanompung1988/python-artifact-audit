# Finding reference — Python Artifact Audit

| Rule | Severity | Detection | Next action |
|---|---|---|---|
| PA001 | Critical | Absolute, traversal, ambiguous separators/control member path | Rebuild artifact; inspect backend output; do not extract |
| PA002 | High | Filename such as `.env.production`, `.pypirc`, `id_rsa`, `.pem` or `.key` | Verify whether the file was intended and remove from artifacts if not; do **not** read or report its contents |
| PA003 | Medium | `.git`, `__pycache__`, `.tox`, or other cache/repo metadata | Exclude accidental build inputs and rebuild |
| PA004 | High | Wheel has zero/multiple `.dist-info` directories or lacks METADATA, WHEEL or RECORD | Repair packaging backend; verify wheel structure |
| PA005 | High | Symbolic or hard link entry | Review archive producer/installer compatibility; avoid extraction |
| PA006 | High | Case-insensitive collision or duplicate file path | Avoid ambiguous installer/platform resolution |
| PA007 | High/Medium | Source archive missing PKG-INFO or pyproject.toml, or inconsistent root layout | Compare modern spec; legacy archives may be deliberately different |

**Deliberate omissions:** this audit does not open file data to inspect secrets; it does not validate RECORD hashes, wheel tags, METADATA fields, license semantics, archive signatures, dependency vulnerabilities, or package import behavior. The format standards describe metadata requirements, but a syntactically acceptable archive can still be malicious. Path matching is heuristic. Count/size caps prevent some resource issues but are not a robust sandbox for adversarial compression formats.
