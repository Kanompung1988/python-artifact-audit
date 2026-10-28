# Technical sources (reviewed 2026-10-28)

- [PyPA Binary distribution format (wheel)](https://packaging.python.org/en/latest/specifications/binary-distribution-format/): ZIP container and `.dist-info/METADATA`, `WHEEL`, `RECORD` requirements.
- [PyPA Source distribution format](https://packaging.python.org/en/latest/specifications/source-distribution-format/): modern `.tar.gz` layout with one root, `pyproject.toml` and `PKG-INFO`; legacy caveats.
- [PEP 427](https://peps.python.org/pep-0427/): wheel format origins and installer structure.
- [Agent Skills specification](https://agentskills.io/specification): discovery metadata, SKILL.md procedure, relative script/reference links and `skills-ref` validation.

These are technical standards and baseline documentation, not measured evidence that leaks are common or that this project's checks are a full conformance suite. Dates refer to this project's review, not to the date the standards were introduced.
