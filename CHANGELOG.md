# Changelog

All notable changes to the OMS specification are documented in this
file.  The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Schema versions use [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Core specification (`spec.md`) — predicate type, predicate body,
  canonicalization rules, signing and verification procedures.
- Algorithm registry (`algorithm-registry.md`) — sha256 (required),
  blake2b (optional), EC P-256/P-384/P-521 key types.
- JSON Schemas for all four bundle layers:
  - `schemas/bundle.schema.json` — full OMS bundle with Sigstore
    verification material (key, certificate, sigstore keyless).
  - `schemas/envelope.schema.json` — DSSE envelope.
  - `schemas/statement.schema.json` — in-toto Statement with OMS
    predicateType constraint.
  - `schemas/predicate.schema.json` — OMS predicate body (resources,
    serialization).
- Test vectors (`test-vectors/`) — valid and invalid bundle examples
- Schema validation script (`test-vectors/validate.py`).
- CI workflow (`.github/workflows/validate-schemas.yml`) — validates
  schemas against test vectors on every push/PR.
- Versioning policy (`VERSIONING.md`).
