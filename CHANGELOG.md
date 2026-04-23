# Changelog

All notable changes to the OMS specification are documented in this
file.  The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Schema versions use [Semantic Versioning](https://semver.org/).

## [1.0.0]

### Added
- Core specification (`SPEC.md`) — predicate type, predicate body,
  canonicalization rules, signing and verification procedures.
- Algorithm registry (`algorithm-registry.md`) — sha256 (required),
  blake2b (optional), blake3 (optional), EC P-256/P-384/P-521 key types.
- JSON Schemas (`schemas/`) — bundle, envelope, statement, predicate.
- Shard serialization (`file-shard-<N>`) support in spec and schema.
- Symbolic link handling rules (§6.1.1).
- Path canonicalization rules (§6.1.2).
- Path exclusion matching semantics (§6.2.1).
- Root digest computation algorithm (§6.5.1).
- Test vectors (`test-vectors/`) — valid and invalid bundle examples.
- Schema validation script and CI workflow.
- Versioning policy (`VERSIONING.md`).
