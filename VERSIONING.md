# Versioning

This document defines how the OMS specification and its artifacts are
versioned.

## Specification Version

The OMS specification (`spec.md`) uses a maturity lifecycle:

| Stage | Meaning |
|---|---|
| **Pre-Draft** | Exploratory; no stability guarantees. |
| **Draft** | Under active development; breaking changes possible with notice. |
| **Approved** | Stable; breaking changes require a new major version. |

The current stage is recorded in the `Status` field at the top of
`spec.md`.

## Schema Versioning

The JSON Schemas under `schemas/` use **semver** in their `$id` URIs
(e.g., `https://model_signing/predicate/v1.0/schema`).

| Change type | Version bump | Example |
|---|---|---|
| New optional field | Minor | v1.0 → v1.1 |
| Field removed or type changed | Major | v1.0 → v2.0 |
| Description / comment only | Patch (no URI change) | — |

When a schema's `$id` version changes, all schemas that reference it via
`$ref` MUST be updated accordingly.

## Bundle Media Type

OMS bundles use the Sigstore bundle media type
(`application/vnd.dev.sigstore.bundle.v0.3+json`).  OMS does **not**
define its own media type — versioning of the outer bundle format is
governed by
[sigstore/protobuf-specs RELEASE.md](https://github.com/sigstore/protobuf-specs/blob/main/RELEASE.md).

The OMS predicate type URI
(`https://model_signing/signature/v1.0`) carries its own version
independently of the bundle media type.

## Predicate Type URI

The predicate type URI is the primary OMS version signal:

```
https://model_signing/signature/v<MAJOR>.<MINOR>
```

| Change type | Effect |
|---|---|
| New optional field in predicate | Minor bump (v1.0 → v1.1); existing verifiers MUST still accept |
| Field removed, renamed, or semantics changed | Major bump (v1.0 → v2.0); new URI |
| New required field in predicate | Major bump |

Verifiers SHOULD accept any predicate type matching their supported
major version.  For example, a verifier supporting `v1.*` MUST accept
both `v1.0` and `v1.1`.

## Schema Evolution

The schemas in `schemas/` validate the **current** normative format.
They do not attempt to cover historical bundle versions.

When the bundle format evolves (e.g., a field moves from optional to
required), the process is:

1. **Update the schema** to reflect the new requirement.
2. **Document the change** in `spec.md` Section 11 (Bundle Version History)
   with the version range affected and the specific relaxation
   verifiers may apply.
3. **Update test vectors** to match the current schema.
4. **Historical bundles** are tested separately in the conformance
   suite's `historical/` category, not by the spec schema.

This follows the same approach as
[sigstore/protobuf-specs](https://github.com/sigstore/protobuf-specs/blob/main/RELEASE.md):
the protobuf definitions describe the current message format, and
backward compatibility is handled in prose and conformance tests.

## Backward Compatibility

1. **Producers** MUST generate bundles using the latest approved
   predicate version.
2. **Verifiers** MUST support the current major version and SHOULD
   support the previous major version for a deprecation period of at
   least 6 months after a new major version is approved.
3. **Schema changes** MUST NOT remove or rename required fields within
   the same major version.
4. **Test vectors** in `test-vectors/` MUST be updated whenever the
   schema changes.
5. **Verifier relaxations** for older bundles are documented in
   `spec.md` §11.1 and tested by the conformance suite's `historical/`
   test category.

## Release Process

1. Propose changes via pull request against `main`.
2. All schema changes MUST include updated test vectors and pass CI
   validation.
3. Spec stage transitions (Draft → Approved) require maintainer
   consensus per `CHARTER.md`.
4. Tag releases using `vMAJOR.MINOR.PATCH` (e.g., `v1.0.0`).
