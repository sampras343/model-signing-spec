# OpenSSF Model Signing (OMS) Specification

**Version:** 1.0-draft  
**Status:** Draft  
**Date:** 2026-04-21

## 1. Introduction

This document specifies the OpenSSF Model Signing (OMS) format for
signing and verifying machine learning models and datasets.

OMS is a thin layer on top of existing, well-established specifications.
It does **not** define its own signing envelope, signature format, or
attestation framework.  Instead it composes:

| Concern | Spec used by OMS |
|---|---|
| Signing envelope | [DSSE — Dead Simple Signing Envelope][dsse] |
| Attestation statement | [in-toto Attestation Framework v1][intoto-statement] |
| Bundle container | [Sigstore Bundle Format][sigstore-bundle] |

OMS defines **only** what these upstream specs leave to the application:

1. The **predicate type** URI.
2. The **predicate body** structure (resource manifest and serialization
   metadata).
3. The **canonicalization** rules for enumerating, hashing, and ordering
   model files.
4. The **subject** computation (root digest of the model).
5. The **verification procedure** for matching a model directory against
   the signed manifest.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [RFC 2119][rfc2119].

## 2. Normative References

| Ref ID | Document | URI |
|---|---|---|
| [DSSE] | Dead Simple Signing Envelope, v1.0 | https://github.com/secure-systems-lab/dsse |
| [DSSE-PROTO] | DSSE protocol specification | https://github.com/secure-systems-lab/dsse/blob/master/protocol.md |
| [DSSE-ENVELOPE] | DSSE envelope specification | https://github.com/secure-systems-lab/dsse/blob/master/envelope.md |
| [INTOTO-STATEMENT] | in-toto Attestation Framework, Statement v1 | https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md |
| [INTOTO-RD] | in-toto Resource Descriptor | https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md |
| [SIGSTORE-BUNDLE] | Sigstore Bundle Format | https://docs.sigstore.dev/about/bundle/ |
| [SIGSTORE-PROTO] | Sigstore protobuf specifications | https://github.com/sigstore/protobuf-specs |
| [SIGSTORE-COMMON] | Sigstore common types (sigstore_common.proto) | https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_common.proto |
| [SIGSTORE-REKOR] | Sigstore Rekor types (sigstore_rekor.proto) | https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_rekor.proto |
| [RFC 2119] | Key words for use in RFCs | https://www.rfc-editor.org/rfc/rfc2119 |
| [RFC 4648] | Base encodings (Base64) | https://www.rfc-editor.org/rfc/rfc4648 |

## 3. Terminology

**Model**: A set of one or more files that constitute a machine learning
model, dataset, or related artifact.  A model is either a single file or
a directory tree.

**OMS Bundle**: A [Sigstore Bundle][sigstore-bundle] containing a
[DSSE][dsse] envelope whose payload is an [in-toto Statement
v1][intoto-statement] with the OMS predicate type.

**Resource Descriptor**: An entry in the OMS predicate describing one
file in the model, per [in-toto Resource Descriptor][intoto-rd].

**Signing Method**: The PKI mechanism used to produce and verify the
signature.  One of: `key`, `certificate`, or `sigstore`.

## 3.1. Schemas

OMS provides machine-readable JSON Schemas (Draft 2020-12) for each
layer of the bundle that OMS constrains:

| Schema | Validates | Path |
|---|---|---|
| Bundle | Top-level Sigstore bundle with OMS constraints | [`schemas/bundle.schema.json`](./schemas/bundle.schema.json) |
| Envelope | DSSE envelope (payloadType, signatures) | [`schemas/envelope.schema.json`](./schemas/envelope.schema.json) |
| Statement | in-toto Statement with OMS predicateType | [`schemas/statement.schema.json`](./schemas/statement.schema.json) |
| Predicate | OMS predicate body (resources, serialization) | [`schemas/predicate.schema.json`](./schemas/predicate.schema.json) |

These schemas compose via `$ref`: bundle → envelope → (decoded payload)
statement → predicate.

Implementations that produce OMS bundles SHOULD validate the output
against the bundle schema.  Conformance test suites MUST validate
bundles against all four schemas.

Canonical test vectors for these schemas are published in
[`test-vectors/`](./test-vectors/).

## 4. OMS Bundle Format

An OMS bundle is a JSON file conforming to the [Sigstore Bundle
Format][sigstore-bundle].  Implementations MUST follow the Sigstore
bundle specification for the top-level structure, including:

- `mediaType` — as defined by [SIGSTORE-BUNDLE].
- `verificationMaterial` — as defined by [SIGSTORE-BUNDLE].
- `dsseEnvelope` — as defined by [DSSE-ENVELOPE].

OMS does **not** redefine any of these fields.  Their semantics,
validation rules, and versioning are governed entirely by the upstream
specifications.

### 4.1. Signing Method and Verification Material

OMS supports three signing methods.  The choice of method determines the
content of `verificationMaterial` per [SIGSTORE-BUNDLE]:

| Method | Required fields | Optional fields |
|---|---|---|
| `key` | `publicKey` per [`sigstore_common.proto#PublicKeyIdentifier`][sigstore-common] | `tlogEntries`, `timestampVerificationData` |
| `certificate` | `x509CertificateChain` per [`sigstore_common.proto#X509CertificateChain`][sigstore-common] | `tlogEntries`, `timestampVerificationData` |
| `sigstore` | `certificate` per [`sigstore_common.proto#X509Certificate`][sigstore-common], `tlogEntries` per [`sigstore_rekor.proto#TransparencyLogEntry`][sigstore-rekor] | `timestampVerificationData` per [`sigstore_bundle.proto#TimestampVerificationData`][sigstore-proto] |

**Field semantics by method:**

- **`key`:** Uses long-lived key pairs. `publicKey` identifies the
  verification key.  Producers MUST use the `hint` field (a hex-encoded
  key fingerprint).  Older bundles (pre-v1.1.0) used `rawBytes` instead;
  verifiers SHOULD accept either.  No Sigstore infrastructure is
  involved, so `tlogEntries` and `timestampVerificationData` are not
  applicable and MAY be absent.

- **`certificate`:** Uses a long-lived signing certificate and CA chain.
  `x509CertificateChain.certificates` contains the leaf certificate
  followed by the CA chain, each as a Base64-encoded DER certificate.
  Note: this is the Sigstore `X509CertificateChain` type, distinct from
  the `X509Certificate` type used by the `sigstore` method.

- **`sigstore`:** Uses Sigstore keyless signing (Fulcio + Rekor).
  `certificate` contains a single short-lived Fulcio certificate (the
  Sigstore `X509Certificate` type — not `X509CertificateChain`).
  `tlogEntries` MUST contain at least one Rekor transparency log entry.
  `timestampVerificationData` MAY contain RFC 3161 signed timestamps.

**DSSE signature fields:**

The `signatures[].keyid` field is OPTIONAL per the [DSSE
specification][dsse].  Producers MAY omit it entirely.  Verifiers MUST
accept any of: absent, empty string (`""`), or `null`.  OMS does not
use `keyid` for verification — the key is identified through
`verificationMaterial`.

### 4.2. Supported Key Types

See [Algorithm Registry](./algorithm-registry.md) for the full list of
REQUIRED and OPTIONAL key types and hash algorithms.

## 5. OMS Predicate

The DSSE envelope payload MUST be an [in-toto Statement
v1][intoto-statement].  OMS defines the predicate type and predicate
body; all other statement fields (`_type`, `subject`) follow
[INTOTO-STATEMENT] without modification.

### 5.1. Predicate Type

```
https://model_signing/signature/v1.0
```

Implementations MUST set `predicateType` to exactly this URI.

> **Historical note:** Version 0.2.0 of the reference implementation
> used `https://model_signing/Digests/v0.1` with a different predicate
> structure where file digests were placed in `subject` entries rather
> than in `predicate.resources`.  That format is deprecated and SHOULD
> NOT be produced by new implementations.  Verifiers MAY support it for
> backwards compatibility.

### 5.2. Predicate Body

The predicate body is a JSON object with two REQUIRED keys:

```json
{
  "resources": [ ... ],
  "serialization": { ... }
}
```

#### 5.2.1. `resources` — File Manifest

An array of resource descriptors, one per file included in the signing
scope.  Each entry follows the [in-toto Resource
Descriptor][intoto-rd] schema and MUST contain:

| Field | Type | Description |
|---|---|---|
| `name` | string | Relative path of the file within the model root, using `/` as the path separator. For single-file models, this is the filename. |
| `digest` | string | Hex-encoded hash of the file contents. |
| `algorithm` | string | Hash algorithm identifier (see [Section 7](#7-hashing-algorithms)). |

The `resources` array MUST contain at least one entry.

The `resources` array MUST be sorted lexicographically by the `name`
field using Unicode code point ordering.

Implementations MUST NOT include directory entries — only regular files.

> **Note:** The [in-toto Resource Descriptor][intoto-rd] defines
> additional optional fields (`uri`, `content`, `download_location`,
> `media_type`, `annotations`).  OMS does not use these fields for the
> file manifest but does not prohibit their presence.  Verifiers MUST
> ignore unrecognized fields in resource descriptors.

#### 5.2.2. `serialization` — Canonicalization Metadata

A JSON object recording the parameters used to enumerate and hash the
model files.  This metadata allows verifiers to reproduce the same
canonicalization.

| Field | Type | Required | Description |
|---|---|---|---|
| `method` | string | REQUIRED | Serialization method.  Currently always `"files"`. |
| `hash_type` | string | REQUIRED | Hash algorithm used for file digests (see [Section 7](#7-hashing-algorithms)). |
| `allow_symlinks` | boolean | REQUIRED | Whether symbolic links were followed during enumeration. |
| `ignore_paths` | array of string | OPTIONAL | Paths that were excluded from the signing scope (see [Section 6.2](#62-path-exclusion)). |

Verifiers MUST use `serialization.hash_type` to determine which hash
algorithm to use when recomputing file digests for verification.

## 6. Signing Procedure

This section defines how a signer produces an OMS bundle from a model.

### 6.1. File Enumeration

1. The signer MUST recursively enumerate all regular files under the
   model root directory (or the single file, for single-file models).

2. For each file, compute the relative path from the model root using
   `/` as the path separator, regardless of the host operating system.

3. Exclude files matching the default ignore list and any
   user-specified ignore paths (see [Section 6.2](#62-path-exclusion)).

4. If `allow_symlinks` is `false` (the default), the signer MUST NOT
   follow symbolic links.  If a symbolic link is encountered, the signer
   SHOULD report an error.

### 6.2. Path Exclusion

The following paths MUST be excluded by default:

- `.git`
- `.gitignore`
- `.gitattributes`
- `.github`

Implementations MAY exclude additional paths (e.g., `.gitmodules`).

Users MAY specify additional paths to exclude via the `--ignore-paths`
flag or equivalent API.

Excluded paths SHOULD be recorded in `serialization.ignore_paths`.

### 6.3. File Hashing

For each file in the enumeration:

1. Read the file contents as a byte sequence.
2. Compute the hash using the algorithm specified by `hash_type`.
3. Encode the hash as a lowercase hexadecimal string.

### 6.4. Resource Descriptor Construction

For each file, construct a resource descriptor (see
[Section 5.2.1](#521-resources--file-manifest)) with:

- `name`: the relative path computed in [Section 6.1](#61-file-enumeration).
- `digest`: the hex-encoded hash computed in [Section 6.3](#63-file-hashing).
- `algorithm`: the hash algorithm identifier.

Sort the resource descriptors lexicographically by `name`.

### 6.5. Subject Computation

The `subject` array of the in-toto statement MUST contain exactly one
entry representing the model as a whole:

| Field | Value |
|---|---|
| `name` | The basename of the model directory or filename (e.g., `"my-model"` for `/path/to/my-model/`). For single-file models, use the filename without the directory path. |
| `digest` | A digest computed over the canonicalized manifest.  The algorithm for computing this digest is implementation-defined. |

Producers MUST set `subject[0].name` to the basename of the model path.
Verifiers MUST NOT rely on the specific value of `subject[0].name` for
correctness — it is informational only and does not affect verification.

> **Backward compatibility note:** Some older implementations used a
> hardcoded value (e.g., `"model"`) instead of the basename.  Verifiers
> MUST accept any non-empty string.

### 6.6. Statement Assembly

Assemble the in-toto Statement v1 per [INTOTO-STATEMENT]:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [ ... ],
  "predicateType": "https://model_signing/signature/v1.0",
  "predicate": {
    "resources": [ ... ],
    "serialization": { ... }
  }
}
```

### 6.7. DSSE Signing

Wrap the statement in a DSSE envelope per [DSSE-PROTO]:

1. Serialize the statement as a JSON byte string (the "payload").
2. Set `payloadType` to `"application/vnd.in-toto+json"` per
   [INTOTO-STATEMENT].
3. Compute the DSSE Pre-Authentication Encoding (PAE) and sign it with
   the signing key per [DSSE-PROTO].
4. Encode the payload as Base64 per [RFC 4648].

### 6.8. Bundle Assembly

Wrap the DSSE envelope in a Sigstore bundle per [SIGSTORE-BUNDLE],
including the appropriate `verificationMaterial` for the signing method
(see [Section 4.1](#41-signing-method-and-verification-material)).

## 7. Hashing Algorithms

See [Algorithm Registry](./algorithm-registry.md) for the canonical
list of supported hash algorithms and their identifiers.

The `algorithm` field in resource descriptors and the `hash_type` field
in serialization metadata MUST use the identifiers defined in the
algorithm registry.

## 8. Verification Procedure

### 8.1. Bundle Parsing

Parse the OMS bundle file as JSON and validate it against the OMS bundle
schema ([`schemas/bundle.schema.json`](./schemas/bundle.schema.json))
and the Sigstore bundle format per [SIGSTORE-BUNDLE].

Implementations MUST validate the `mediaType` field per
[SIGSTORE-BUNDLE].

### 8.2. Signature Verification

Verify the DSSE envelope signature per [DSSE-PROTO] using the
verification material from the bundle.  The specifics depend on the
signing method:

| Method | Verification procedure |
|---|---|
| `key` | Verify the DSSE signature against the public key identified by `verificationMaterial.publicKey`. |
| `certificate` | Validate the certificate chain in `verificationMaterial` against the trusted root CA, then verify the DSSE signature against the leaf certificate's public key.  The leaf certificate MUST be within its validity period. |
| `sigstore` | Per [SIGSTORE-BUNDLE], including transparency log verification. |

OMS does not define the cryptographic verification procedure — it
defers entirely to [DSSE-PROTO] and [SIGSTORE-BUNDLE].

### 8.3. Statement Validation

After signature verification succeeds, decode the DSSE payload and
validate it as an in-toto Statement v1 per [INTOTO-STATEMENT].
Implementations SHOULD validate the decoded statement against
[`schemas/statement.schema.json`](./schemas/statement.schema.json):

1. `_type` MUST be `"https://in-toto.io/Statement/v1"`.
2. `predicateType` MUST be `"https://model_signing/signature/v1.0"`.
3. `predicate` MUST be present and conform to
   [`schemas/predicate.schema.json`](./schemas/predicate.schema.json).

### 8.4. Manifest Verification

Verify the model contents against the signed manifest:

1. Read `serialization.hash_type` to determine the hash algorithm.
2. Read `serialization.ignore_paths` (if present) to determine excluded
   paths.
3. Enumerate all files in the model directory per
   [Section 6.1](#61-file-enumeration), applying the same exclusion
   rules.
4. For each resource descriptor in `resources`:
   a. Verify that a file with the matching `name` exists in the model.
   b. Compute the hash of that file using the algorithm from step 1.
   c. Verify that the computed hash matches `digest`.
5. Verify that no files exist in the model that are not accounted for
   in `resources` (unless the `--ignore-unsigned-files` option is set).

If any check in steps 4–5 fails, the verifier MUST report verification
failure.

### 8.5. Unsigned File Handling

By default, files present in the model directory but absent from
`resources` (after applying exclusions) MUST cause verification to fail.

When the `--ignore-unsigned-files` option (or equivalent) is enabled,
the verifier MUST still verify all files listed in `resources` but MUST
NOT reject the model for containing additional unlisted files.

## 9. Bundle File Conventions

The OMS bundle is a detached signature — it is a separate file from the
model it signs.

- The bundle file SHOULD be named with a `.sig` extension.
- The bundle file SHOULD be stored alongside the model (in the same
  directory or parent directory).
- The bundle file itself SHOULD be excluded from the signing scope.

## 10. Conformance

An implementation conforms to this specification if it:

1. Produces bundles that conform to [SIGSTORE-BUNDLE], [DSSE], and
   [INTOTO-STATEMENT].
2. Uses the predicate type and predicate body structure defined in
   [Section 5](#5-oms-predicate).
3. Follows the file enumeration and hashing rules defined in
   [Section 6](#6-signing-procedure).
4. Implements the verification procedure defined in
   [Section 8](#8-verification-procedure).
5. Supports at minimum the `sha256` hash algorithm and the `key`
   signing method.

A verifier MAY additionally support the deprecated v0.1 predicate
format (see [Section 5.1](#51-predicate-type)) for backwards
compatibility, but MUST NOT produce it.

## 11. Bundle Version History

This section documents how the OMS bundle format has evolved.  The
JSON Schemas in `schemas/` validate the **current** format.  Verifiers
SHOULD support at least one prior version for a deprecation window of
6 months after a new version is released (see
[`VERSIONING.md`](./VERSIONING.md)).

| Version range | `predicateType` | Notable differences from current |
|---|---|---|
| **v1.1.0+** (current) | `https://model_signing/signature/v1.0` | Normative format. See Section 4.1 for per-method field requirements. |
| v0.3.1 – v1.0.0 | `https://model_signing/signature/v1.0` | Same predicate structure but: `publicKey` uses `rawBytes`+`keyDetails` instead of `hint`; `signatures[].keyid` may be `null`; `serialization.ignore_paths` absent. |
| v0.2.0 | `https://model_signing/Digests/v0.1` | Deprecated predicate layout: file digests placed in `subject` entries instead of `predicate.resources`. No `serialization` object. |

### 11.1. Known Field Differences Across Versions and Implementations

| Field | Current normative | Known variants | Verifier guidance |
|---|---|---|---|
| `publicKey` | `{"hint": "<fingerprint>"}` | Pre-v1.1.0: `{"rawBytes": "...", "keyDetails": "..."}` | MUST accept either `hint` or `rawBytes` |
| `signatures[].keyid` | Optional, MAY be omitted | `""` (Python), absent (Go), `null` (pre-v1.1.0) | MUST accept absent, empty string, or null |
| `subject[0].name` | Basename of the model path | `"model"` (some Python versions), directory basename (Go) | MUST accept any non-empty string; informational only |
| `tlogEntries` | Required for `sigstore`; optional for `key`/`certificate` | `[]` (Python key/cert), absent (Go key/cert), populated (sigstore) | MUST require for `sigstore`; MUST accept absent or empty for `key`/`certificate` |
| `serialization.ignore_paths` | Optional array | Absent in pre-v1.1.0 bundles | MUST accept absence |
| `certificate` vs `x509CertificateChain` | `certificate` for `sigstore`; `x509CertificateChain` for `certificate` method | These are distinct Sigstore protobuf types, not interchangeable | MUST match field to method |

### 11.2. Verifier Backward Compatibility

When a verifier encounters a bundle from an older version, it SHOULD
apply the following relaxations:

1. **`publicKey.rawBytes` instead of `publicKey.hint`** (pre-v1.1.0):
   Accept `rawBytes` (and optionally `keyDetails`) as an alternative
   to `hint` for key identification.

2. **`signatures[].keyid` is `null` or absent**: Accept any of
   absent, empty string, or `null`.  OMS does not use `keyid` for
   verification.

3. **`serialization.ignore_paths` absent** (pre-v1.1.0): Treat as
   if no user-specified paths were excluded (default exclusions still
   apply per §6.2).

4. **Deprecated predicate type** (v0.2.0): The verifier MAY support
   `https://model_signing/Digests/v0.1` for backward compatibility
   but MUST NOT produce bundles with this predicate type.

Producers MUST always generate bundles conforming to the current
version.

### 11.2. Schema and Conformance Testing

The schemas in `schemas/` validate **only** the current format.
Backward compatibility is tested separately in the conformance suite
via the `historical/` test category, which exercises verifier
relaxations documented above.

## Appendix A: Complete Bundle Example

A signed OMS bundle for a two-file model using key-based signing:

```json
{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {
    "publicKey": {
      "hint": "e8450dec4eb99dae995da9af1bc2cc9f76ed669ee2e744f57abba763df3e3f8e"
    }
  },
  "dsseEnvelope": {
    "payload": "<base64-encoded in-toto statement>",
    "payloadType": "application/vnd.in-toto+json",
    "signatures": [
      {
        "sig": "<base64-encoded signature>",
        "keyid": ""
      }
    ]
  }
}
```

The decoded in-toto statement payload:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "my-model",
      "digest": {
        "sha256": "92745110b1ab4368471cbe31664e10174e954b113a3df333db860317b2c6dec4"
      }
    }
  ],
  "predicateType": "https://model_signing/signature/v1.0",
  "predicate": {
    "resources": [
      {
        "name": "config.json",
        "digest": "5e472403951781d18d5f790aa5b3316a5f535fc37a1052f6659c9c6af82e3643",
        "algorithm": "sha256"
      },
      {
        "name": "weights.bin",
        "digest": "4555555dc68d872c2270ba89ecc5f6f094812f65372b37e50071fe5168031c49",
        "algorithm": "sha256"
      }
    ],
    "serialization": {
      "method": "files",
      "hash_type": "sha256",
      "allow_symlinks": false,
      "ignore_paths": [
        ".git",
        ".gitignore",
        ".gitattributes",
        ".github"
      ]
    }
  }
}
```

## Appendix B: Relationship to Upstream Specifications

```
┌─────────────────────────────────────────────────┐
│              Sigstore Bundle                    │
│  (mediaType, verificationMaterial)              │
│  Spec: https://docs.sigstore.dev/about/bundle/  │
│                                                 │
│  ┌───────────────────────────────────────────┐  │
│  │           DSSE Envelope                   │  │
│  │  (payloadType, payload, signatures)       │  │
│  │  Spec: https://github.com/secure-systems- │  │
│  │        lab/dsse/blob/master/protocol.md   │  │
│  │                                           │  │
│  │  ┌─────────────────────────────────────┐  │  │
│  │  │     in-toto Statement v1            │  │  │
│  │  │  (_type, subject, predicateType)    │  │  │
│  │  │  Spec: https://github.com/in-toto/  │  │  │
│  │  │        attestation/.../statement.md │  │  │
│  │  │                                     │  │  │
│  │  │  ┌───────────────────────────────┐  │  │  │
│  │  │  │     OMS Predicate  ◄── THIS   │  │  │  │
│  │  │  │  (resources, serialization)   │  │  │  │
│  │  │  │  Spec: THIS DOCUMENT          │  │  │  │
│  │  │  └───────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

OMS defines only the innermost layer.  Everything else is governed by
the referenced upstream specifications.

[dsse]: https://github.com/secure-systems-lab/dsse
[dsse-proto]: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
[intoto-statement]: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
[intoto-rd]: https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md
[sigstore-bundle]: https://docs.sigstore.dev/about/bundle/
[sigstore-proto]: https://github.com/sigstore/protobuf-specs
[sigstore-common]: https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_common.proto
[sigstore-rekor]: https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_rekor.proto
[rfc2119]: https://www.rfc-editor.org/rfc/rfc2119
