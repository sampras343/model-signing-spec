# Conformance Test Suite Reference

This document is the technical reference for the OMS (Open Model Signing) conformance
test suite. It covers the structure of `test-suite.json`, how generators consume it, and
how to add new tests.

## 1. Architecture Overview

`test-suite.json` is the single source of truth for every test case. Generators and the
test runner both read from it. The flow works as follows:

```
test-suite.json (declares all tests, models, keys, methods, expected outcomes)
       |
       +---> generate_keys.py    --> assets/keys/...     (PKI material)
       +---> generate_models.py  --> assets/models/...   (fixture directories)
       +---> generate_bundles.py --> test-cases/verify/   (bundle.sig files)
       |
       v
  Test Runner (action.py)
       |
       +-- reads test-suite.json
       +-- resolves model/key paths via defaults + overrides
       +-- invokes adapter entrypoint (sign-model / verify-model)
       +-- compares exit code against "expect" field
       +-- reports pass/fail per test ID
```

**Directory layout:**

```
conformance/
  test-suite.schema.json          # JSON Schema for test-suite.json
  test/
    assets/
      generate_keys.py
      generate_models.py
      generate_bundles.py
      keys/                       # generated key material
      models/                     # generated model fixtures
    test-cases/
      test-suite.json             # the single source of truth
      verify/
        positive/                 # pre-committed bundles, expect pass
        negative/                 # pre-committed bundles, expect fail
        historical/               # committed bundles from older versions
```

## 2. Test Categories

### roundtrip (31 tests)

Signs a model, then verifies the resulting bundle in one operation. Exercises the full
signing and verification path. No pre-committed bundle needed -- the bundle is produced
at test time.

Tests here cover: EC curve variants (P-256/384/521), ignore-paths, symlink rejection,
certificate chains, self-signed certs, sigstore OIDC, deterministic signing, empty model
rejection, sig-inside-model, and model edge cases (binary, unicode, special chars).

### verify-positive (8 tests)

Verifies a pre-committed `bundle.sig` against a known model and expects success. These
test "can this implementation verify a known-good bundle?" without requiring it to sign.
Includes cross-implementation interop tests (bundles signed by Go, verified by test
client).

### verify-negative (27 tests)

Verifies a pre-committed `bundle.sig` and expects failure. Every test has `"expect":
"fail"` inherited from category defaults. Covers: tampered content, wrong keys, wrong
CA, expired certs, method mismatches, malformed bundles (empty, truncated, corrupted,
missing envelope), wrong metadata (mediaType, payloadType, statement type, predicate),
missing files, extra files, empty resources, missing serialization, and no signatures.

### verify-historical (13 tests)

Verifies bundles produced by older implementation versions (v0.2.0 through v1.1.0) to
ensure backwards compatibility. Each test ships its own model directory and
verify-material inside its `test_dir`. Uses `model_relative_to: "test_dir"` and
`keys_relative_to: "test_dir"` to reference these self-contained artifacts.

## 3. Defaults Inheritance

Configuration merges in three layers: **category defaults < method defaults < test**.
Each layer can provide `sign`, `verify`, path resolution, and behavioral flags.

**Resolution order (most specific wins):**

```
global_defaults        (defined at top level, currently unused)
  <- category.defaults (e.g. model_relative_to, expect)
  <- category.method_defaults[method]  (e.g. key paths per method)
  <- test case fields  (explicit overrides)
```

**Example -- how `key-simple` in roundtrip resolves:**

| Field | Source | Value |
|---|---|---|
| `model_relative_to` | category defaults | `"assets"` |
| `expect` | schema default | `"pass"` |
| `sign.private_key` | method_defaults.key.sign | `"keys/certificate/signing-key.pem"` |
| `verify.public_key` | method_defaults.key.verify | `"keys/certificate/signing-key-pub.pem"` |
| `verify.ignore_paths` | test-level override | `["ignore-me"]` |

**Example -- how `key-p256` overrides signing key:**

| Field | Source | Value |
|---|---|---|
| `sign.private_key` | test-level `sign` | `"keys/p256/signing-key.pem"` |
| `verify.public_key` | test-level `verify` | `"keys/p256/signing-key-pub.pem"` |

**Category defaults summary:**

| Category | `model_relative_to` | `keys_relative_to` | `expect` |
|---|---|---|---|
| roundtrip | `assets` | `assets` | `pass` |
| verify-positive | `assets` | `assets` | `pass` |
| verify-negative | `assets` | `assets` | `fail` |
| verify-historical | `test_dir` | `test_dir` | `pass` |

## 4. Model Types Reference

| Model | Files | Used by |
|---|---|---|
| `simple` | `signme-1` (9B), `signme-2` (8B), `ignore-me` (0B) | key-simple, certificate-simple, key-p256/384/521, symlink tests, most negative tests |
| `single-file` | `model.bin` (256B, `0xEF` repeated) | key-single-file, sigstore-single-file |
| `multi-file` | `config.json`, `weights.bin` (1024B), `subdir/adapter.bin` (512B) | key-multi-file, certificate-multi-file, sigstore-multi-file |
| `binary-content` | `header.bin` (10B, PNG-like), `weights.bin` (1024B, 0x00..0xFF x4) | key-binary-content |
| `empty` | `.gitignore` only (no signable files) | key-empty-model-rejected (expect: fail) |
| `with-dotfiles` | `.config`, `.env.example`, `model.bin` | key-dotfile-included |
| `with-empty-file` | `empty.bin` (0B), `signme-1` (8B) | key-empty-file |
| `with-git-dir` | `model.bin`, `.git/HEAD`, `.github/ci.yml`, `.gitignore`, `.gitattributes` | key-default-ignores |
| `hidden-subdir` | `model.bin`, `.cache/weights.bin`, `.local/share/data.bin` | key-files-in-hidden-dir |
| `with-nested-gitignore` | `model.bin`, `subdir/.gitignore` | key-nested-git-not-excluded |
| `with-nested-ignore` | `ignore-me`, `signme-1`, `subdir/ignore-me` | key-ignore-paths-exact-match |
| `unicode-names` | `weights.bin`, `模型.bin` (NFC-normalized) | key-unicode-filename |
| `special-chars` | `file (copy).bin`, `normal.bin`, `path with spaces/model.bin` | key-special-chars-path |

**When to use which model:** Use `simple` as the default for tests that focus on
signing/verification logic rather than model structure. Use specialized models only when
testing the specific edge case they represent (binary content, Unicode paths, etc.).

## 5. Key Types Reference

| Directory | Curve | Files | Purpose |
|---|---|---|---|
| `certificate/` | P-384 | ca-cert, int-ca-cert, signing-key, signing-key-pub, signing-key-cert, ca-priv*, int-ca-priv* | 3-level PKI: root CA -> intermediate CA -> leaf. Default for all key/certificate tests |
| `expired/` | P-384 | signing-key*, signing-key-cert* | Leaf cert with notAfter=2020-01-02. Used by generate_bundles.py only |
| `p256/` | P-256 | signing-key, signing-key-pub | EC curve variant testing |
| `p384/` | P-384 | signing-key, signing-key-pub | EC curve variant testing |
| `p521/` | P-521 | signing-key, signing-key-pub | EC curve variant testing |
| `self-signed/` | P-256 | signing-key, signing-cert, signing-key-pub* | Self-signed cert with code-signing EKU |
| `wrong/` | P-256 | wrong-key-pub, wrong-ca-cert, wrong-key* | Unrelated key/CA for negative tests |

*Files marked with \* are internal to generation or unused by tests.*

**Certificate chain (3-level PKI):**

```
[Root CA]  ca-cert.pem  (self-signed, P-384, keyCertSign)
    |
    +--- signs --->  [Intermediate CA]  int-ca-cert.pem  (P-384, keyCertSign, pathLen=0)
                          |
                          +--- signs --->  [Leaf]  signing-key-cert.pem  (P-384, digitalSignature, codeSigning EKU)
```

Verification requires: `cert_chain: ["keys/certificate/ca-cert.pem"]` (root CA as trust
anchor). Signing requires: private key + leaf cert + `cert_chain:
["keys/certificate/int-ca-cert.pem"]` (intermediate).

## 6. Bundle Generation Reference

### Sign-based bundles (7)

Generated by invoking the adapter entrypoint to sign a model. Each produces a real
Sigstore bundle via the implementation under test.

| Test case | Method | Model | Notes |
|---|---|---|---|
| positive/key-simple | key | simple | Baseline; also source for 8 negative copies |
| positive/certificate-simple | certificate | simple | Source for 3 negative copies |
| positive/key-multi-file | key | multi-file | No ignore-paths |
| positive/key-ignore-paths | key | simple | Tests ignore-paths |
| positive/key-single-file | key | single-file | Single file model |
| positive/key-simple-ignore-unsigned-files | key | simple | Harness injects extra.bin after signing |
| negative/certificate-expired_fail | certificate | simple (temp copy) | Signs with expired key/cert |

### Copy-based negative bundles (11)

Valid bundles reused in contexts that should cause verification failure. The bundle
itself is correct; the test changes what is passed to verify (wrong key, model
modifications, method mismatch).

| Test case | Copied from | Why it fails |
|---|---|---|
| key-simple-tampered-content_fail | key-simple | model_modifications.tamper changes signme-1 |
| key-simple-wrong-key_fail | key-simple | verify uses wrong-key-pub.pem |
| key-simple-missing-file_fail | key-simple | model_modifications.delete removes signme-2 |
| key-simple-extra-file_fail | key-simple | model_modifications.inject adds injected.bin |
| key-verify-as-certificate_fail | key-simple | Verified with certificate method |
| key-verify-as-sigstore_fail | key-simple | Verified with sigstore method |
| key-missing-file-with-ignore-unsigned_fail | key-simple | Missing manifest file, ignore_unsigned on |
| key-tampered-with-ignore-unsigned_fail | key-simple | Tampered file, ignore_unsigned on |
| certificate-simple-wrong-ca_fail | certificate-simple | verify uses wrong-ca-cert.pem |
| certificate-verify-as-key_fail | certificate-simple | Verified with key method |
| certificate-verify-as-sigstore_fail | certificate-simple | Verified with sigstore method |

### Mutation-based bundles (7)

Start from the key-simple bundle, parse JSON, modify one field, write back. The
signature becomes invalid for the modified field but the structure is otherwise intact.

| Test case | Mutation | Spec |
|---|---|---|
| key-simple-wrong-mediatype_fail | `mediaType` -> `"application/json"` | 8.1 |
| key-simple-wrong-payload-type_fail | `payloadType` -> `"application/octet-stream"` | 6.7, 8.1 |
| key-simple-wrong-statement-type_fail | `_type` -> `".../Statement/v0.1"` | 8.3 |
| malformed-wrong-predicate_fail | `predicateType` -> wrong URL | 5.1, 8.3 |
| key-simple-empty-resources_fail | `resources` -> `[]` | 5.2.1 |
| key-simple-missing-serialization_fail | removes `serialization` key | 5.2.2, 8.3 |
| key-simple-no-signature_fail | `signatures` -> `[]` | 8.1 |

### Handcrafted bundles (4)

Created directly as raw bytes or minimal JSON. No signing tool used.

| Test case | Content | Spec |
|---|---|---|
| malformed-empty-bundle_fail | Zero bytes | 8.1 |
| key-simple-truncated-bundle_fail | First 100 bytes of key-simple | 8.1 |
| key-simple-corrupted-bundle_fail | `{"garbage": true}` | 8.1 |
| malformed-missing-envelope_fail | Valid JSON, has mediaType + verificationMaterial, no dsseEnvelope | 8.1 |

### Committed bundles (not generated, 25)

These bundles are checked into the repository because they require external signing
infrastructure or represent historical artifacts:

- **2 Go interop** (positive): `certificate-simple-go`, `key-simple-go`
- **4 sigstore negative**: `sigstore-tampered-content_fail`, `sigstore-verify-as-key_fail`,
  `sigstore-wrong-identity_fail`, `sigstore-wrong-issuer_fail`
- **13 historical**: all `historical-v*` tests (v0.2.0 through v1.1.0)

## 7. How to Add a New Test Case

### Add a roundtrip test

1. Choose or create a model in `generate_models.py`.
2. Add the test entry to `categories.roundtrip.tests` in `test-suite.json`:

```json
{
  "id": "key-my-new-test",
  "description": "Key roundtrip testing <specific behavior>",
  "spec_refs": ["<section>"],
  "method": "key",
  "model": "models/<model-name>",
  "expected_signed_files": ["file1", "file2"]
}
```

3. Key/cert paths are inherited from `method_defaults`. Override `sign` or `verify`
   blocks only if the test uses non-default keys.
4. If the test should fail (e.g., empty model rejection), add `"expect": "fail"`.

### Add a verify-negative test with a new mutation

1. Add the test entry to `categories.verify-negative.tests`:

```json
{
  "id": "key-simple-my-mutation_fail",
  "description": "FAIL: <reason>",
  "spec_refs": ["<section>"],
  "method": "key",
  "model": "models/simple",
  "test_dir": "negative/key-simple-my-mutation_fail",
  "verify": { "ignore_paths": ["ignore-me"] }
}
```

2. Add the mutation function in `generate_bundles.py`:

```python
def _mutate_my_field(b: dict) -> None:
    payload = _decode_payload(b)
    payload["predicate"]["myField"] = "wrong-value"
    _encode_payload(b, payload)

_mutate_bundle(
    key_simple_bundle,
    negative / "key-simple-my-mutation_fail" / "bundle.sig",
    _mutate_my_field,
)
```

3. Run `python generate_bundles.py <entrypoint>` to produce the bundle.
4. Verify the test fails by running the suite.

### Add a new model type

1. Write a generator function in `generate_models.py`:

```python
def _gen_my_model(root: Path) -> None:
    _write(root / "data.bin", b"content")
```

2. Register it in `_GENERATORS`:

```python
_GENERATORS = {
    ...
    "my-model": _gen_my_model,
}
```

3. Reference it in test-suite.json as `"model": "models/my-model"`.
4. Run `python generate_models.py` to create the fixture.

### Add a new key type

1. Add generation logic in `generate_keys.py` under `generate_all_keys()`.
2. Reference the output path in test-suite.json via `sign` or `verify` blocks:

```json
"sign": { "private_key": "keys/my-type/signing-key.pem" },
"verify": { "public_key": "keys/my-type/signing-key-pub.pem" }
```

3. Run `python generate_keys.py` to generate the material.

## 8. Spec Coverage Matrix

Spec references use `"spec_refs": ["<section>"]` notation. Each section below lists the
tests that exercise it.

| Spec Section | Area | Test IDs |
|---|---|---|
| 4.1 | Signing methods (key, certificate, sigstore) | key-simple, certificate-simple, certificate-self-signed, all sigstore-\*, all method-mismatch \*-verify-as-\*_fail |
| 4.2 | EC curve support | key-p256, key-p384, key-p521 |
| 5.1 | Predicate type | malformed-wrong-predicate_fail |
| 5.2 | In-toto statement structure | key-simple, certificate-simple |
| 5.2.1 | Resources array requirements | key-simple-empty-resources_fail |
| 5.2.2 | Serialization requirement | key-simple-missing-serialization_fail |
| 6.1 | Model directory requirements | key-multi-file, key-empty-model-rejected, key-single-file, sigstore-multi-file |
| 6.1.1 | Symlink handling | key-symlink-cycle, key-symlink-default-rejected, key-symlink-outside-root |
| 6.1.2 | Path encoding | key-single-file, key-multi-file, key-special-chars-path, key-unicode-filename |
| 6.2 | Default excludes and ignore-paths | key-default-ignores, key-dotfile-included, key-ignore-paths, key-files-in-hidden-dir, key-sig-inside-model |
| 6.2.1 | Exact path matching for ignores | key-ignore-paths-exact-match, key-nested-git-not-excluded |
| 6.3.1 | Binary content hashing | key-binary-content, key-empty-file |
| 6.4 | Manifest construction | key-simple, key-multi-file |
| 6.5 | Deterministic signing | key-simple-deterministic |
| 6.5.1 | Manifest reproducibility | key-simple-deterministic |
| 6.7 | DSSE payloadType | key-simple-wrong-payload-type_fail |
| 7 | Sigstore bundle structure | sigstore-tampered-content_fail |
| 8.1 | Bundle parsing and validation | key-simple, all malformed-\*_fail, wrong-mediatype, truncated, corrupted, no-signature |
| 8.2 | Signature and certificate verification | key-simple, certificate-simple, key-simple-wrong-key_fail, certificate-simple-wrong-ca_fail, certificate-expired_fail, sigstore-wrong-identity/issuer |
| 8.3 | Statement and predicate validation | key-simple, key-simple-wrong-statement-type_fail, malformed-wrong-predicate_fail, key-simple-missing-serialization_fail |
| 8.4 | File integrity checks | key-simple, key-simple-tampered-content_fail, key-simple-missing-file_fail, key-simple-extra-file_fail |
| 8.5 | ignore_unsigned_files flag | key-ignore-unsigned, key-simple-ignore-unsigned-files, key-missing-file-with-ignore-unsigned_fail, key-tampered-with-ignore-unsigned_fail |
| 9 | Signature file auto-exclusion | key-sig-inside-model, sigstore-sig-inside-model |
| 11 | Backwards compatibility and interop | all historical-\*, certificate-simple-go, key-simple-go |
