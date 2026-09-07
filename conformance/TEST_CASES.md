# Conformance test cases

**90 tests** total: **37 roundtrip** (live sign, then verify) and **53 verify** (pre-committed offline bundles). This document indexes the **Open Model Signing (OMS)** conformance suite in this repository. Requirements are as defined in the [OMS Specification](https://github.com/ossf/model-signing-spec/blob/main/spec/v1.0.md); section references below use the same numbering as that spec.

**oms-schemas:** Every successful roundtrip run validates produced bundles and decoded DSSE payloads against the published OMS JSON Schemas from the `oms-schemas` package (outer bundle, statement, predicate, resources), in addition to the test harness’s own structural checks.

---

## Spec coverage matrix

| Spec Section | Requirement | Test(s) | Status |
|---|---|---|---|
| §4.1 | key method - publicKey in verificationMaterial | All key roundtrip + verify tests | Covered |
| §4.1 | certificate method - x509CertificateChain | certificate-simple, certificate-multi-file, etc. | Covered |
| §4.1 | sigstore method - certificate + tlogEntries | sigstore-simple, sigstore-multi-file, historical-v0.3.1/v1.0.0/v1.0.1/v1.1.0-sigstore | Covered (CI-only) |
| §4.1 | sigstore wrong identity rejection | sigstore-wrong-identity_fail | Covered (CI-only) |
| §4.1 | sigstore wrong issuer rejection | sigstore-wrong-issuer_fail | Covered (CI-only) |
| §4.1 | Accept hint or rawBytes in publicKey | historical-v0.3.1/v1.0.0 (rawBytes) vs v1.1.0 (hint) | Covered |
| §4.1 | Accept keyid absent/empty/null | Go vs Python bundles | Covered |
| §4.1 | Certificate validity period enforced | certificate-expired_fail, certificate-not-yet-valid_fail | Covered |
| §4.1 | Intermediate CA validity period enforced | certificate-expired-intermediate_fail | Covered |
| §4.1 | Root CA validity period enforced | certificate-expired-root_fail | Covered |
| §4.1 | Full-chain expiry rejected (no time-pinning) | certificate-all-expired_fail | Covered |
| §4.1 | Certificate must have code_signing EKU | certificate-no-code-signing-eku_fail | Covered |
| §4.1 | Method-specific verificationMaterial match | key-verify-as-certificate_fail, certificate-verify-as-key_fail, sigstore-verify-as-key_fail, key-verify-as-sigstore_fail, certificate-verify-as-sigstore_fail | Covered |
| §4.1 | Producers MUST use hint field in publicKey | _assert_key_uses_hint (all key roundtrip) | Covered |
| §4.2 | EC P-256 key support | key-p256 | Covered |
| §4.2 | EC P-384 key support | key-p384 | Covered |
| §4.2 | EC P-521 key support | key-p521 | Covered |
| §5.1 | predicateType exact match | malformed-wrong-predicate_fail, _assert_predicate_type (all roundtrip) | Covered |
| §5.1 | Deprecated v0.1 backward compat | historical-v0.2.0-certificate | Covered |
| §5.2.1 | resources minItems 1 | Schema validation (all roundtrip/positive), key-simple-empty-resources_fail | Covered |
| §5.2.1 | resources sorted by name | _assert_resources_sorted (all roundtrip) | Covered |
| §5.2.1 | Only regular files, no directory entries | Implicit in all tests | Covered |
| §5.2.2 | serialization required fields | Schema validation, key-simple-missing-serialization_fail | Covered |
| §5.2.2 | shard_size MUST be absent when method is files | _assert_no_shard_size_for_files (all roundtrip) | Covered |
| §6.1 | Recursive file enumeration | key-multi-file, key-deeply-nested, key-assets-subdir | Covered |
| §6.1 | Model MUST have ≥1 file after exclusions | key-empty-model-rejected | Covered |
| §6.1.1 | Symlink rejected by default (allow_symlinks=false) | key-symlink-default-rejected | Covered |
| §6.1.1 | Out-of-root symlink MUST error | key-symlink-outside-root | Covered |
| §6.1.1 | Symlink cycle MUST error | key-symlink-cycle | Covered |
| §6.1.2 | Forward slash path separator | All multi-file tests | Covered |
| §6.1.2 | Paths relative to model root | key-multi-file (subdir/adapter.bin) | Covered |
| §6.1.2 | Single-file basename only | key-single-file | Covered |
| §6.1.2 | Case-sensitive comparison | Implicit | Covered |
| §6.1.2 | Path canonicalization (no /, ../, ./, //, trailing /) | _assert_paths_canonical (all roundtrip) | Covered |
| §6.1.2 | UTF-8 filenames | key-unicode-filename | Covered |
| §6.2 | Default git path exclusions | key-default-ignores, key-deeply-nested-with-git, key-multi-git-dirs, key-multi-gitignore, key-git-and-ignore-combined | Covered |
| §6.2 | Non-git dotfiles NOT excluded | key-dotfile-included | Covered |
| §6.2 | Hidden subdirectories NOT excluded | key-files-in-hidden-dir | Covered |
| §6.2 | User --ignore-paths | key-ignore-paths | Covered |
| §6.2 | Signature file auto-exclusion | key-sig-inside-model | Covered |
| §6.2 | Nested git-pattern NOT auto-excluded | key-nested-git-not-excluded | Covered |
| §6.2.1 | Top-level matching for default excludes | key-default-ignores, key-multi-git-dirs, key-multi-gitignore | Covered |
| §6.2.1 | Exact relative path for user ignores | key-ignore-paths, key-ignore-paths-exact-match | Covered |
| §6.2.1 | User ignore path depth semantics | key-ignore-paths-exact-match | Covered |
| §6.3.1 | File serialization (files method) | All roundtrip tests | Covered |
| §6.3.1 | Resource algorithm matches serialization.hash_type | _assert_algorithm_consistency (all roundtrip) | Covered |
| §6.3.2 | Shard serialization (`"shards"` method) | - | Not covered (client limitation) |
| §6.4 | Resource descriptors sorted by name | _assert_resources_sorted (all roundtrip) | Covered |
| §6.5 | subject[0].name = basename of model path | _assert_subject_name (all roundtrip) | Covered |
| §6.5.1 | Root digest = SHA-256 of concatenated digests | _assert_root_digest (all roundtrip) | Covered |
| §7 | sha256 REQUIRED | All tests | Covered |
| §7 | blake2b OPTIONAL | - | Not covered (optional, not CLI-accessible) |
| §7 | blake3 OPTIONAL | - | Not covered (optional, not CLI-accessible) |
| §8.1 | Bundle schema validation | validate_bundle (all positive/roundtrip) | Covered |
| §8.1 | mediaType validation | key-simple-wrong-mediatype_fail | Covered |
| §8.2 | Signature vs wrong key | key-simple-wrong-key_fail | Covered |
| §8.2 | Signature vs wrong CA | certificate-simple-wrong-ca_fail | Covered |
| §6.7 | payloadType MUST be application/vnd.in-toto+json | key-simple-wrong-payload-type_fail | Covered |
| §8.3 | Statement _type validation | key-simple-wrong-statement-type_fail | Covered |
| §8.3 | Statement validation | Schema validation | Covered |
| §8.3 | Wrong predicateType rejection | malformed-wrong-predicate_fail | Covered |
| §8.4 | Tampered content detection | key-simple-tampered-content_fail | Covered |
| §8.4 | Missing file detection | key-simple-missing-file_fail | Covered |
| §8.4 | Extra unsigned file detection | key-simple-extra-file_fail | Covered |
| §8.5 | --ignore-unsigned-files | key-ignore-unsigned, key-simple-ignore-unsigned-files | Covered |
| §8.5 | Tampered file still detected with --ignore-unsigned-files | key-tampered-with-ignore-unsigned_fail | Covered |
| §8.5 | Missing file still detected with --ignore-unsigned-files | key-missing-file-with-ignore-unsigned_fail | Covered |
| §9 | Bundle excluded from signing scope | key-sig-inside-model | Covered |
| §10 | Conformance (sha256, files, key minimum) | All tests | Covered |
| §10 | Rejection of unsupported algorithm/method with informative error | - | Not covered (needs adapter protocol extension) |
| §10 | Deterministic signing (names and digests) | key-simple-deterministic | Covered |
| §11 | Historical backward compatibility | 13 historical tests (v0.2.0–v1.1.0) | Covered |

---

## Category 1: Verify tests

Paths are under `test/test-cases/verify/…` unless noted. “Verify” means the client checks a pre-built bundle and model without signing in that run.

### Positive cases (6)

#### `key-simple`
**Spec:** §4.1, §6.2, §8.1–§8.4

**What it tests:** Baseline key-based verification for a two-file model where one path is excluded from the signed set.

**Setup:** The model includes `signme-1`, `signme-2`, and `ignore-me`. The bundle was produced with `ignore-me` excluded (aligned with the simple fixture’s ignore list). This is an entry-level smoke test for the key method.

**Why it exists:** A minimal passing path must work before more complex cases; it anchors expectations for key material, manifest contents, and verification against the spec’s bundle and integrity rules.

**Expected outcome:** Exit code 0. The signed contents correspond to the two in-scope files (not `ignore-me`).

**Impact if it fails:** The entire key-based signing and verification feature is effectively broken for normal two-file models.

#### `certificate-simple`
**Spec:** §4.1, §8.2

**What it tests:** X.509 certificate–chain verification for a bundle signed with a leaf certificate backed by a three-level PKI (leaf, intermediate, root trust anchor).

**Setup:** A committed bundle and matching model layout; the client is configured with the appropriate certificate chain and trust material so the full chain can be validated.

**Why it exists:** Many deployments use certificate-based identity rather than raw public keys; the client must validate the full chain, not just the signature bytes.

**Expected outcome:** Exit code 0; verification succeeds with correct chain and trust.

**Impact if it fails:** Certificate-based signing and verification is broken; PKI-backed workflows cannot be trusted.

#### `key-multi-file`
**Spec:** §6.1, §6.1.2, §6.4

**What it tests:** Key-based verification on a model with subdirectories and multiple files, including canonical path form and lexicographic resource ordering in the manifest.

**Setup:** Model contains `weights.bin`, `config.json`, and `subdir/adapter.bin`.

**Why it exists:** Real models are rarely flat; the client must walk the tree, emit stable relative names with `/` separators, and sort resource descriptors deterministically.

**Expected outcome:** Exit code 0. The expected signed file list, sorted, is exactly `["config.json", "subdir/adapter.bin", "weights.bin"]`.

**Impact if it fails:** Models with nested directories cannot be signed or verified reliably.

#### `key-ignore-paths`
**Spec:** §6.2, §6.2.1

**What it tests:** That user-supplied `--ignore-paths` correctly excludes files from the signed set and that verification still matches the resulting manifest.

**Setup:** Model has `signme-1`, `signme-2`, and `ignore-me`. The bundle was created with `ignore-me` excluded.

**Why it exists:** Authors must omit secrets, build artifacts, or other non-model files from the signed scope; exclusion semantics must be consistent between signing and verification.

**Expected outcome:** Exit code 0. The bundle contains only `signme-1` and `signme-2` (not `ignore-me`).

**Impact if it fails:** Non-model files cannot be excluded safely; manifests may drift or verification may fail in realistic repos.

#### `key-single-file`
**Spec:** §6.1.2

**What it tests:** Key-based verification when the “model” is a single file `model.bin`, so the resource name is the filename itself, not a longer relative path.

**Setup:** Single-file model fixture with only `model.bin` at the model root (as defined by the test assets).

**Why it exists:** Many artifact formats (e.g. ONNX, GGUF) are shipped as one file; the spec’s single-file naming rules must be exercised.

**Expected outcome:** Exit code 0. The manifest lists `["model.bin"]` as the resource name.

**Impact if it fails:** Single-file models cannot be signed or verified correctly.

#### `key-simple-ignore-unsigned-files`
**Spec:** §8.5

**What it tests:** The `--ignore-unsigned-files` flag, allowing extra files present on disk that are not in the signed manifest to be ignored during verification.

**Setup:** Same family of layout as the simple case, with an additional unsigned file present alongside signed files; verification is run with the flag enabled as required by the case config.

**Why it exists:** Deployed directories often gain runtime or auxiliary files that should not break verification when operators opt in to lenient mode.

**Expected outcome:** Exit code 0 even when unsigned files are present, when the flag is set.

**Impact if it fails:** Teams cannot deploy signed models into directories with extra runtime artifacts without false verification failures.

### Historical cases (15)

#### `go-interop-key`
**Spec:** §4.1, §11

**What it tests:** That a bundle produced by the Go implementation (key method) verifies successfully with the client under test.

**Setup:** A Go-generated bundle for the simple model downloaded from OCI fixtures; same key relationship as `key-simple`.

**Why it exists:** Verification must be interoperable across implementations and languages.

**Expected outcome:** Exit code 0.

**Impact if it fails:** Cross-language, key-based interoperability is broken.

#### `go-interop-certificate`
**Spec:** §4.1, §11

**What it tests:** That a Go-produced certificate-method bundle verifies successfully with the client under test.

**Setup:** A Go-generated certificate bundle downloaded from OCI fixtures with matching trust configuration.

**Why it exists:** Certificate signing must work across toolchains.

**Expected outcome:** Exit code 0.

**Impact if it fails:** Cross-language certificate interoperability is broken.

> **Note:** Historical bundles may not match every detail of the current OMS JSON Schema. Known differences include: `tlogEntries` may be optional for key/certificate material in older bundles, `keyid` may be null in bundles produced before v1.1.0, and v0.2.0 uses a deprecated `predicateType`. The suite still requires these to verify when marked pass.

#### `historical-v0.2.0-certificate`
**Spec:** §5.1, §11

**What it tests:** Backward compatibility with a certificate bundle produced by the Go client at v0.2.0 (the first release using the Sigstore-style bundle format), using the older predicate and schema-era conventions.

**Setup:** A frozen bundle and model from that era; no live signing in this test.

**Why it exists:** Production data from the earliest supported format must remain verifiable so long-lived artifacts stay auditable.

**Expected outcome:** Exit code 0.

**Impact if it fails:** The oldest production bundles in the wild would become unverifiable.

#### `historical-v0.3.1-elliptic-key`
**Spec:** §11

**What it tests:** The oldest key-signed (EC) bundle format from Go v0.3.1, which introduced key-based signing.

**Setup:** Committed v0.3.1 key bundle and matching model.

**Why it exists:** v0.3.x was the first key-signing line; many historical artifacts may use this shape.

**Expected outcome:** Exit code 0.

**Impact if it fails:** v0.3.x key-signed bundles cannot be verified.

#### `historical-v0.3.1-certificate`
**Spec:** §11

**What it tests:** A certificate bundle from v0.3.1, paired with the key case to cover the certificate path in the same release generation.

**Setup:** Committed v0.3.1 certificate bundle and model.

**Why it exists:** Both key and certificate flows must remain compatible for that generation.

**Expected outcome:** Exit code 0.

**Impact if it fails:** v0.3.x certificate bundles cannot be verified.

#### `historical-v1.0.0-elliptic-key`
**Spec:** §11

**What it tests:** A key bundle from v1.0.0, the first stable OMS release line and the most widely deployed key-signed shape.

**Setup:** v1.0.0 key bundle and assets.

**Why it exists:** v1.0.0 is a major compatibility baseline; failures here have the broadest user impact.

**Expected outcome:** Exit code 0.

**Impact if it fails:** **Highest severity** among historical lines - a large class of v1.0.0 key bundles would be unverifiable.

#### `historical-v1.0.0-certificate`
**Spec:** §11

**What it tests:** A certificate bundle from v1.0.0, mirroring the key case for the stable release’s certificate method.

**Setup:** v1.0.0 certificate bundle and assets.

**Why it exists:** Certificate deployments on v1.0.0 need the same guarantee as key deployments.

**Expected outcome:** Exit code 0.

**Impact if it fails:** v1.0.0 certificate bundles would be unverifiable across the board.

#### `historical-v1.0.1-elliptic-key`
**Spec:** §6.2, §11

**What it tests:** A v1.0.1 key bundle from the last release that did not carry `ignore_paths` inside the predicate; ignores were applied only via the signer/validator CLI, not embedded in the payload.

**Setup:** Model includes `ignore-me` excluded at signing/verification time by flags only, matching the transition-era behavior.

**Why it exists:** The suite must cover the hand-off between “CLI-only” ignores and later predicate-embedded `ignore_paths` (v1.1.0+).

**Expected outcome:** Exit code 0.

**Impact if it fails:** v1.0.1 key bundles would be unverifiable, breaking a common migration step.

#### `historical-v1.0.1-certificate`
**Spec:** §6.2, §11

**What it tests:** The same v1.0.1 transition point as the elliptic key case, for the certificate method.

**Setup:** v1.0.1 certificate bundle with the same ignore semantics as the key case for that release.

**Why it exists:** Both methods must track ignore behavior consistently across the transition.

**Expected outcome:** Exit code 0.

**Impact if it fails:** v1.0.1 certificate bundles would be unverifiable.

#### `historical-v1.1.0-elliptic-key`
**Spec:** §6.2, §11

**What it tests:** A v1.1.0 key bundle where the predicate includes `ignore_paths`, reflecting the schema evolution after v1.0.1.

**Setup:** v1.1.0 key bundle; ignores are represented in the signed predicate as well as in verification configuration where applicable.

**Why it exists:** Most recent “deployment era” bundles may include embedded ignore paths; clients must handle them.

**Expected outcome:** Exit code 0.

**Impact if it fails:** The most recent common deployment key bundles would be unverifiable.

#### `historical-v1.1.0-certificate`
**Spec:** §6.2, §11

**What it tests:** A v1.1.0 certificate bundle with the same embedded `ignore_paths` evolution as the key case.

**Setup:** v1.1.0 certificate bundle and matching trust path.

**Why it exists:** Certificate users on the current line need parity with the key path for historical verification.

**Expected outcome:** Exit code 0.

**Impact if it fails:** v1.1.0 certificate bundles would be unverifiable for typical deployments.

#### `historical-v0.3.1-sigstore`
**Spec:** §4.1, §11

**What it tests:** A Sigstore (keyless) bundle from Go v0.3.1 (first sigstore release). Verifies with identity `stefanb@us.ibm.com` and issuer `https://sigstore.verify.ibm.com/oauth2`.

**Setup:** Committed sigstore bundle with model. Requires CI (Sigstore infrastructure). Skipped locally.

**Why it exists:** Earliest sigstore-signed bundle in the Go client. Ensures backwards compatibility with keyless signing from the first release.

**Expected outcome:** Verification succeeds (exit 0). Skipped locally.

**Impact if it fails:** Keyless bundles from Go v0.3.1 are unverifiable.

#### `historical-v1.0.0-sigstore`
**Spec:** §4.1, §11

**What it tests:** A Sigstore bundle from Go v1.0.0 (first stable release). Same identity and issuer as v0.3.1.

**Setup:** Committed sigstore bundle. Requires CI. Skipped locally.

**Why it exists:** Validates that the stable sigstore bundle format is backwards compatible.

**Expected outcome:** Verification succeeds. Skipped locally.

**Impact if it fails:** Sigstore bundles from Go v1.0.0 are unverifiable.

#### `historical-v1.0.1-sigstore`
**Spec:** §4.1, §11

**What it tests:** A Sigstore bundle from Go v1.0.1 with `ignore_paths` in the predicate. Introduced `ignore-me` file in the model.

**Setup:** Committed sigstore bundle. Requires CI. Skipped locally. Verify config includes `ignore_paths: ["ignore-me"]`.

**Why it exists:** First sigstore bundle that includes `ignore_paths` in the predicate, testing both sigstore verify and path exclusion handling together.

**Expected outcome:** Verification succeeds. Skipped locally.

**Impact if it fails:** Sigstore bundles with ignore_paths from Go v1.0.1 are unverifiable.

#### `historical-v1.1.0-sigstore`
**Spec:** §4.1, §11

**What it tests:** A Sigstore bundle from Go v1.1.0 with `ignore_paths` in the predicate. Latest sigstore historical vector.

**Setup:** Committed sigstore bundle. Requires CI. Skipped locally.

**Why it exists:** Latest Go client sigstore release. Validates ongoing backwards compatibility for keyless signing.

**Expected outcome:** Verification succeeds. Skipped locally.

**Impact if it fails:** Latest sigstore bundles from Go v1.1.0 are unverifiable.

### Negative cases (32)

#### `key-simple-tampered-content_fail`
**Spec:** §8.4

**What it tests:** That modifying file content after signing is detected: `signme-1` is tampered (e.g. post-sign byte change) so the digest no longer matches the manifest.

**Setup:** Pre-built bundle and model, with a tamper step applied to `signme-1` before verify.

**Why it exists:** Detecting post-sign modification is a primary security property of model signing; this is the core integrity check.

**Expected outcome:** Non-zero exit; verification must fail (digest mismatch / integrity failure).

**Impact if it fails:** **Critical security failure** - the client could silently accept a tampered model.

#### `key-simple-wrong-key_fail`
**Spec:** §8.2

**What it tests:** Rejection when verification uses a public key that does not correspond to the key that signed the bundle (`wrong-key-pub.pem` or equivalent unrelated EC key material).

**Setup:** Valid bundle, but `verify` supplies the wrong public key.

**Why it exists:** The signature must be bound to the intended publisher; an unrelated key must not “verify” the same payload.

**Expected outcome:** Non-zero exit.

**Impact if it fails:** **Critical** - a client might accept a bundle as valid under an arbitrary or attacker-chosen key.

#### `key-simple-missing-file_fail`
**Spec:** §8.4

**What it tests:** Rejection when a file listed in the signed manifest (e.g. `signme-2`) is deleted from the on-disk model after signing but before verify.

**Setup:** Post-sign delete of a required file.

**Why it exists:** The manifest promises a full set of files; missing content must fail closed.

**Expected outcome:** Non-zero exit.

**Impact if it fails:** **Critical** - attackers or broken pipelines could remove model components and verification might still pass.

#### `key-simple-extra-file_fail`
**Spec:** §8.4, §8.5

**What it tests:** Strict mode without `--ignore-unsigned-files` must reject a model directory that contains an extra file (e.g. `injected.bin`) not present in the signed manifest.

**Setup:** Pre-verify injection of a new file; verify runs without the lenient unsigned-files option.

**Why it exists:** Unmodeled files can be supply-chain or data-poisoning attempts; the default must be strict.

**Expected outcome:** Non-zero exit.

**Impact if it fails:** **Security failure** - file injection in the model directory would go undetected in the default mode.

#### `certificate-simple-wrong-ca_fail`
**Spec:** §8.2

**What it tests:** Chain validation when the client trusts a wrong root or CA (`wrong-ca-cert.pem` instead of the true issuer), so the path from leaf to trust anchor is invalid.

**Setup:** Legitimate cert-signed bundle, but `verify` uses an unrelated CA as trust.

**Why it exists:** Trust anchors define who is allowed; substituting a random CA must not produce success.

**Expected outcome:** Non-zero exit; chain validation must fail.

**Impact if it fails:** **Critical** - any CA’s certificate could be accepted, making the trust store meaningless.

#### `key-simple-corrupted-bundle_fail`
**Spec:** §8.1

**What it tests:** Handling of a bundle file that is not valid JSON (garbled or structurally invalid while still a “file on disk”).

**Setup:** Committed or generated corrupted bundle content.

**Why it exists:** Parsers must reject garbage deterministically; crashes are unacceptable for a security tool.

**Expected outcome:** Non-zero exit; no crash; clear failure.

**Impact if it fails:** Poor robustness (crashes) or spurious success on invalid input, undermining confidence in the implementation.

#### `key-simple-truncated-bundle_fail`
**Spec:** §8.1

**What it tests:** A partial bundle (first 100 bytes of a real bundle) simulating a truncated or incomplete write.

**Setup:** Truncated copy of a valid bundle.

**Why it exists:** Partial I/O and transfer failures are common; the client must not treat a half file as a valid signed bundle.

**Expected outcome:** Non-zero exit.

**Impact if it fails:** Incomplete bundles might be mis-handled, risking wrong security conclusions.

#### `key-simple-wrong-mediatype_fail`
**Spec:** §8.1

**What it tests:** The outer bundle’s `mediaType` is changed to a wrong value (e.g. `v0.1`) in a way that is **outside** the DSSE envelope, so the cryptographic signature on the statement may still be valid for the original bytes, but the **outer** type no longer matches what this client and spec require.

**Setup:** Committed or modified bundle with `mediaType` not matching the expected OMS bundle media type, while the envelope bytes may be unchanged in ways that do not re-sign the payload.

**Why it exists:** The implementation must not verify only the inner signature in isolation; the bundle wrapper and `mediaType` are part of correct interpretation (§8.1).

**Expected outcome:** Non-zero exit.

**Impact if it fails:** Clients could accept bundles labeled as a different or obsolete outer format, confusing tooling and interop.

#### `key-simple-no-signature_fail`
**Spec:** §8.1

**What it tests:** A bundle where the `signatures` array is empty, so there is no signature to check even if JSON schema might be relaxed.

**Setup:** Valid JSON object for a bundle with empty `signatures`.

**Why it exists:** Absence of a signature must be a hard failure, not a silent pass or ambiguous state.

**Expected outcome:** Non-zero exit.

**Impact if it fails:** Unsigned or stripped signature lists could be treated as success.

#### `malformed-empty-bundle_fail`
**Spec:** §8.1

**What it tests:** A zero-byte file passed as the bundle.

**Setup:** Empty path or zero-length bundle file.

**Why it exists:** Edge-case input should fail fast and clearly, not with undefined behavior.

**Expected outcome:** Non-zero exit.

**Impact if it fails:** Unpredictable errors or spurious pass on empty input.

#### `malformed-missing-envelope_fail`
**Spec:** §8.1

**What it tests:** JSON that is valid overall and may include `mediaType` but is missing the required `dsseEnvelope` (or equivalent) field the client needs.

**Setup:** Syntactically valid JSON, structurally wrong for a DSSE-wrapped OMS bundle.

**Why it exists:** Field presence must be validated, not only JSON validity and media type.

**Expected outcome:** Non-zero exit.

**Impact if it fails:** Malformed but “almost valid” JSON could be mis-processed.

#### `malformed-wrong-predicate_fail`
**Spec:** §5.1, §8.3

**What it tests:** The `predicateType` URI inside the in-envelope statement is changed to a wrong value; the DSSE signature is over a specific payload, so the payload is no longer the one that was signed (or the statement no longer matches the expected predicate type).

**Setup:** Committed bundle variant with wrong `predicateType` in the signed payload.

**Why it exists:** The predicate type identifies the kind of in-toto statement; the wrong type must invalidate verification.

**Expected outcome:** Non-zero exit; signature or payload check must fail.

**Impact if it fails:** Wrong semantic types could be smuggled as if they were OMS model statements.

#### `certificate-no-code-signing-eku_fail`
**Spec:** §4.1

**What it tests:** That a certificate without the `code_signing` Extended Key Usage (EKU) extension is rejected during certificate-method signing or verification.

**Setup:** Signs the simple model using a leaf certificate issued by the standard intermediate CA but without the `code_signing` EKU. The certificate is valid and properly chained — only the EKU is missing.

**Why it exists:** The OMS spec requires certificates used for signing to have the `code_signing` EKU. Accepting a certificate without it would allow arbitrary certificates to produce valid signatures.

**Expected outcome:** Non-zero exit code (signing or verification rejected).

**Impact if it fails:** Clients accept signatures from certificates not authorized for code signing, undermining the PKI trust model.

#### `certificate-expired_fail`
**Spec:** §4.1, §8.2

**What it tests:** A leaf certificate whose **validity period** is in the past (e.g. Jan 1–2, 2020) while the chain and signature are otherwise consistent with a signed bundle.

**Setup:** Committed or generated cert and bundle using that expired leaf.

**Why it exists:** X.509 time validity is mandatory; expired identities must not be treated as current signers.

**Expected outcome:** Non-zero exit; temporal validation must fail.

**Impact if it fails:** **Security failure** - decommissioned or expired credentials could be accepted as valid.

#### `certificate-not-yet-valid_fail`
**Spec:** §4.1, §8.2

**What it tests:** A leaf certificate whose **validity period has not yet started** (notBefore is one year in the future) while the chain and signature are otherwise valid.

**Setup:** Generated leaf cert with notBefore = now + 1 year, notAfter = now + 2 years, issued by the standard intermediate CA. Signing or verification uses this future-dated certificate.

**Why it exists:** X.509 temporal validation requires checking both notBefore and notAfter. A certificate that is not yet valid must be rejected just as firmly as one that has expired.

**Expected outcome:** Non-zero exit; temporal validation must fail (certificate not yet valid).

**Impact if it fails:** **Security failure** - certificates issued for future use could be accepted before their intended activation date, bypassing temporal controls.

#### `certificate-expired-intermediate_fail`
**Spec:** §4.1, §8.2

**What it tests:** A valid leaf certificate whose **intermediate CA** has an expired validity period (notAfter 2020-01-02). The root CA and leaf are otherwise valid.

**Setup:** Dedicated expired intermediate CA cert (notBefore 2020-01-01, notAfter 2020-01-02) signed by the standard root CA. A valid leaf cert is issued from this expired intermediate.

**Why it exists:** X.509 chain validation must verify the validity period of every certificate in the chain, not just the leaf. An expired intermediate CA invalidates all certificates it issued.

**Expected outcome:** Non-zero exit; chain temporal validation must fail at the intermediate CA level.

**Impact if it fails:** **Security failure** - an expired intermediate CA could continue to be accepted, allowing its leaf certificates to verify despite the CA being decommissioned.

#### `certificate-expired-root_fail`
**Spec:** §4.1, §8.2

**What it tests:** A valid leaf certificate and valid intermediate CA whose **root CA** (trust anchor) has an expired validity period (notAfter 2020-01-02). All other aspects of the chain are correct.

**Setup:** Dedicated expired root CA cert. Valid intermediate and leaf certs issued from this expired root. Verification uses the expired root as trust anchor.

**Why it exists:** Even the trust anchor must be temporally valid. An expired root CA means the entire trust chain is no longer authoritative.

**Expected outcome:** Non-zero exit; chain temporal validation must fail at the root CA level.

**Impact if it fails:** **Security failure** - an expired root CA could continue to anchor trust chains, undermining the entire certificate lifecycle management model.

#### `certificate-all-expired_fail`
**Spec:** §4.1, §8.2

**What it tests:** An entire certificate chain where **root, intermediate, and leaf** are all expired. This is the scenario identified in sigstore/model-transparency#663 where implementations that pin verification time to the leaf's notBefore could tautologically pass chain validation.

**Setup:** All three certificates have validity periods entirely in the past (root and intermediate: Jan-Jun 2020, leaf: Feb-Mar 2020). The leaf's notBefore falls within the CA validity windows, so a verifier that pins time to notBefore would incorrectly find all certs valid.

**Why it exists:** Verifiers must use the current wall-clock time for validity checks, not the certificate's own notBefore. Pinning to notBefore creates a tautological pass: any self-consistent chain of expired certs would verify, defeating the purpose of certificate expiry.

**Expected outcome:** Non-zero exit; temporal validation must fail for all certificates in the chain.

**Impact if it fails:** **Critical security failure** - the time-pinning bug (issue #663) means any expired certificate chain that was internally consistent would be accepted, completely negating certificate expiry as a security control.

#### `key-verify-as-certificate_fail`
**Spec:** §4.1

**What it tests:** A key-signed bundle (verification material includes a `publicKey` or equivalent key method material) is submitted to verification that is run in **certificate** mode, so the `verificationMaterial` type does not match the method the bundle was produced for.

**Setup:** Use `key`-style bundle; invoke verify with certificate chain parameters only (mismatched method).

**Why it exists:** Method consistency prevents confusion attacks where a key bundle is “verified” by ignoring key rules or vice versa.

**Expected outcome:** Non-zero exit; type/method mismatch must be detected.

**Impact if it fails:** **Security failure** - the implementation might not enforce that verification method matches bundle contents, weakening authentication semantics.

#### `sigstore-wrong-identity_fail`
**Spec:** §4.1, §8.2

**What it tests:** A valid sigstore-signed bundle is verified with a **wrong certificate identity** (SAN). The Fulcio certificate was issued to a different workflow than the one the verifier expects.

**Setup:** Pre-committed sigstore bundle; verify config specifies a non-matching identity. Requires CI (Sigstore infrastructure).

**Why it exists:** Sigstore keyless verification relies on identity matching. Accepting a mismatched identity means any signer could produce accepted bundles.

**Expected outcome:** Non-zero exit; identity mismatch detected. Skipped locally.

**Impact if it fails:** **Security failure.** Bundles from untrusted signers accepted as trusted.

#### `sigstore-wrong-issuer_fail`
**Spec:** §4.1, §8.2

**What it tests:** A valid sigstore-signed bundle is verified with the **wrong OIDC issuer** URL.

**Setup:** Pre-committed sigstore bundle; verify config specifies a wrong `identity_provider`. Requires CI.

**Why it exists:** The OIDC issuer is the trust anchor for keyless signing. A wrong issuer means the verifier is not validating the token's origin.

**Expected outcome:** Non-zero exit; issuer mismatch detected. Skipped locally.

**Impact if it fails:** **Security failure.** Certificates from untrusted identity providers silently accepted.

#### `sigstore-verify-as-key_fail`
**Spec:** §4.1

**What it tests:** A sigstore-signed bundle (verificationMaterial contains a Fulcio certificate) is verified with `key` method and a public key. The verification material type does not match.

**Setup:** Pre-committed sigstore bundle; verify config uses method `key` with an EC public key.

**Why it exists:** Method mismatch is the inverse of `key-verify-as-certificate_fail`. A sigstore bundle must not be accepted by key-based verification.

**Expected outcome:** Non-zero exit; method mismatch detected.

**Impact if it fails:** **Security failure.** A sigstore bundle could be "verified" by ignoring the Fulcio certificate chain entirely.

#### `sigstore-tampered-content_fail`
**Spec:** §7, §8.4

**What it tests:** A valid sigstore-signed bundle is verified against a **tampered** model (file content changed after signing). The root digest must not match.

**Setup:** Pre-committed sigstore bundle with `model_modifications.tamper` applied to `signme-1`. Requires CI (Sigstore infrastructure). Skipped locally.

**Why it exists:** Validates that tamper detection works with the sigstore method, not just key/certificate methods.

**Expected outcome:** Non-zero exit; digest mismatch detected. Skipped locally.

**Impact if it fails:** **Integrity failure.** Sigstore-signed bundles do not detect content tampering.

#### `certificate-verify-as-key_fail`
**Spec:** §4.1

**What it tests:** A certificate-signed bundle (verificationMaterial contains an `x509CertificateChain`) is verified with `key` method and a public key. The verification material type does not match.

**Setup:** Pre-committed certificate bundle (from certificate-simple positive test); verify config uses method `key` with a public key.

**Why it exists:** Complements `key-verify-as-certificate_fail` and `sigstore-verify-as-key_fail` by testing the remaining method mismatch direction. A certificate bundle must not be accepted by key-based verification.

**Expected outcome:** Non-zero exit; method/material mismatch detected.

**Impact if it fails:** **Security failure.** A certificate-signed bundle could be "verified" by ignoring the certificate chain entirely.

#### `key-simple-wrong-payload-type_fail`
**Spec:** §6.7, §8.1

**What it tests:** A bundle with a **valid DSSE signature** but wrong `payloadType` (set to `"application/octet-stream"` instead of `"application/vnd.in-toto+json"`). The signature is computed over the correct PAE for the wrong payloadType, so pure signature verification would pass - the verifier must explicitly check that `payloadType` matches the expected in-toto content type.

**Setup:** Crafted bundle signed with the test EC P-384 key; only `payloadType` deviates from the valid bundle.

**Why it exists:** The spec (§6.7) requires `payloadType` to be `"application/vnd.in-toto+json"`. A verifier that only checks the DSSE signature without validating `payloadType` would silently accept a payload labeled as a different content type.

**Expected outcome:** Non-zero exit; payloadType mismatch or PAE verification failure.

**Impact if it fails:** **Security failure.** Bundles could claim to contain non-in-toto payloads while being accepted as OMS bundles.

#### `key-simple-wrong-statement-type_fail`
**Spec:** §8.3

**What it tests:** A bundle with a **valid DSSE signature** but wrong in-toto statement `_type` (set to `"https://in-toto.io/Statement/v0.1"` instead of `"https://in-toto.io/Statement/v1"`). The signature is valid for the modified payload.

**Setup:** Crafted bundle signed with the test EC P-384 key; the decoded payload has a wrong `_type` field.

**Why it exists:** The spec (§8.3 step 1) requires `_type` to be exactly `"https://in-toto.io/Statement/v1"`. A verifier that skips this check could accept statements from a different version of the in-toto attestation framework.

**Expected outcome:** Non-zero exit; statement type validation failure.

**Impact if it fails:** Wrong in-toto statement versions could be silently accepted, potentially leading to misinterpretation of attestation semantics.

#### `key-simple-empty-resources_fail`
**Spec:** §5.2.1

**What it tests:** A bundle with a **valid DSSE signature** but an empty `resources` array in the predicate. The spec requires at least one resource descriptor.

**Setup:** Crafted bundle signed with the test EC P-384 key; the predicate has `"resources": []`.

**Why it exists:** While `key-empty-model-rejected` tests that the *signer* rejects empty models, this test verifies that the *verifier* also rejects a signed bundle that claims zero resources. A bundle with no resources is meaningless and should fail verification at the predicate or manifest stage.

**Expected outcome:** Non-zero exit; empty resources detected or manifest mismatch (model has files but bundle lists none).

**Impact if it fails:** A signed bundle asserting no files could pass verification, providing false integrity guarantees.

#### `key-simple-missing-serialization_fail`
**Spec:** §5.2.2, §8.3

**What it tests:** A bundle with a **valid DSSE signature** but a predicate missing the `serialization` object entirely. The spec requires `serialization` as a REQUIRED key in the predicate body.

**Setup:** Crafted bundle signed with the test EC P-384 key; the predicate has `resources` but no `serialization`.

**Why it exists:** The verifier must read `serialization.method`, `serialization.hash_type`, and `serialization.allow_symlinks` to perform manifest verification (§8.4). A missing `serialization` object should fail at predicate validation, not crash or silently skip hash verification.

**Expected outcome:** Non-zero exit; missing serialization or schema validation failure.

**Impact if it fails:** A bundle without serialization metadata could be accepted, skipping hash algorithm and symlink policy checks entirely.

#### `key-tampered-with-ignore-unsigned_fail`
**Spec:** §8.5

**What it tests:** A valid key-signed bundle verified against a **tampered** model (signme-1 content changed) while `--ignore-unsigned-files` is enabled. The flag must not suppress digest verification for files listed in `resources`.

**Setup:** Pre-committed key bundle; `model_modifications.tamper` applied to `signme-1`; verify config sets `ignore_unsigned_files: true`.

**Why it exists:** The `--ignore-unsigned-files` flag should only skip the "extra files on disk" check. A verifier that interprets the flag as "skip all digest checks" would silently accept tampered content - a critical security failure.

**Expected outcome:** Non-zero exit; digest mismatch detected despite lenient mode.

**Impact if it fails:** **Critical security failure.** Tampered model content would go undetected when the flag is enabled.

#### `key-missing-file-with-ignore-unsigned_fail`
**Spec:** §8.5

**What it tests:** A valid key-signed bundle verified when a manifest-listed file (signme-2) is **deleted** from the model, while `--ignore-unsigned-files` is enabled. The flag must not suppress the check that all manifest-listed files are present.

**Setup:** Pre-committed key bundle; `model_modifications.delete` removes `signme-2`; verify config sets `ignore_unsigned_files: true`.

**Why it exists:** A verifier could interpret `--ignore-unsigned-files` as "skip the entire manifest-vs-filesystem comparison". This test ensures only the extra-files direction is relaxed.

**Expected outcome:** Non-zero exit; missing file detected despite lenient mode.

**Impact if it fails:** **Critical security failure.** Missing model components would go undetected.

#### `key-verify-as-sigstore_fail`
**Spec:** §4.1

**What it tests:** A key-signed bundle (publicKey in verificationMaterial) is verified with `sigstore` method. The verification material type does not match.

**Setup:** Pre-committed key bundle; verify config uses method `sigstore` with identity/issuer parameters.

**Why it exists:** Completes the method-mismatch test matrix. A key bundle verified as sigstore could bypass Fulcio certificate and Rekor log validation.

**Expected outcome:** Non-zero exit; method/material mismatch detected.

**Impact if it fails:** **Security failure.** Sigstore verification guarantees (certificate identity, transparency log) could be bypassed.

#### `certificate-verify-as-sigstore_fail`
**Spec:** §4.1

**What it tests:** A certificate-signed bundle (x509CertificateChain in verificationMaterial) is verified with `sigstore` method. The verification material type does not match.

**Setup:** Pre-committed certificate bundle; verify config uses method `sigstore` with identity/issuer parameters.

**Why it exists:** Ensures certificate bundles cannot masquerade as sigstore bundles. The x509CertificateChain type is structurally different from the single X509Certificate used by sigstore.

**Expected outcome:** Non-zero exit; method/material mismatch detected.

**Impact if it fails:** **Security failure.** Certificate-signed bundles could bypass Fulcio/Rekor validation.

---

## Category 2: Roundtrip tests (37)

Paths are under `test/test-cases/roundtrip/`. Each case signs a model copy, then verifies it using the test harness, exercising live crypto and I/O.

> **Note:** After every successful `sign`, the produced bundle is validated structurally: OMS JSON Schemas from **oms-schemas** apply to the outer bundle and decoded statement/predicate; the harness asserts resource descriptors are **sorted** by `name` (§6.4), recomputes the **root digest** (§6.5.1), validates **subject name** equals the model basename (§6.5), checks **path canonicalization** rules (§6.1.2), verifies **algorithm consistency** between resource descriptors and `serialization.hash_type` (§6.3.1), confirms **shard_size is absent** for files-method bundles (§5.2.2), asserts **predicateType** is the current v1.0 URI (§5.1), asserts key-method bundles use **publicKey.hint** (§4.1), and when the case uses `sig_inside_model`, checks that the signature file is **excluded** from the signed set (§6.2, §9).

#### `key-simple`
**Spec:** §4.1, §5.2, §6.1–§6.5, §8.1–§8.4

**What it tests:** A minimal end-to-end **sign** then **verify** for the key method on the `models/simple` fixture, matching the “happy path” for the suite.

**Setup:** `models/simple` with `signme-1` and `signme-2` in scope; `ignore-me` excluded as configured. Private key and public key in `config.json` per assets.

**Why it exists:** If this fails, no other key roundtrip can be trusted; it wires signing, manifest construction, and verification together.

**Expected outcome:** Exit code 0. Bundle lists exactly `["signme-1", "signme-2"]` in sorted order (per `expected_signed_files`).

**Impact if it fails:** Key signing and verification is fundamentally broken for the reference layout.

#### `certificate-simple`
**Spec:** §4.1, §5.2, §8.2

**What it tests:** Full PKI **sign** with leaf + intermediate material and **verify** using the root CA as trust anchor, for the same high-level `simple` model as the key case (certificate method).

**Setup:** Leaf signing cert and chain from `test/assets/keys/certificate/…`; sign block includes `private_key` / chain as required by the adapter; verify uses `ca-cert.pem` or equivalent as trust.

**Why it exists:** Certificate signing is a first-class method; the roundtrip must prove chain handling end to end, not only in verify-only historical bundles.

**Expected outcome:** Exit code 0.

**Impact if it fails:** Certificate-based signing and verification in live workflows is broken.

#### `key-multi-file`
**Spec:** §6.1, §6.1.2, §6.4

**What it tests:** Key signing and verification for a model that includes a subdirectory: `weights.bin`, `config.json`, `subdir/adapter.bin` - relative paths, traversal, and sort order of resources.

**Setup:** `models/multi-file` (or equivalent) with nested path.

**Why it exists:** Nested layouts and canonical ordering are required for deterministic manifests and for real repository shapes.

**Expected outcome:** Exit code 0. Expected sorted files: `["config.json", "subdir/adapter.bin", "weights.bin"]`.

**Impact if it fails:** Nested “models with folders” cannot be signed and verified in practice.

#### `certificate-multi-file`
**Spec:** §4.1, §6.1, §6.1.2

**What it tests:** The **certificate** method on the same multi-file / nested model layout as `key-multi-file`, ensuring PKI sign+verify with non-flat trees.

**Setup:** `models/multi-file` with certificate sign/verify config.

**Why it exists:** Users may standardize on certificates while still using nested file layouts; both dimensions must work together.

**Expected outcome:** Exit code 0.

**Impact if it fails:** The combination of X.509 signing and multi-file model layouts is broken.

#### `certificate-self-signed`
**Spec:** §4.1, §8.2

**What it tests:** Signing and verifying with a **self-signed** leaf certificate (the same cert acts as the trust anchor and the end-entity), common in development or air-gapped settings.

**Setup:** `keys/self-signed/…` material; single-cert chain configuration.

**Why it exists:** The spec does not only target enterprise PKI; self-signed is explicitly in scope for test and constrained environments.

**Expected outcome:** Exit code 0.

**Impact if it fails:** Developers and air-gapped users cannot sign with a single self-contained cert as intended.

#### `key-single-file`
**Spec:** §6.1.2

**What it tests:** Key sign+verify for a “model” that is a single file `model.bin` at the root, exercising basename-only resource naming and a different canonicalization path from multi-file cases.

**Setup:** `models/single-file`.

**Why it exists:** Single-artifact deliverables are common; they must not be special-cased incorrectly.

**Expected outcome:** Exit code 0. Manifest contains `["model.bin"]`.

**Impact if it fails:** Single-file models (many ML artifact formats) cannot be roundtripped.

#### `key-git-and-ignore-combined`
**Spec:** §6.2

**What it tests:** Full combination of `.git`, `.gitignore`, `.gitattributes`, and user-specified ignore paths in a single model.

**Setup:** `models/with-git-and-ignore` with `model.bin` signed, plus `.git/HEAD`, `.gitignore`, `.gitattributes`, and `ignored-file.tmp` all excluded.

**Why it exists:** Real repositories often contain multiple types of excluded paths simultaneously; this tests that all exclusion mechanisms compose correctly without interference.

**Expected outcome:** Exit code 0.

**Impact if it fails:** Combined git-related and user-specified exclusions would interfere with each other, causing files to be incorrectly included or excluded.

#### `key-ignore-paths`
**Spec:** §6.2, §6.2.1

**What it tests:** **Sign** and **verify** with the same user `--ignore-paths` (e.g. `ignore-me`) so the excluded file never enters the signed set but in-scope files do.

**Setup:** `models/simple` (or same layout) with explicit ignore in both sign and verify config.

**Why it exists:** Exclusions must be stable across the roundtrip, not just in verify-only fixtures.

**Expected outcome:** Exit code 0. `ignore-me` is not listed among signed files.

**Impact if it fails:** Roundtrip and verify-only behavior for `ignore-paths` diverge, breaking reproducible signing workflows.

#### `key-ignore-unsigned`
**Spec:** §8.5

**What it tests:** After a successful sign, a file is **injected** into the model directory; **verify** is run with `--ignore-unsigned-files` so the extra file does not break verification.

**Setup:** Post-sign `inject` (or equivalent) of an extra file; verify block enables ignore-unsigned.

**Why it exists:** Simulates release pipelines where the directory gains files after signing (caches, sidecars) but operators still want a green verify.

**Expected outcome:** Exit code 0 with the extra file present on disk.

**Impact if it fails:** Deployment and lifecycle patterns that rely on lenient post-sign directories cannot be supported.

#### `key-deeply-nested`
**Spec:** §6.1, §6.1.2

**What it tests:** Key roundtrip on a model where files are stored in a deeply nested directory structure (`a/very/deep/directory/tree/`).

**Setup:** `models/deeply-nested` with a single signed file at five levels of nesting.

**Why it exists:** Implementations must correctly enumerate and canonicalize paths through arbitrarily deep directory trees, not just one or two levels.

**Expected outcome:** Exit code 0.

**Impact if it fails:** Models with deeply nested directory structures would fail signing or verification due to path enumeration or canonicalization errors.

#### `key-deeply-nested-with-git`
**Spec:** §6.2

**What it tests:** That `.git` at the model root is excluded even when signed files are deeply nested in subdirectories.

**Setup:** `models/deeply-nested-with-git` with a deeply nested signed file and `.git/HEAD` at the root.

**Why it exists:** Validates that default git exclusions apply correctly regardless of how deep the actual model files are stored.

**Expected outcome:** Exit code 0.

**Impact if it fails:** Default git exclusions might not apply when model files are deeply nested, causing `.git` contents to appear in the manifest.

#### `key-default-ignores`
**Spec:** §6.2

**What it tests:** Default git- and tool-related paths (e.g. `.git/HEAD`, `.github/ci.yml`, `.gitignore`, `.gitattributes`) are **automatically** excluded with **no** explicit `--ignore-paths`.

**Setup:** `models/with-git-dir` (or equivalent) with `model.bin` as the only model content that should remain signed.

**Why it exists:** The spec’s default-exclusion list must work out of the box so repos do not need huge ignore lists for common VCS files.

**Expected outcome:** Exit code 0. Bundle contains only `["model.bin"]` (git-like paths not in the manifest).

**Impact if it fails:** Users would have to manually specify standard git paths on every sign, increasing errors and merge conflicts.

#### `key-dotfile-included`
**Spec:** §6.2

**What it tests:** Non-git “dotfiles” at the model root (e.g. `.config`, `.env.example`) **are** included in the signed set along with a normal `model.bin`, i.e. they are not treated like `.git` metadata.

**Setup:** `models/with-dotfiles`.

**Why it exists:** Distinguish default VCS-style ignores from legitimate hidden config files, which are often security-sensitive and must be signed.

**Expected outcome:** Exit code 0. All three paths appear in the bundle’s file list (exact list per case config).

**Impact if it fails:** Important configuration files at dot paths could be **silently** excluded, breaking integrity and surprise expectations.

#### `key-files-in-hidden-dir`
**Spec:** §6.2

**What it tests:** Files under “hidden” directories that are **not** git default ignores - e.g. `.cache/weights.bin`, `.local/share/data.bin` - must be **included** in the signed manifest with stable relative names.

**Setup:** `models/hidden-subdir` (or equivalent layout).

**Why it exists:** “Hidden” directory names are not a blanket excuse to drop user model content; only the spec’s default-exclude set applies to auto-exclusion.

**Expected outcome:** Exit code 0. All model files in those paths appear in the bundle.

**Impact if it fails:** Content under common hidden app dirs could be silently omitted from the manifest (integrity gap).

#### `key-empty-file`
**Spec:** §6.3.1

**What it tests:** A zero-byte file `empty.bin` is hashed and included in the manifest alongside a non-empty `signme-1` (or similar); the known SHA-256 of the empty file (`e3b0c44…` / standard empty string hash) is used correctly.

**Setup:** `models/with-empty-file`.

**Why it exists:** Edge cases in hashing and file iteration must be correct; empty files occur in real layouts.

**Expected outcome:** Exit code 0.

**Impact if it fails:** Hashing of empty or sparse models could be wrong, breaking manifest equality with other signers.

#### `key-assets-subdir`
**Spec:** §6.1

**What it tests:** Recursive file enumeration through a model with an `assets/` subdirectory containing additional files.

**Setup:** `models/with-assets-subdir` with `weights.bin`, `config.json`, `assets/vocab.txt`, and `assets/tokenizer.bin`.

**Why it exists:** Real models often include asset subdirectories with vocabulary files, tokenizers, or other supporting data that must be recursively enumerated and signed.

**Expected outcome:** Exit code 0.

**Impact if it fails:** Models with asset subdirectories would not be correctly enumerated, leaving supporting files unsigned.

#### `key-binary-content`
**Spec:** §6.3.1

**What it tests:** A model with true **binary** payloads - bytes across the range `0x00`–`0xFF`, nulls, and binary magic (e.g. PNG header) - to ensure no text, newline, or encoding assumptions in hashing or I/O.

**Setup:** `models/binary-content` with `header.bin` / `weights.bin` (or as defined in assets).

**Why it exists:** Model files are not UTF-8 text; the serializer must be byte-accurate.

**Expected outcome:** Exit code 0.

**Impact if it fails:** Non-text or mixed binary models may produce wrong digests on some platforms or tools.

#### `key-unicode-filename`
**Spec:** §6.1.2

**What it tests:** UTF-8 file names in the model tree (e.g. `模型.bin` with Chinese characters) are preserved in the manifest and matched on disk in a case- and encoding-correct way.

**Setup:** `models/unicode-names` with `weights.bin` and `模型.bin` (or asset-defined list).

**Why it exists:** International models and non-ASCII paths are in scope for OMS; path encoding bugs are common if untested.

**Expected outcome:** Exit code 0.

**Impact if it fails:** Real-world non-English filenames may fail sign or verify spuriously.

#### `key-special-chars-path`
**Spec:** §6.1.2

**What it tests:** File names and paths with **spaces**, **parentheses** (e.g. `file (copy).bin`), and nested `path with spaces/model.bin` - shell and JSON edge cases for how paths are written and read.

**Setup:** `models/special-chars` per fixture table.

**Why it exists:** User filesystems and export tools produce such names; the signer and CLI must not corrupt them on roundtrip.

**Expected outcome:** Exit code 0.

**Impact if it fails:** A class of “messy but valid” paths would break the signing or verification workflow.

#### `key-p384`
**Spec:** §4.2

**What it tests:** End-to-end sign and verify using an **EC P-384** key pair, as required to be available in conforming clients.

**Setup:** `keys/p384/…` key material; same logical model as the standard key cases where applicable.

**Why it exists:** The spec **mandates** P-384 support; this is a direct algorithm conformance check.

**Expected outcome:** Exit code 0.

**Impact if it fails:** The implementation is **non-compliant** and blocks P-384 users and policies.

#### `key-p521`
**Spec:** §4.2

**What it tests:** End-to-end sign and verify using an **EC P-521** key pair, as required to be available in conforming clients.

**Setup:** `keys/p521/…` key material.

**Why it exists:** The spec **mandates** P-521 support, often required in government or high-assurance settings.

**Expected outcome:** Exit code 0.

**Impact if it fails:** The implementation is **non-compliant**; high-assurance or regulated environments cannot be met.

#### `key-p256`
**Spec:** §4.2

**What it tests:** End-to-end sign and verify using an **EC P-256 (secp256r1)** key pair, the most widely deployed elliptic curve.

**Setup:** `keys/p256/…` key material; same logical model as the standard key cases.

**Why it exists:** The spec **mandates** P-256 support. While the default signing key is P-384, P-256 is the most common curve in production deployments and must be explicitly tested for the key method (not only via the certificate-self-signed test which uses the certificate method).

**Expected outcome:** Exit code 0.

**Impact if it fails:** The implementation is **non-compliant** for the most widely used elliptic curve.

#### `key-multi-git-dirs`
**Spec:** §6.2, §6.2.1

**What it tests:** Multiple `.git` directories at various levels (root and inside a submodule directory) are all correctly excluded from the signed manifest.

**Setup:** `models/multi-git-dirs` with `model.bin` and `submodule/model.bin` signed, plus `.git/HEAD` and `submodule/.git/HEAD` excluded.

**Why it exists:** Nested repositories and submodules create multiple `.git` directories; the implementation must handle exclusions at every level, not just the root.

**Expected outcome:** Exit code 0.

**Impact if it fails:** `.git` directories inside nested submodules would leak into the signed manifest, breaking verification in repositories with submodules.

#### `key-multi-gitignore`
**Spec:** §6.2, §6.2.1

**What it tests:** Multiple `.gitignore` files at various levels (root and inside subdirectories) are all correctly excluded from the signed manifest.

**Setup:** `models/multi-gitignore` with `model.bin` and `subdir/data.bin` signed, plus `.gitignore` at the root and `subdir/.gitignore` excluded.

**Why it exists:** Projects often have `.gitignore` files at multiple directory levels; the implementation must handle exclusions for all of them consistently.

**Expected outcome:** Exit code 0.

**Impact if it fails:** `.gitignore` files at non-root levels would appear in the signed manifest, causing verification mismatches when those files are absent or changed.

#### `key-nested-git-not-excluded`
**Spec:** §6.2

**What it tests:** A `.gitignore` file inside a **subdirectory** (e.g. `subdir/.gitignore`) is **not** auto-excluded by the default ignore list. Default exclusions match only top-level path components.

**Setup:** `models/with-nested-gitignore` with `model.bin` and `subdir/.gitignore`.

**Why it exists:** An implementation that overzealously strips `.gitignore` at any depth would silently omit user model content. This test ensures only top-level git paths are auto-excluded per §6.2.1.

**Expected outcome:** Exit code 0. Expected signed files: `["model.bin", "subdir/.gitignore"]`.

**Impact if it fails:** Files with git-pattern names inside subdirectories would be silently excluded from the manifest, creating an integrity gap.

#### `key-ignore-paths-exact-match`
**Spec:** §6.2.1

**What it tests:** User-specified `--ignore-paths` matches only at the **exact relative path from the model root**. An entry `ignore-me` excludes the top-level `ignore-me` but NOT `subdir/ignore-me`.

**Setup:** `models/with-nested-ignore` with `signme-1`, `ignore-me`, and `subdir/ignore-me`. Only top-level `ignore-me` is excluded.

**Why it exists:** Distinguishes exact-path matching from recursive or substring matching. Without this test, a signer that excludes `ignore-me` at any depth would pass all existing tests because no model fixture has a nested file with the same name as an ignored path.

**Expected outcome:** Exit code 0. Expected signed files: `["signme-1", "subdir/ignore-me"]`.

**Impact if it fails:** User ignore paths would silently exclude files deeper in the tree, breaking the spec's exact-path-from-root semantics.

#### `key-simple-deterministic`
**Spec:** §6.4, §6.5.1

**What it tests:** Running **sign twice** on the same model and keys yields **identical** resource `name` ordering and per-file **digests** (and thus stable root material), with no time- or run-dependent fields leaking into the hashed predicate for files.

**Setup:** Two sign passes in the same case or repeated invocation as defined by the harness; same inputs.

**Why it exists:** Reproducible builds, CI caching, and diffing manifests require deterministic outputs.

**Expected outcome:** Exit code 0; resource names and digests match between runs.

**Impact if it fails:** **Non-deterministic signing** breaks reproducible releases and complicates cross-signer interop and auditing.

#### `key-sig-inside-model`
**Spec:** §6.2, §9

**What it tests:** When the **bundle** file (e.g. `bundle.sig`) is placed **inside** the model directory, the signing implementation must **auto-exclude** that path from the file manifest so the signature does not hash itself (no circular dependency / self-inclusion).

**Setup:** `sig_inside_model: true` in config; bundle path not counted as a normal model resource.

**Why it exists:** The spec says the output bundle must be out of the signed path or explicitly handled; in-repo bundle placement is a real layout.

**Expected outcome:** Exit code 0. `bundle.sig` (or configured name) is **not** in the resources / expected signed file list.

**Impact if it fails:** The **signature would be part of** its own manifest, voiding the intended model digest semantics.

#### `key-empty-model-rejected`
**Spec:** §6.1

**What it tests:** If the model directory, after all **default** exclusions, contains **no** signable files (e.g. only `.gitignore` in `models/empty` which is auto-excluded), the **signer** must **reject** the operation: a model with zero resources is invalid.

**Setup:** `models/empty` (or equivalent) where only default-excluded content remains; expect failure per spec.

**Why it exists:** The spec requires at least one file after enumeration and exclusions; signing “nothing” is a logic error and could produce useless or ambiguous bundles.

**Expected outcome:** Signing must fail (non-zero exit). If the client signs an empty model, the test fails - the client is out of spec.

**Impact if it fails:** The client is out of spec; users could publish meaningless signed bundles for empty trees.

#### `key-symlink-default-rejected`
**Spec:** §6.1.1

**What it tests:** A model copy is modified to include an **internal symlink** (e.g. via `model_modifications.symlinks`); with default `allow_symlinks=false`, the **signer** must **reject** the model (not follow the symlink as if it were a file).

**Setup:** Symlink created inside the model; default symlink policy (reject).

**Why it exists:** Symlinks complicate the threat model and path semantics; the default must be the secure, explicit “no symlinks” behavior unless opted in (if the spec allows opt-in).

**Expected outcome:** Signing must fail (non-zero exit). If the client follows symlinks instead of rejecting, the test fails.

**Impact if it fails:** Conformance to symlink rules is not met; signers that follow links may include unintended or attacker-controlled path targets.

#### `key-symlink-outside-root`
**Spec:** §6.1.1

**What it tests:** A symlink under the model points **outside** the model root (e.g. to `/tmp/nonexistent-target` or similar); the signer must **error**, not read arbitrary filesystem locations through the link.

**Setup:** `model_modifications` adds an out-of-root symlink; default or explicit `allow_symlinks` as the case requires.

**Why it exists:** Out-of-tree symlinks are a classic exfiltration or confusion vector; the spec requires a hard error.

**Expected outcome:** Signing must fail (non-zero exit) with a clear error about out-of-root symlink.

**Impact if it fails:** Security and clarity: the signing scope could include files outside the intended model directory.

#### `key-symlink-cycle`
**Spec:** §6.1.1

**What it tests:** A **directory symlink** that creates a **cycle** (e.g. points to `.` in a way that loops); the walk must **detect** the cycle and **error** rather than infinite-loop or skip silently in an unsafe way.

**Setup:** `model_modifications` introduces a cycle (as defined in the test harness).

**Why it exists:** Cycles in symlink layouts must be detected; silent skip can hide parts of the tree or make behavior implementation-defined.

**Expected outcome:** Signing must fail (non-zero exit) with a clear cycle detection error.

**Impact if it fails:** Unpredictable manifest contents or non-spec behavior when user models contain symlink cycles.

#### `sigstore-simple`
**Spec:** §4.1

**What it tests:** End-to-end **keyless** sigstore signing and verification on a simple model. Uses a GitHub Actions OIDC token to obtain a Fulcio certificate and records a Rekor transparency log entry.

**Setup:** Requires CI environment (`SIGSTORE_ID_TOKEN`). The sign step receives the OIDC token via `--identity-token`; the verify step checks `--identity` and `--identity-provider`. Skipped locally.

**Why it exists:** Core validation that the `sigstore` method works end-to-end through the conformance adapter.

**Expected outcome:** Sign succeeds (exit 0), bundle contains Fulcio cert + tlogEntries, verify succeeds.

**Impact if it fails:** Sigstore signing/verification is broken in the client's conformance adapter.

#### `sigstore-multi-file`
**Spec:** §4.1, §6.1, §6.1.2

**What it tests:** Keyless sigstore signing on a **multi-file model** with subdirectories. Ensures path canonicalization (§6.1.2) and file enumeration (§6.1) work correctly with sigstore bundles.

**Setup:** Uses the `models/multi-file` fixture with nested directories. Requires CI.

**Why it exists:** Validates that sigstore works beyond trivial single-file models and that path handling is consistent across signing methods.

**Expected outcome:** All files in subdirectories correctly enumerated and signed. Verify succeeds.

**Impact if it fails:** Path handling diverges between PKI methods, or sigstore bundles don't cover deep directory trees.

#### `sigstore-ignore-paths`
**Spec:** §4.1, §6.2

**What it tests:** Keyless sigstore signing with `--ignore-paths` exclusions. Files matching the ignore list must not appear in the bundle.

**Setup:** Uses `models/simple` with `ignore-me` excluded. Requires CI.

**Why it exists:** Validates that `ignore_paths` semantics (§6.2) are consistent for the sigstore method.

**Expected outcome:** Bundle contains only non-excluded files. Verify succeeds with matching ignore list.

**Impact if it fails:** Path exclusion logic diverges between signing methods.

#### `sigstore-single-file`
**Spec:** §4.1, §6.1

**What it tests:** Keyless sigstore sign-then-verify on a **single-file** model, ensuring the sigstore method handles the simplest possible model correctly.

**Setup:** Uses `models/single-file`. Requires CI (OIDC token). Skipped locally.

**Why it exists:** Validates that sigstore works for single-file models, not just directories.

**Expected outcome:** Sign and verify both succeed. Skipped locally.

**Impact if it fails:** Sigstore method cannot handle single-file models.

#### `sigstore-sig-inside-model`
**Spec:** §4.1, §6.2

**What it tests:** Keyless sigstore signing with the **bundle placed inside the model directory**. Validates that the signature file is auto-excluded from the manifest (§6.2).

**Setup:** Uses `models/simple` with `sig_inside_model: true`. Requires CI. Skipped locally.

**Why it exists:** Tests signature file auto-exclusion with the sigstore method, ensuring the exclusion logic is method-agnostic.

**Expected outcome:** Sign and verify succeed. Bundle does not include its own path in the manifest.

**Impact if it fails:** Signature file auto-exclusion is broken for sigstore, causing verification to fail or including the bundle in its own manifest.

---

## Bundle validation (roundtrip)

After each successful `sign`, the harness (via `test/test_roundtrip.py` and `oms-schemas`) checks:

- **JSON Schema** for the outer bundle and the statement/predicate (§8.1, §8.3).
- **Resource descriptor order** - lexicographic by `name` (§6.4).
- **Root digest** - recomputed from per-file digests (§6.5.1).
- **Subject name** - must equal the basename of the model path (§6.5).
- **Path canonicalization** - no leading `/`, `../`, `./`, `//`, or trailing `/` in resource names (§6.1.2).
- **Algorithm consistency** - every resource `algorithm` matches `serialization.hash_type` (§6.3.1).
- **No shard_size for files method** - `shard_size` must be absent when method is `"files"` (§5.2.2).
- **PredicateType** - must be the current v1.0 URI, not the deprecated v0.1 (§5.1).
- **Key hint** - key-method bundles must use `publicKey.hint` (§4.1).
- **Signature file exclusion** when `sig_inside_model` is set - bundle path not in signed set (§6.2, §9).

---

## Not covered

| Spec | Gap | Why |
|---|---|---|
| §6.3.2 | Shard serialization (`"shards"` method) | Adapter CLI does not expose `--serialization` flag; needs protocol extension. |
| §7 | BLAKE2b / BLAKE3 | Optional algorithms; adapter CLI does not expose `--hash-algorithm` flag. |
| §10 | Rejection of unsupported algorithm/method | No negative test that requests an unsupported hash or serialization method and asserts an informative error. Needs adapter protocol extension for `--hash-algorithm` and `--serialization`. |

---

## Config schema (`config.json`)

All cases share one shape. Roundtrip cases add a `sign` block; negative verify cases may set `model_modifications`.

| Field | Required | Default | Notes |
|---|---|---|---|
| `description` | yes | - | Human-readable one-line purpose. |
| `method` | yes | - | `key`, `certificate`, or `sigstore` (as used by the adapter). |
| `model` | yes | - | Path to fixture, usually under `test/assets/`. |
| `model_relative_to` | no | `assets` | `assets` or `test_dir` (historical bundles colocated with model). |
| `expect` | no | `pass` | `pass` or `fail` (e.g. empty-model rejection). |
| `sig_inside_model` | no | `false` | If true, place `bundle.sig` inside the model copy for the test. |
| `requires_ci` | no | `false` | If true, test is skipped outside CI (e.g. sigstore needing OIDC). |
| `sign` | roundtrip | - | `private_key`, `signing_cert`, `cert_chain`, `identity_token_env`, `use_staging`. |
| `verify` | when verifying | - | `public_key`, `cert_chain`, `ignore_paths`, `ignore_unsigned_files`, `identity`, `identity_provider`, `use_staging`. |
| `expected_signed_files` | no | - | Exact sorted manifest file list to assert. |
| `model_modifications` | no | - | `tamper` / `delete` / `inject` / `symlinks` for pre-sign or pre-verify model changes. |

Example (abbreviated):

```json
{
  "description": "…",
  "method": "key",
  "model": "models/simple",
  "model_relative_to": "assets",
  "expect": "pass",
  "sig_inside_model": false,
  "sign": { "private_key": "keys/…/signing-key.pem" },
  "verify": {
    "public_key": "keys/…/signing-key-pub.pem",
    "ignore_paths": ["ignore-me"],
    "ignore_unsigned_files": false
  },
  "expected_signed_files": ["signme-1", "signme-2"],
  "model_modifications": { "tamper": {}, "delete": [], "inject": {}, "symlinks": {} }
}
```

---

## Test count summary

| Category | Count |
|---|---|
| Verify - positive | 6 |
| Verify - negative | 32 |
| Verify - historical | 15 |
| Roundtrip | 37 |
| **Total** | **90** |

