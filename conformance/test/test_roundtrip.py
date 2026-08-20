"""Sign-then-verify round-trip tests.

Test cases are defined in ``roundtrip.yaml``.  Each entry specifies the
method, model, key material, and expected outcomes.  Shared assets (models,
keys) live in ``test/assets/``.

These tests require signing capability and are skipped when ``--skip-signing`` is passed.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from .client import ModelSigningClient, CaseConfig, sigstore_token_available
from .schema_validator import validate_bundle, decode_payload

ASSETS = Path(__file__).parent / "assets"


def _assert_resources_sorted(bundle_path: Path) -> None:
    """Assert resource descriptors in the predicate are sorted by name (§6.4)."""
    bundle = json.loads(bundle_path.read_text())
    statement = decode_payload(bundle)
    resources = statement.get("predicate", {}).get("resources", [])
    names = [r["name"] for r in resources]
    assert names == sorted(names), (
        f"Resource descriptors must be lexicographically sorted by name.\n"
        f"  got: {names}\n"
        f"  want: {sorted(names)}"
    )


def _assert_root_digest(bundle_path: Path) -> None:
    """Assert subject digest matches SHA-256 over concatenated resource digests (§6.5.1).

    The root digest is computed as:
      SHA-256( raw_bytes(resource[0].digest) || raw_bytes(resource[1].digest) || ... )
    where resources are in canonical (sorted-by-name) order and each hex digest
    is decoded to raw bytes before concatenation.
    """
    bundle = json.loads(bundle_path.read_text())
    statement = decode_payload(bundle)

    resources = statement["predicate"]["resources"]
    concat = b""
    for r in resources:
        concat += bytes.fromhex(r["digest"])
    expected = hashlib.sha256(concat).hexdigest()

    subjects = statement.get("subject", [])
    assert len(subjects) == 1, f"Expected exactly 1 subject, got {len(subjects)}"
    actual = subjects[0].get("digest", {}).get("sha256")
    assert actual is not None, "subject[0].digest.sha256 is missing"
    assert actual == expected, (
        f"Root digest mismatch (§6.5.1):\n"
        f"  subject.digest.sha256: {actual}\n"
        f"  recomputed from resources: {expected}"
    )


def _assert_signature_excluded(bundle_path: Path, model_path: Path) -> None:
    """Assert the bundle file itself is not listed in resources (§6.2)."""
    bundle = json.loads(bundle_path.read_text())
    statement = decode_payload(bundle)
    names = {r["name"] for r in statement["predicate"]["resources"]}

    bundle_name = bundle_path.name
    try:
        rel = bundle_path.resolve().relative_to(model_path.resolve())
        bundle_name = str(rel).replace("\\", "/")
    except ValueError:
        pass

    assert bundle_name not in names, (
        f"Signature file '{bundle_name}' must be excluded from resources (§6.2)"
    )


def _assert_subject_name(bundle_path: Path, model_path: Path) -> None:
    """Assert subject[0].name equals the basename of the model path (§6.5)."""
    bundle = json.loads(bundle_path.read_text())
    statement = decode_payload(bundle)
    subjects = statement.get("subject", [])
    assert len(subjects) == 1, f"Expected exactly 1 subject, got {len(subjects)}"
    actual_name = subjects[0].get("name")
    expected_name = model_path.name
    assert actual_name == expected_name, (
        f"subject[0].name mismatch (§6.5):\n"
        f"  actual:   {actual_name!r}\n"
        f"  expected: {expected_name!r}"
    )


def _assert_paths_canonical(bundle_path: Path) -> None:
    """Assert all resource names follow path canonicalization rules (§6.1.2)."""
    bundle = json.loads(bundle_path.read_text())
    statement = decode_payload(bundle)
    resources = statement.get("predicate", {}).get("resources", [])
    for r in resources:
        name = r["name"]
        assert not name.startswith("/"), (
            f"Resource name must not start with '/' (§6.1.2): {name!r}"
        )
        assert "/../" not in f"/{name}/" and not name.startswith("../"), (
            f"Resource name must not contain '../' components (§6.1.2): {name!r}"
        )
        assert not name.endswith("/"), (
            f"Resource name must not have trailing '/' (§6.1.2): {name!r}"
        )
        assert "//" not in name, (
            f"Resource name must not contain consecutive separators (§6.1.2): {name!r}"
        )
        parts = name.split("/")
        assert "." not in parts, (
            f"Resource name must not contain '.' components (§6.1.2): {name!r}"
        )


def _assert_no_shard_size_for_files(bundle_path: Path) -> None:
    """Assert shard_size is absent when serialization.method is 'files' (§5.2.2)."""
    bundle = json.loads(bundle_path.read_text())
    statement = decode_payload(bundle)
    ser = statement.get("predicate", {}).get("serialization", {})
    if ser.get("method") == "files":
        assert "shard_size" not in ser, (
            "shard_size MUST be absent when method is 'files' (§5.2.2)"
        )


def _assert_algorithm_consistency(bundle_path: Path) -> None:
    """Assert resource algorithm fields match serialization.hash_type (§6.3.1)."""
    bundle = json.loads(bundle_path.read_text())
    statement = decode_payload(bundle)
    ser = statement.get("predicate", {}).get("serialization", {})
    hash_type = ser.get("hash_type")
    if not hash_type:
        return
    resources = statement.get("predicate", {}).get("resources", [])
    for r in resources:
        assert r.get("algorithm") == hash_type, (
            f"Resource algorithm mismatch (§6.3.1):\n"
            f"  resource '{r['name']}' algorithm: {r.get('algorithm')!r}\n"
            f"  serialization.hash_type: {hash_type!r}"
        )


def _assert_key_uses_hint(bundle_path: Path) -> None:
    """Assert key-method bundles use publicKey.hint, not rawBytes (§4.1)."""
    bundle = json.loads(bundle_path.read_text())
    vm = bundle.get("verificationMaterial", {})
    pk = vm.get("publicKey", {})
    if not pk:
        return
    assert "hint" in pk, (
        "Producers MUST use the 'hint' field in publicKey (§4.1), "
        "found keys: " + str(list(pk.keys()))
    )
    assert pk["hint"], "publicKey.hint must be a non-empty string (§4.1)"


def _assert_predicate_type(bundle_path: Path) -> None:
    """Assert predicateType is the current v1.0 URI, not deprecated (§5.1)."""
    bundle = json.loads(bundle_path.read_text())
    statement = decode_payload(bundle)
    expected = "https://model_signing/signature/v1.0"
    actual = statement.get("predicateType")
    assert actual == expected, (
        f"predicateType mismatch (§5.1):\n"
        f"  actual:   {actual!r}\n"
        f"  expected: {expected!r}"
    )


@pytest.mark.signing
def test_roundtrip(
    client: ModelSigningClient, roundtrip_cfg: CaseConfig, tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    """Sign a model then verify the produced bundle with the same client."""
    cfg = roundtrip_cfg
    label = f"{cfg.id}: {cfg.description}"

    if cfg.method == "sigstore" and request.config.getoption("--skip-sigstore"):
        pytest.skip(f"[{label}] skipped (--skip-sigstore)")
    if cfg.requires_ci and not sigstore_token_available():
        pytest.skip(f"[{label}] requires OIDC token (set SIGSTORE_ID_TOKEN or SIGSTORE_ID_TOKEN_FILE)")

    model_src = ASSETS / "models" / cfg.model
    if not model_src.exists():
        pytest.fail(f"Model directory not found: {model_src}")

    model_copy = tmp_path / "model"
    shutil.copytree(model_src, model_copy)

    if cfg.model_modifications:
        cfg.model_modifications.apply(model_copy)

    if cfg.sig_inside_model:
        bundle_path = model_copy / "bundle.sig"
    else:
        bundle_path = tmp_path / "bundle.sig"

    sign_result = client.sign(
        method=cfg.method,
        model_path=model_copy,
        output_bundle=bundle_path,
        cfg=cfg,
        assets_root=ASSETS,
    )

    if cfg.expect == "fail":
        assert sign_result.returncode != 0, (
            f"[{label}] Expected signing to FAIL but it succeeded.\n"
            f"stdout: {sign_result.stdout}\nstderr: {sign_result.stderr}"
        )
        return

    assert sign_result.returncode == 0, (
        f"[{label}] Signing failed.\n"
        f"stdout: {sign_result.stdout}\nstderr: {sign_result.stderr}"
    )
    assert bundle_path.exists(), f"[{label}] bundle.sig not created after signing"

    validate_bundle(bundle_path, method=cfg.method)
    _assert_resources_sorted(bundle_path)
    _assert_root_digest(bundle_path)
    _assert_paths_canonical(bundle_path)
    _assert_subject_name(bundle_path, model_copy)
    _assert_no_shard_size_for_files(bundle_path)
    _assert_algorithm_consistency(bundle_path)
    _assert_predicate_type(bundle_path)
    if cfg.method == "key":
        _assert_key_uses_hint(bundle_path)
    if cfg.sig_inside_model:
        _assert_signature_excluded(bundle_path, model_copy)

    verify_block = cfg.verify
    if verify_block and verify_block.ignore_unsigned_files and verify_block.ignore_paths:
        (model_copy / "injected.bin").write_text("injected after signing\n")

    verify_result = client.verify(
        method=cfg.method,
        model_path=model_copy,
        bundle=bundle_path,
        cfg=cfg,
        keys_root=ASSETS,
    )
    assert verify_result.returncode == 0, (
        f"[{label}] Verification failed.\n"
        f"stdout: {verify_result.stdout}\nstderr: {verify_result.stderr}"
    )

    if cfg.expected_signed_files:
        actual = client.get_signed_files(bundle_path)
        assert actual == sorted(cfg.expected_signed_files), (
            f"[{label}] Signed files mismatch:\n"
            f"  expected: {sorted(cfg.expected_signed_files)}\n"
            f"  actual:   {actual}"
        )

    if "deterministic" in cfg.id:
        bundle_path2 = tmp_path / "bundle2.sig"
        sign_result2 = client.sign(
            method=cfg.method,
            model_path=model_copy,
            output_bundle=bundle_path2,
            cfg=cfg,
            assets_root=ASSETS,
        )
        assert sign_result2.returncode == 0
        assert client.get_signed_files(bundle_path) == client.get_signed_files(bundle_path2), (
            f"[{label}] Non-deterministic signing detected (file names differ)"
        )
        resources1 = client.get_resource_descriptors(bundle_path)
        resources2 = client.get_resource_descriptors(bundle_path2)
        assert resources1 == resources2, (
            f"[{label}] Non-deterministic signing detected (digests differ)"
        )
