"""Parametrized bundle verification tests.

Test cases are defined in YAML config files under the ``policy-positive``,
``policy-negative``, and ``historical`` categories.  Each entry references
a test directory that must contain:
  - ``bundle.sig``   -- the pre-committed bundle to verify

Shared assets (models, keys) live in test/assets/ and are referenced by
config fields resolved against that root.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from .client import ModelSigningClient, CaseConfig, sigstore_token_available
from .schema_validator import validate_bundle

ASSETS = Path(__file__).parent / "assets"
TEST_CASES = Path(__file__).parent / "test-cases"



def _resolve_model(
    cfg: CaseConfig, verify_dir: Path, tmp_path: Path,
) -> Path:
    """Resolve model path and copy to temp dir."""
    if cfg.model_relative_to == "test_dir":
        model_src = verify_dir / cfg.model
    else:
        model_src = ASSETS / "models" / cfg.model

    if not model_src.exists():
        pytest.fail(f"Model not found: {model_src}")

    if model_src.is_file():
        model_copy = tmp_path / model_src.name
        shutil.copy2(model_src, model_copy)
    else:
        model_copy = tmp_path / "model"
        shutil.copytree(model_src, model_copy)

    if cfg.model_modifications:
        target = model_copy if model_copy.is_dir() else model_copy.parent
        cfg.model_modifications.apply(target)

    return model_copy


def test_verify(
    client: ModelSigningClient, verify_cfg: CaseConfig, tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    """Verify a pre-committed bundle."""
    cfg = verify_cfg
    if cfg.test_dir is None:
        pytest.fail(f"test_dir not set for {cfg.id}")
    verify_dir = TEST_CASES / "verify" / cfg.test_dir
    label = f"{cfg.id}: {cfg.description}"

    if cfg.method == "sigstore" and request.config.getoption("--skip-sigstore"):
        pytest.skip(f"[{label}] skipped (--skip-sigstore)")
    if cfg.requires_ci and not sigstore_token_available():
        pytest.skip(f"[{label}] requires OIDC token (set SIGSTORE_ID_TOKEN or SIGSTORE_ID_TOKEN_FILE)")

    bundle = verify_dir / "bundle.sig"
    if not bundle.exists():
        pytest.fail(f"Missing bundle.sig in {verify_dir}")

    expected_fail = cfg.expect == "fail"

    if not expected_fail and bundle.stat().st_size > 0:
        validate_bundle(bundle, method=cfg.method)

    model_path = _resolve_model(cfg, verify_dir, tmp_path)

    keys_root = verify_dir if cfg.keys_relative_to == "test_dir" else ASSETS

    result = client.verify(
        method=cfg.method,
        model_path=model_path,
        bundle=bundle,
        cfg=cfg,
        keys_root=keys_root,
    )

    if expected_fail:
        assert result.returncode != 0, (
            f"[{label}] Expected verification to FAIL but it succeeded.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    else:
        assert result.returncode == 0, (
            f"[{label}] Expected verification to PASS but it failed.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

        if cfg.expected_signed_files:
            actual = client.get_signed_files(bundle)
            assert actual == sorted(cfg.expected_signed_files), (
                f"[{label}] Signed files mismatch:\n"
                f"  expected: {sorted(cfg.expected_signed_files)}\n"
                f"  actual:   {actual}"
            )
