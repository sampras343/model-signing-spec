"""Download pre-signed test fixtures from an OCI registry (ghcr.io).

These are irreproducible bundles (historical, Go-interop, sigstore-negative)
that cannot be regenerated at test time. They are stored as OCI artifacts
on ghcr.io, signed with cosign, and verified before extraction.

The ``fixtures`` config (loaded from YAML by ``config_loader``) specifies
the OCI image reference, digest, and cosign verification parameters.

Execution contexts
------------------

**CI (GitHub Actions):**
    Fixtures are downloaded and verified in an explicit workflow step
    *before* pytest runs (see ``.github/workflows/conformance-ci.yml``).
    This module is NOT invoked in CI -- the workflow uses ``cosign verify``
    and ``oras pull`` directly for better error visibility and caching.

**Local development:**
    This module is called by the ``generate_test_assets`` session fixture
    in ``conftest.py``. It requires ``cosign`` and ``oras`` CLIs on PATH.
    If either is missing, fixture download is skipped with a warning and
    tests that depend on downloaded bundles will fail.

    To install the prerequisites::

        # cosign
        go install github.com/sigstore/cosign/v2/cmd/cosign@latest
        # or: brew install cosign

        # oras
        go install oras.land/oras/cmd/oras@latest
        # or: brew install oras

    Or download manually and extract into the verify directory::

        oras pull ghcr.io/sampras343/model-signing-spec/conformance-fixtures@sha256:... \\
            --output /tmp/fixtures
        tar xzf /tmp/fixtures/*.tar.gz -C conformance/test/test-cases/verify/
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


def _run(args: list[str], label: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        logger.warning("%s failed:\n  %s", label, result.stderr.strip())
    return result


def download_fixtures(
    test_cases_dir: Path,
    fixtures_cfg: dict,
) -> None:
    """Download, verify, and extract pre-signed fixtures if not present.

    Args:
        test_cases_dir: Path to ``conformance/test/test-cases/``.
        fixtures_cfg: Fixtures configuration dict from config_loader.

    Flow:
      1. Check marker file -- skip if already downloaded for this digest
      2. cosign verify -- validate signature against expected identity/issuer
      3. oras pull -- download the OCI artifact
      4. Extract tarball into verify test-cases directory
    """
    if not fixtures_cfg:
        logger.warning("No fixtures configuration provided -- skipping download")
        return

    verify_dir = test_cases_dir / "verify"
    marker = verify_dir / ".fixtures-downloaded"

    image = fixtures_cfg["image"]
    digest = fixtures_cfg["digest"]
    image_ref = f"{image}@{digest}"

    if marker.exists() and marker.read_text().strip() == digest:
        logger.info("Fixtures already downloaded (digest: %s)", digest[:16])
        return

    historical_dir = verify_dir / "historical"
    if historical_dir.exists() and any(historical_dir.rglob("bundle.sig")):
        logger.info("Historical bundles already present -- writing marker")
        marker.write_text(digest + "\n")
        return

    # Step 1: Verify cosign signature
    cosign_cfg = fixtures_cfg.get("cosign", {})
    identity = cosign_cfg.get("certificate_identity", "")
    issuer = cosign_cfg.get("certificate_oidc_issuer", "")

    if shutil.which("cosign") is None:
        if identity and issuer:
            logger.error(
                "cosign not found but signature verification is required -- "
                "refusing to download unverified artifacts. "
                "Install cosign: https://docs.sigstore.dev/cosign/installation/"
            )
            return
        logger.warning("cosign not found -- skipping signature verification")
    elif identity and issuer:
        logger.info("Verifying cosign signature for %s...", image_ref)
        result = _run(
            [
                "cosign", "verify",
                "--certificate-identity", identity,
                "--certificate-oidc-issuer", issuer,
                image_ref,
            ],
            "cosign verify",
        )
        if result.returncode != 0:
            logger.error(
                "Cosign verification FAILED for %s -- refusing to download.\n"
                "  Expected identity: %s\n  Expected issuer: %s",
                image_ref, identity, issuer,
            )
            return
        logger.info("Cosign signature verified")
    else:
        logger.warning("No cosign identity/issuer configured -- skipping verification")

    # Step 2: Pull with oras
    if shutil.which("oras") is None:
        logger.warning(
            "oras not found -- cannot download fixtures. "
            "Install oras: https://oras.land/docs/installation"
        )
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        logger.info("Pulling %s...", image_ref)
        result = _run(
            ["oras", "pull", image_ref, "--output", str(tmp)],
            "oras pull",
        )
        if result.returncode != 0:
            return

        tarballs = list(tmp.glob("*.tar.gz"))
        if not tarballs:
            logger.warning("No .tar.gz found in pulled artifact")
            return

        tarball = tarballs[0]
        logger.info("Extracting %s to %s", tarball.name, verify_dir)
        with tarfile.open(tarball, "r:gz") as tf:
            tf.extractall(path=verify_dir, filter="data")

    marker.write_text(digest + "\n")
    logger.info("Fixtures downloaded and verified (digest: %s)", digest[:16])


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    here = Path(__file__).resolve().parent
    test_cases = here.parent / "test-cases"
    config_dir = here.parent.parent.parent / "config"

    if not config_dir.exists():
        print(f"Config directory not found at {config_dir}", file=sys.stderr)
        sys.exit(1)

    from conformance.test.config_loader import load_suite
    suite = load_suite(config_dir, test_cases)
    download_fixtures(test_cases, suite.fixtures)
