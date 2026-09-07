"""Generate all test key material for the conformance test suite.

This module replaces the old certtool-based gen.sh script with a pure-Python
implementation using the ``cryptography`` library.  It produces the exact
directory layout expected by every conformance test configuration under
``conformance/test/assets/keys/``.

EC curves are read from the ``keys_manifest`` (loaded from ``keys.yaml`` by
``config_loader``) so that adding or changing a curve only requires a YAML
edit.  When no manifest is supplied the function falls back to hardcoded
defaults for backward compatibility.

Usage (CLI)::

    python -m conformance.test.assets.generate_keys [output_dir] [--config-dir PATH]

Usage (programmatic)::

    from conformance.test.assets.generate_keys import generate_all_keys
    generate_all_keys(Path("conformance/test/assets"), keys_manifest=keys_dict)
"""

from __future__ import annotations

import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_private_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    """Serialize an EC private key to PEM (no encryption)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_public_key(path: Path, key: ec.EllipticCurvePublicKey) -> None:
    """Serialize an EC public key to SubjectPublicKeyInfo PEM."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    """Serialize a certificate to PEM."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _generate_ec_keypair(
    curve: ec.EllipticCurve,
) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    key = ec.generate_private_key(curve)
    return key, key.public_key()


# Mapping from keys.yaml curve names to cryptography curve objects.
_CURVE_MAP: dict[str, ec.EllipticCurve] = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}


def _resolve_curve(
    keys_manifest: dict | None,
    group_name: str,
    fallback: ec.EllipticCurve,
) -> ec.EllipticCurve:
    """Resolve the EC curve for a key group from the manifest.

    Looks up ``keys_manifest[group_name]["curve"]`` and maps it through
    ``_CURVE_MAP``.  Returns *fallback* when the manifest is ``None``,
    the group is absent, or the curve name is unrecognized.
    """
    if keys_manifest and group_name in keys_manifest:
        curve_name = keys_manifest[group_name].get("curve")
        if curve_name and curve_name in _CURVE_MAP:
            return _CURVE_MAP[curve_name]
    return fallback


_TEN_YEARS = datetime.timedelta(days=3650)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _add_ski(
    builder: x509.CertificateBuilder,
    public_key: ec.EllipticCurvePublicKey,
) -> x509.CertificateBuilder:
    return builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False,
    )


def _add_aki(
    builder: x509.CertificateBuilder,
    ca_cert: x509.Certificate,
) -> x509.CertificateBuilder:
    return builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_cert.public_key()  # type: ignore[arg-type]
        ),
        critical=False,
    )


# ---------------------------------------------------------------------------
# Certificate builders
# ---------------------------------------------------------------------------

def _build_root_ca(
    key: ec.EllipticCurvePrivateKey,
    *,
    cn: str = "root-ca",
    not_valid_before: datetime.datetime | None = None,
    not_valid_after: datetime.datetime | None = None,
) -> x509.Certificate:
    """Self-signed root CA certificate."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    now = _now()
    pub = key.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before or now)
        .not_valid_after(not_valid_after or (now + _TEN_YEARS))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    builder = _add_ski(builder, pub)
    return builder.sign(key, hashes.SHA384())


def _build_intermediate_ca(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    int_key: ec.EllipticCurvePrivateKey,
    *,
    cn: str = "intermediate-ca",
    not_valid_before: datetime.datetime | None = None,
    not_valid_after: datetime.datetime | None = None,
) -> x509.Certificate:
    """Intermediate CA certificate signed by root CA."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    now = _now()
    pub = int_key.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before or now)
        .not_valid_after(not_valid_after or (now + _TEN_YEARS))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    builder = _add_ski(builder, pub)
    builder = _add_aki(builder, ca_cert)
    return builder.sign(ca_key, hashes.SHA384())


def _build_signing_cert(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    signing_pub: ec.EllipticCurvePublicKey,
    *,
    cn: str = "signing-key",
    not_valid_before: datetime.datetime | None = None,
    not_valid_after: datetime.datetime | None = None,
    is_ca: bool = False,
    include_code_signing_eku: bool = True,
) -> x509.Certificate:
    """Leaf signing certificate issued by a CA."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    now = _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(signing_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before or now)
        .not_valid_after(not_valid_after or (now + _TEN_YEARS))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None if is_ca else None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if include_code_signing_eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
    builder = _add_ski(builder, signing_pub)
    builder = _add_aki(builder, ca_cert)
    return builder.sign(ca_key, hashes.SHA384())


def _build_self_signed_cert(
    key: ec.EllipticCurvePrivateKey,
    *,
    cn: str = "self-signed-test",
) -> x509.Certificate:
    """Self-signed leaf certificate with code-signing EKU."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    pub = key.public_key()
    now = _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _TEN_YEARS)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
    )
    builder = _add_ski(builder, pub)
    # Self-signed: AKI from own public key
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(pub),
        critical=False,
    )
    return builder.sign(key, hashes.SHA256())


def _build_wrong_ca_cert(
    key: ec.EllipticCurvePrivateKey,
) -> x509.Certificate:
    """Self-signed CA certificate from a 'wrong' (unrelated) CA."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Wrong CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wrong"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    pub = key.public_key()
    now = _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _TEN_YEARS)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
    )
    builder = _add_ski(builder, pub)
    return builder.sign(key, hashes.SHA256())


# ---------------------------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------------------------

def _validate_against_manifest(keys_dir: Path, keys_manifest: dict) -> None:
    """Verify generated key files match the manifest from config_loader.

    Raises ``FileNotFoundError`` if a declared file is missing.
    Prints a warning for any generated file not in the manifest.

    Args:
        keys_dir: Path to the generated keys directory.
        keys_manifest: Normalized keys dict from config_loader.
                       Format: ``{name: {"files": [filename, ...]}}``
    """
    if not keys_manifest:
        return

    # Check all declared files exist
    missing: list[str] = []
    for dir_name, dir_spec in keys_manifest.items():
        for filename in dir_spec.get("files", []):
            path = keys_dir / dir_name / filename
            if not path.exists():
                missing.append(str(path))

    if missing:
        raise FileNotFoundError(
            "Key manifest validation failed -- declared files missing:\n"
            + "\n".join(f"  - {m}" for m in missing)
        )

    # Warn about undeclared files
    declared: set[str] = set()
    for dir_name, dir_spec in keys_manifest.items():
        for filename in dir_spec.get("files", []):
            declared.add(f"{dir_name}/{filename}")

    for path in keys_dir.rglob("*"):
        if path.is_file():
            rel = path.relative_to(keys_dir).as_posix()
            if rel not in declared:
                print(f"  warning: undeclared key file: keys/{rel}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_all_keys(
    output_dir: Path,
    keys_manifest: dict | None = None,
) -> None:
    """Generate all key material under ``output_dir/keys/``.

    This function is idempotent -- calling it again overwrites existing
    files with freshly-generated material.

    Args:
        output_dir: The base directory (typically ``conformance/test/assets``).
                    Keys are written into ``output_dir/keys/...``.
        keys_manifest: Optional normalized keys dict from config_loader.
                       If provided, the generated output is validated
                       against the manifest.
    """
    keys_dir = output_dir / "keys"

    # ------------------------------------------------------------------
    # certificate/ -- 3-level CA chain (curve from keys.yaml, default P-384)
    # ------------------------------------------------------------------
    cert_dir = keys_dir / "certificate"
    cert_curve = _resolve_curve(keys_manifest, "certificate", ec.SECP384R1())

    ca_key, _ = _generate_ec_keypair(cert_curve)
    ca_cert = _build_root_ca(ca_key)
    _write_private_key(cert_dir / "ca-priv.pem", ca_key)
    _write_cert(cert_dir / "ca-cert.pem", ca_cert)

    int_ca_key, _ = _generate_ec_keypair(cert_curve)
    int_ca_cert = _build_intermediate_ca(ca_key, ca_cert, int_ca_key)
    _write_private_key(cert_dir / "int-ca-priv.pem", int_ca_key)
    _write_cert(cert_dir / "int-ca-cert.pem", int_ca_cert)

    signing_key, signing_pub = _generate_ec_keypair(cert_curve)
    signing_cert = _build_signing_cert(
        int_ca_key,
        int_ca_cert,
        signing_pub,
        cn="signing-key",
        is_ca=False,
    )
    _write_private_key(cert_dir / "signing-key.pem", signing_key)
    _write_public_key(cert_dir / "signing-key-pub.pem", signing_pub)
    _write_cert(cert_dir / "signing-key-cert.pem", signing_cert)

    # ------------------------------------------------------------------
    # expired/ -- leaf cert signed by intermediate CA, already expired
    #             (curve from keys.yaml, default P-384)
    # ------------------------------------------------------------------
    expired_dir = keys_dir / "expired"
    expired_curve = _resolve_curve(keys_manifest, "expired", ec.SECP384R1())

    expired_key, expired_pub = _generate_ec_keypair(expired_curve)
    expired_cert = _build_signing_cert(
        int_ca_key,
        int_ca_cert,
        expired_pub,
        cn="expired-signing-key",
        not_valid_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
        not_valid_after=datetime.datetime(2020, 1, 2, tzinfo=datetime.timezone.utc),
        is_ca=False,
    )
    _write_private_key(expired_dir / "signing-key.pem", expired_key)
    _write_cert(expired_dir / "signing-key-cert.pem", expired_cert)

    # ------------------------------------------------------------------
    # not-yet-valid/ -- leaf cert whose validity period is in the future
    #                   (curve from keys.yaml, default P-384)
    # ------------------------------------------------------------------
    nyv_dir = keys_dir / "not-yet-valid"
    nyv_curve = _resolve_curve(keys_manifest, "not-yet-valid", ec.SECP384R1())

    nyv_key, nyv_pub = _generate_ec_keypair(nyv_curve)
    now = _now()
    nyv_cert = _build_signing_cert(
        int_ca_key,
        int_ca_cert,
        nyv_pub,
        cn="not-yet-valid-signing-key",
        not_valid_before=now + datetime.timedelta(days=365),
        not_valid_after=now + datetime.timedelta(days=730),
        is_ca=False,
    )
    _write_private_key(nyv_dir / "signing-key.pem", nyv_key)
    _write_cert(nyv_dir / "signing-key-cert.pem", nyv_cert)

    # ------------------------------------------------------------------
    # expired-intermediate/ -- expired intermediate CA with valid leaf
    #                          (curve from keys.yaml, default P-384)
    # ------------------------------------------------------------------
    ei_dir = keys_dir / "expired-intermediate"
    ei_curve = _resolve_curve(
        keys_manifest, "expired-intermediate", ec.SECP384R1(),
    )

    # Reuse the standard root CA (ca_key / ca_cert) from certificate/
    ei_int_key, _ = _generate_ec_keypair(ei_curve)
    ei_int_cert = _build_intermediate_ca(
        ca_key,
        ca_cert,
        ei_int_key,
        cn="expired-intermediate-ca",
        not_valid_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
        not_valid_after=datetime.datetime(2020, 1, 2, tzinfo=datetime.timezone.utc),
    )
    ei_leaf_key, ei_leaf_pub = _generate_ec_keypair(ei_curve)
    ei_leaf_cert = _build_signing_cert(
        ei_int_key,
        ei_int_cert,
        ei_leaf_pub,
        cn="leaf-of-expired-intermediate",
    )
    _write_private_key(ei_dir / "signing-key.pem", ei_leaf_key)
    _write_cert(ei_dir / "signing-key-cert.pem", ei_leaf_cert)
    _write_cert(ei_dir / "int-ca-cert.pem", ei_int_cert)

    # ------------------------------------------------------------------
    # expired-root/ -- expired root CA with valid intermediate and leaf
    #                  (curve from keys.yaml, default P-384)
    # ------------------------------------------------------------------
    er_dir = keys_dir / "expired-root"
    er_curve = _resolve_curve(keys_manifest, "expired-root", ec.SECP384R1())

    er_root_key, _ = _generate_ec_keypair(er_curve)
    er_root_cert = _build_root_ca(
        er_root_key,
        cn="expired-root-ca",
        not_valid_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
        not_valid_after=datetime.datetime(2020, 1, 2, tzinfo=datetime.timezone.utc),
    )
    er_int_key, _ = _generate_ec_keypair(er_curve)
    er_int_cert = _build_intermediate_ca(
        er_root_key, er_root_cert, er_int_key,
        cn="intermediate-of-expired-root",
    )
    er_leaf_key, er_leaf_pub = _generate_ec_keypair(er_curve)
    er_leaf_cert = _build_signing_cert(
        er_int_key, er_int_cert, er_leaf_pub,
        cn="leaf-of-expired-root",
    )
    _write_private_key(er_dir / "signing-key.pem", er_leaf_key)
    _write_cert(er_dir / "signing-key-cert.pem", er_leaf_cert)
    _write_cert(er_dir / "int-ca-cert.pem", er_int_cert)
    _write_cert(er_dir / "ca-cert.pem", er_root_cert)

    # ------------------------------------------------------------------
    # all-expired/ -- entire chain (root + intermediate + leaf) expired
    #                 (curve from keys.yaml, default P-384)
    # ------------------------------------------------------------------
    ae_dir = keys_dir / "all-expired"
    ae_curve = _resolve_curve(keys_manifest, "all-expired", ec.SECP384R1())

    ae_root_key, _ = _generate_ec_keypair(ae_curve)
    ae_root_cert = _build_root_ca(
        ae_root_key,
        cn="all-expired-root-ca",
        not_valid_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
        not_valid_after=datetime.datetime(2020, 6, 1, tzinfo=datetime.timezone.utc),
    )
    ae_int_key, _ = _generate_ec_keypair(ae_curve)
    ae_int_cert = _build_intermediate_ca(
        ae_root_key, ae_root_cert, ae_int_key,
        cn="all-expired-intermediate-ca",
        not_valid_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
        not_valid_after=datetime.datetime(2020, 6, 1, tzinfo=datetime.timezone.utc),
    )
    ae_leaf_key, ae_leaf_pub = _generate_ec_keypair(ae_curve)
    ae_leaf_cert = _build_signing_cert(
        ae_int_key, ae_int_cert, ae_leaf_pub,
        cn="all-expired-leaf",
        not_valid_before=datetime.datetime(2020, 2, 1, tzinfo=datetime.timezone.utc),
        not_valid_after=datetime.datetime(2020, 3, 1, tzinfo=datetime.timezone.utc),
    )
    _write_private_key(ae_dir / "signing-key.pem", ae_leaf_key)
    _write_cert(ae_dir / "signing-key-cert.pem", ae_leaf_cert)
    _write_cert(ae_dir / "int-ca-cert.pem", ae_int_cert)
    _write_cert(ae_dir / "ca-cert.pem", ae_root_cert)

    # ------------------------------------------------------------------
    # Standalone EC keypairs (curves from keys.yaml, defaults below)
    # ------------------------------------------------------------------
    _STANDALONE_DEFAULTS: dict[str, ec.EllipticCurve] = {
        "p256": ec.SECP256R1(),
        "p384": ec.SECP384R1(),
        "p521": ec.SECP521R1(),
    }
    for name, default_curve in _STANDALONE_DEFAULTS.items():
        curve = _resolve_curve(keys_manifest, name, default_curve)
        d = keys_dir / name
        k, pub = _generate_ec_keypair(curve)
        _write_private_key(d / "signing-key.pem", k)
        _write_public_key(d / "signing-key-pub.pem", pub)

    # ------------------------------------------------------------------
    # self-signed/ -- self-signed cert with code-signing EKU
    #                 (curve from keys.yaml, default P-256)
    # ------------------------------------------------------------------
    ss_dir = keys_dir / "self-signed"
    ss_curve = _resolve_curve(keys_manifest, "self-signed", ec.SECP256R1())
    ss_key, _ = _generate_ec_keypair(ss_curve)
    ss_cert = _build_self_signed_cert(ss_key, cn="self-signed-test")
    _write_private_key(ss_dir / "signing-key.pem", ss_key)
    _write_cert(ss_dir / "signing-cert.pem", ss_cert)

    # ------------------------------------------------------------------
    # wrong/ -- independent keypair + unrelated self-signed CA
    #           (curve from keys.yaml, default P-256)
    # ------------------------------------------------------------------
    wrong_dir = keys_dir / "wrong"
    wrong_curve = _resolve_curve(keys_manifest, "wrong", ec.SECP256R1())
    wrong_key, wrong_pub = _generate_ec_keypair(wrong_curve)
    wrong_ca_cert = _build_wrong_ca_cert(wrong_key)
    _write_public_key(wrong_dir / "wrong-key-pub.pem", wrong_pub)
    _write_cert(wrong_dir / "wrong-ca-cert.pem", wrong_ca_cert)

    # ------------------------------------------------------------------
    # no-code-signing/ -- cert WITHOUT code_signing EKU
    #                     (signed by the certificate chain's intermediate CA)
    # ------------------------------------------------------------------
    ncs_dir = keys_dir / "no-code-signing"
    ncs_curve = _resolve_curve(keys_manifest, "no-code-signing", ec.SECP384R1())
    ncs_key, ncs_pub = _generate_ec_keypair(ncs_curve)
    ncs_cert = _build_signing_cert(
        int_ca_key,
        int_ca_cert,
        ncs_pub,
        cn="no-code-signing",
        include_code_signing_eku=False,
    )
    _write_private_key(ncs_dir / "signing-key.pem", ncs_key)
    _write_cert(ncs_dir / "signing-key-cert.pem", ncs_cert)

    # ------------------------------------------------------------------
    # Validate against manifest if provided
    # ------------------------------------------------------------------
    if keys_manifest is not None:
        _validate_against_manifest(keys_dir, keys_manifest)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
    else:
        # Default: conformance/test/assets relative to repo root
        target = Path(__file__).resolve().parent

    keys_manifest = None
    config_dir = None
    for i, arg in enumerate(sys.argv):
        if arg == "--config-dir" and i + 1 < len(sys.argv):
            config_dir = Path(sys.argv[i + 1])

    if config_dir:
        from conformance.test.config_loader import load_suite
        test_cases_dir = Path(__file__).resolve().parent.parent / "test-cases"
        suite = load_suite(config_dir, test_cases_dir)
        keys_manifest = suite.keys

    generate_all_keys(target, keys_manifest=keys_manifest)
    print(f"Key material generated under {target / 'keys'}")
