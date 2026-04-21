"""OMS JSON Schemas for bundle validation.

This package ships the normative JSON Schemas from the OpenSSF Model
Signing specification.  Conformance suites and implementations install
this package to validate bundles against the spec — the same way
sigstore-conformance depends on sigstore-protobuf-specs.

Usage::

    from oms_schemas import SCHEMA_DIR

    bundle_schema = json.loads((SCHEMA_DIR / "bundle.schema.json").read_text())
"""

from pathlib import Path

SCHEMA_DIR: Path = Path(__file__).parent
"""Path to the directory containing the OMS JSON Schema files."""
