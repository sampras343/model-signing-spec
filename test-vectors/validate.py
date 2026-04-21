#!/usr/bin/env python3
"""Validate test vectors against the OMS JSON Schemas.

Two-level validation:
  1. Bundle schema  — structural (mediaType, verificationMaterial, dsseEnvelope)
  2. Statement schema — decoded payload (predicateType, predicate body)

Directory convention:
  valid/            MUST pass both levels
  invalid/          MUST fail the bundle schema
  invalid-payload/  MUST pass the bundle schema but fail the statement schema
"""

import base64
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from oms_schemas import SCHEMA_DIR
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

VECTORS_DIR = Path(__file__).resolve().parent


def load_validators():
    schemas = {}
    for f in SCHEMA_DIR.glob("*.json"):
        schemas[f.name] = json.loads(f.read_text())

    pairs = [
        (s["$id"], Resource.from_contents(s, default_specification=DRAFT202012))
        for s in schemas.values()
    ]
    registry = Registry().with_resources(pairs)

    return (
        Draft202012Validator(schemas["bundle.schema.json"], registry=registry),
        Draft202012Validator(schemas["statement.schema.json"], registry=registry),
    )


def decode_payload(bundle: dict) -> dict:
    raw = bundle["dsseEnvelope"]["payload"]
    return json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))


def main():
    bundle_v, statement_v = load_validators()
    passed = failed = 0

    # --- valid/ : must pass both levels ---
    print("valid/")
    for p in sorted((VECTORS_DIR / "valid").glob("*.json")):
        try:
            b = json.loads(p.read_text())
            bundle_v.validate(b)
            statement_v.validate(decode_payload(b))
            print(f"  PASS  {p.name}")
            passed += 1
        except (ValidationError, json.JSONDecodeError) as e:
            msg = e.message if hasattr(e, "message") else str(e)
            print(f"  FAIL  {p.name}: {msg[:80]}")
            failed += 1

    # --- invalid/ : must fail bundle schema ---
    print("invalid/")
    for p in sorted((VECTORS_DIR / "invalid").glob("*.json")):
        try:
            b = json.loads(p.read_text())
            bundle_v.validate(b)
            print(f"  FAIL  {p.name}: expected bundle-level rejection")
            failed += 1
        except (ValidationError, json.JSONDecodeError):
            print(f"  PASS  {p.name} (correctly rejected)")
            passed += 1

    # --- invalid-payload/ : must pass bundle, fail statement ---
    payload_dir = VECTORS_DIR / "invalid-payload"
    if payload_dir.exists():
        print("invalid-payload/")
        for p in sorted(payload_dir.glob("*.json")):
            try:
                b = json.loads(p.read_text())
                bundle_v.validate(b)
            except (ValidationError, json.JSONDecodeError) as e:
                msg = e.message if hasattr(e, "message") else str(e)
                print(f"  FAIL  {p.name}: unexpectedly failed bundle schema: {msg[:60]}")
                failed += 1
                continue

            try:
                statement_v.validate(decode_payload(b))
                print(f"  FAIL  {p.name}: expected statement-level rejection")
                failed += 1
            except (ValidationError, json.JSONDecodeError):
                print(f"  PASS  {p.name} (correctly rejected at statement level)")
                passed += 1

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
