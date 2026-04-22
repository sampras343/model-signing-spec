#!/usr/bin/env python3
"""Validate test vectors against the OMS JSON Schemas.

Uses the ``oms_schemas`` package API for all validation.

Directory convention:
  valid/            MUST pass bundle + statement schema
  invalid/          MUST fail the bundle schema
  invalid-payload/  MUST pass the bundle schema but fail the statement schema
"""

import json
import sys
from pathlib import Path

from jsonschema import ValidationError
from oms_schemas import _init_validators, decode_payload

VECTORS_DIR = Path(__file__).resolve().parent


def main():
    bundle_v, statement_v = _init_validators()
    passed = failed = 0

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
