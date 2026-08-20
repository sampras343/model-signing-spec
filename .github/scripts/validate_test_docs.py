#!/usr/bin/env python3
"""Validate TEST_CASES.md stays in sync with YAML config files.

Checks:
  1. Every test ID in YAML configs has a matching entry in TEST_CASES.md
  2. Every test ID in TEST_CASES.md has a matching entry in YAML configs
  3. Test IDs in TEST_CASES.md are globally unique (with category qualifier)
  4. Spec refs in TEST_CASES.md match YAML configs exactly
  5. Category grouping matches between the two files
  6. Total test count in the summary table matches actual count

Exit code 0 on success, 1 on any mismatch.

Usage:
    python .github/scripts/validate_test_docs.py
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml>=6.0", file=sys.stderr)
    sys.exit(1)


def _find_repo_root() -> Path:
    """Walk up from this script to find the repo root."""
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / "conformance" / "TEST_CASES.md").exists():
            return p
        p = p.parent
    raise FileNotFoundError("Cannot locate repo root with conformance/TEST_CASES.md")


# -- YAML extraction ----------------------------------------------------------

def _load_yaml(path: Path) -> dict:
    """Load a YAML file."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# Duplicated from conformance/test/config_loader.py — keep in sync
_SUITE_KEY_TO_CATEGORY = {
    "roundtrip": "roundtrip",
    "historical": "historical",
    "policy_positive": "policy-positive",
    "policy_negative": "policy-negative",
}


def extract_yaml_tests(config_dir: Path) -> dict[str, dict[str, dict]]:
    """Return {category: {id: test_entry}} from YAML config files."""
    index = _load_yaml(config_dir / "index.yaml")
    result: dict[str, dict[str, dict]] = {}

    test_suites = index.get("test_suites", {})
    for suite_key, rel_path in test_suites.items():
        category_name = _SUITE_KEY_TO_CATEGORY.get(suite_key, suite_key)
        suite_file = (config_dir / rel_path).resolve()
        if not suite_file.exists():
            continue
        suite_data = _load_yaml(suite_file)
        result[category_name] = {}
        for t in suite_data.get("tests", []):
            result[category_name][t["id"]] = t

    return result


# -- Markdown extraction -------------------------------------------------------

_H4_RE = re.compile(r"^#### `([^`]+)`", re.MULTILINE)
_SPEC_RE = re.compile(r"\*\*Spec:\*\*\s*(.*)")
_SECTION_RE = re.compile(r"([\xa7][\d.]+)")  # section sign

_CATEGORY_TRIGGERS = {
    "### Positive cases": "policy-positive",
    "### Historical cases": "historical",
    "### Negative cases": "policy-negative",
    "## Category 2: Roundtrip": "roundtrip",
}
_CATEGORY_TERMINATORS = {"## Bundle validation", "## Not covered", "## Config schema"}
_COUNT_RE = re.compile(r"\*\*(\d+) tests\*\*")


def extract_md_tests(
    md_path: Path,
) -> tuple[dict[str, list[str]], dict[tuple[str, str], list[str]], int | None]:
    """Parse TEST_CASES.md and return:
      - {category: [id, ...]}
      - {(category, id): [spec_refs]}
      - declared total count (from the header) or None
    """
    content = md_path.read_text()
    lines = content.split("\n")

    current_cat: str | None = None
    current_id: str | None = None
    categorized: dict[str, list[str]] = {}
    spec_refs: dict[tuple[str, str], list[str]] = {}

    for line in lines:
        # Detect category boundaries
        for trigger, cat in _CATEGORY_TRIGGERS.items():
            if trigger in line:
                current_cat = cat
                break
        for term in _CATEGORY_TERMINATORS:
            if term in line:
                current_cat = None
                break

        m = _H4_RE.match(line)
        if m and current_cat:
            current_id = m.group(1)
            categorized.setdefault(current_cat, []).append(current_id)

        sm = _SPEC_RE.search(line)
        if sm and current_id is not None and current_cat:
            refs = sorted(_SECTION_RE.findall(sm.group(1)))
            spec_refs[(current_cat, current_id)] = refs
            current_id = None

    # Extract declared total from header
    total_match = _COUNT_RE.search(content.split("---")[0])
    declared_total = int(total_match.group(1)) if total_match else None

    return categorized, spec_refs, declared_total


# -- Validation ----------------------------------------------------------------

def validate(config_dir: Path, md_path: Path) -> list[str]:
    """Return a list of error strings. Empty means all checks passed."""
    errors: list[str] = []

    yaml_tests = extract_yaml_tests(config_dir)
    md_categorized, md_spec_refs, declared_total = extract_md_tests(md_path)

    # 1 & 2: Cross-reference IDs per category
    all_cats = sorted(set(list(yaml_tests.keys()) + list(md_categorized.keys())))
    for cat in all_cats:
        yaml_ids = set(yaml_tests.get(cat, {}).keys())
        md_ids = set(md_categorized.get(cat, []))

        for tid in sorted(yaml_ids - md_ids):
            errors.append(f"IN_YAML_NOT_MD: [{cat}] {tid}")

        for tid in sorted(md_ids - yaml_ids):
            errors.append(f"IN_MD_NOT_YAML: [{cat}] {tid}")

    # 3: Uniqueness within each category (duplicates within same category)
    for cat, ids in md_categorized.items():
        dupes = {k: v for k, v in Counter(ids).items() if v > 1}
        for tid, count in dupes.items():
            errors.append(
                f"DUPLICATE_IN_CATEGORY: [{cat}] {tid} appears {count} times"
            )

    # 4: Spec refs match
    for cat_name, cat_tests in yaml_tests.items():
        for tid, entry in cat_tests.items():
            yaml_refs = sorted(entry.get("spec_refs", []))
            key = (cat_name, tid)
            if key in md_spec_refs:
                md_refs = md_spec_refs[key]
                if yaml_refs != md_refs:
                    errors.append(
                        f"SPEC_REFS_MISMATCH: [{cat_name}] {tid} "
                        f"yaml={yaml_refs} md={md_refs}"
                    )

    # 5: Category counts
    for cat in all_cats:
        yaml_count = len(yaml_tests.get(cat, {}))
        md_count = len(md_categorized.get(cat, []))
        if yaml_count != md_count:
            errors.append(
                f"COUNT_MISMATCH: [{cat}] yaml={yaml_count} md={md_count}"
            )

    # 6: Total count in header
    actual_total = sum(len(ids) for ids in md_categorized.values())
    yaml_total = sum(len(t) for t in yaml_tests.values())

    if declared_total is not None and declared_total != yaml_total:
        errors.append(
            f"HEADER_TOTAL_MISMATCH: TEST_CASES.md header says "
            f"{declared_total} but YAML configs have {yaml_total}"
        )

    if actual_total != yaml_total:
        errors.append(
            f"ACTUAL_TOTAL_MISMATCH: MD documents {actual_total} tests "
            f"but YAML configs have {yaml_total}"
        )

    return errors


# -- Main ----------------------------------------------------------------------

def main() -> int:
    root = _find_repo_root()
    config_dir = root / "conformance" / "config"
    md_path = root / "conformance" / "TEST_CASES.md"

    if not config_dir.exists():
        print(f"ERROR: {config_dir} not found", file=sys.stderr)
        return 1
    if not md_path.exists():
        print(f"ERROR: {md_path} not found", file=sys.stderr)
        return 1

    errors = validate(config_dir, md_path)

    if errors:
        print(f"FAIL: {len(errors)} sync issue(s) between TEST_CASES.md and YAML configs:\n")
        for e in errors:
            print(f"  {e}")
        return 1

    # Count for summary
    yaml_tests = extract_yaml_tests(config_dir)
    total = sum(len(t) for t in yaml_tests.values())
    print(f"OK: TEST_CASES.md and YAML configs are in sync ({total} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
