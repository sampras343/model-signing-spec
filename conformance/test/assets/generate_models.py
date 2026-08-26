#!/usr/bin/env python3
"""Generate deterministic model fixture directories from normalized model data.

Reads model definitions (pre-loaded from YAML by ``config_loader``) and
materializes each model directory under ``<output_dir>/models/``.  File
content is specified declaratively using a small set of encoding types:

- ``{}``                                      -- zero-byte file
- ``{"content": "..."}``                      -- UTF-8 text
- ``{"encoding": "hex", "content": "..."}``   -- hex-decoded binary
- ``{"encoding": "fill", "byte": "XX", "size": N}``  -- N bytes of 0xXX
- ``{"encoding": "pattern", "pattern": "sequential-256", "repeat": N}``
                                               -- ``bytes(range(256)) * N``

Filenames may carry ``"unicode_normalization": "NFC"`` to request NFC
normalisation before writing.

Usage (programmatic)::

    from conformance.test.assets.generate_models import generate_all_models
    generate_all_models(output_dir, models)

Where ``models`` is the normalized dict from ``config_loader.load_suite().models``.
"""

from __future__ import annotations

import argparse
import shutil
import unicodedata
from pathlib import Path


# ---------------------------------------------------------------------------
# File materialisation
# ---------------------------------------------------------------------------


def materialize_file(path: Path, spec: dict) -> None:
    """Create a file at *path* based on its specification dict.

    Supported spec formats:

    - ``{}`` -- zero-byte file.
    - ``{"content": "..."}`` -- UTF-8 text written as-is.
    - ``{"encoding": "hex", "content": "..."}`` -- hex-decoded binary.
    - ``{"encoding": "fill", "byte": "XX", "size": N}`` -- *N* bytes of
      ``0xXX``.
    - ``{"encoding": "pattern", "pattern": "sequential-256", "repeat": N}``
      -- ``bytes(range(256))`` repeated *N* times.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    if not spec:
        # Empty spec -> zero-byte file
        path.write_bytes(b"")
        return

    # Handle size-only spec (zero-byte file with explicit size: 0)
    if set(spec.keys()) == {"size"} and spec["size"] == 0:
        path.write_bytes(b"")
        return

    encoding = spec.get("encoding")

    if encoding is None:
        # Plain UTF-8 text
        path.write_bytes(spec["content"].encode("utf-8"))
    elif encoding == "hex":
        path.write_bytes(bytes.fromhex(spec["content"]))
    elif encoding == "fill":
        size = spec["size"]
        if size > 100_000_000:
            raise ValueError(f"Fill size {size} exceeds 100MB limit for {path}")
        byte_val = int(spec["byte"], 16)
        path.write_bytes(bytes([byte_val]) * size)
    elif encoding == "pattern":
        pattern = spec["pattern"]
        if pattern == "sequential-256":
            path.write_bytes(bytes(range(256)) * spec["repeat"])
        else:
            raise ValueError(f"Unknown pattern: {pattern!r}")
    else:
        raise ValueError(f"Unknown encoding: {encoding!r}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_all_models(output_dir: Path, models: dict) -> None:
    """Generate all model directories under ``output_dir/models/``.

    The function is **idempotent**: any pre-existing ``models/`` tree is
    removed and recreated from scratch so that the output is always
    byte-identical to a fresh generation.

    Args:
        output_dir: Parent directory (typically ``conformance/test/assets``).
                    Models are created under ``output_dir/models/``.
        models: Normalized model definitions dict from config_loader.
                Format: ``{name: {"files": {path: spec_dict}}}``
    """
    models_dir = output_dir / "models"
    if models_dir.exists():
        shutil.rmtree(models_dir)
    models_dir.mkdir(parents=True)

    for name, model_def in models.items():
        model_root = models_dir / name
        model_root.mkdir(parents=True, exist_ok=True)

        for filename, file_spec in model_def["files"].items():
            # Strip unicode_normalization from the spec before dispatching
            norm = file_spec.get("unicode_normalization")
            if norm is not None:
                file_spec = {
                    k: v for k, v in file_spec.items()
                    if k != "unicode_normalization"
                }
                filename = unicodedata.normalize(norm, filename)

            target = model_root / filename
            if not target.resolve().is_relative_to(models_dir.resolve()):
                raise ValueError(f"Path traversal blocked: {filename}")
            materialize_file(target, file_spec)

    print(f"Generated {len(models)} model directories in {models_dir}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate deterministic model fixtures for conformance tests.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).parent,
        help="Parent directory; models will be created under <output-dir>/models/",
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="Path to conformance/config/ directory with YAML configs",
    )
    args = parser.parse_args()

    if args.config_dir:
        from conformance.test.config_loader import load_suite
        test_cases_dir = Path(__file__).parent.parent / "test-cases"
        suite = load_suite(args.config_dir, test_cases_dir)
        generate_all_models(args.output_dir, suite.models)
    else:
        # Fallback: locate config dir relative to this file
        here = Path(__file__).resolve().parent
        config_dir = here.parent.parent.parent / "config"
        test_cases_dir = here.parent / "test-cases"
        if config_dir.exists():
            from conformance.test.config_loader import load_suite
            suite = load_suite(config_dir, test_cases_dir)
            generate_all_models(args.output_dir, suite.models)
        else:
            print(f"Config directory not found at {config_dir}")
            raise SystemExit(1)


if __name__ == "__main__":
    main()
