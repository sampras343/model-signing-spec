"""Load modular YAML configuration files for the conformance test suite.

This module reads the ``conformance/config/index.yaml`` master index and
resolves all referenced YAML files (models, keys, fixtures, test suites)
into a single ``ConformanceSuite`` object consumed by conftest.py and the
asset-generation scripts.

The YAML files use a human-friendly array-of-objects format that this loader
normalizes into the dict-keyed format expected by downstream consumers
(``generate_models.py``, ``generate_keys.py``, etc.).

Public API::

    suite = load_suite(config_dir, test_cases_dir)

    suite.models        # {name: {files: {path: spec}}}
    suite.keys          # {name: {description, curve, files: [...]}}
    suite.fixtures      # OCI config dict
    suite.mutations     # {name: {operation, path, value, ...}}
    suite.handcrafts    # {name: {content_type, content, ...}}
    suite.tests("roundtrip")  # list[dict]

Requires ``pyyaml>=6.0``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:
    raise ImportError(
        "PyYAML is required for loading YAML configuration files. "
        "Install it with:  pip install pyyaml>=6.0"
    ) from exc


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def _normalize_models(raw: list[dict]) -> dict[str, dict]:
    """Convert the YAML models array into a dict keyed by name.

    Input (YAML array format)::

        [{"name": "simple", "files": [{"path": "f1", "content": "..."}]}]

    Output (dict format expected by generate_models.py)::

        {"simple": {"files": {"f1": {"content": "..."}}}}

    Field renames applied per file spec:
      - ``fill_byte`` -> ``byte``
      - ``hex_content`` -> ``content`` (when ``encoding == "hex"``)
    """
    result: dict[str, dict] = {}
    for model in raw:
        name = model["name"]
        files_dict: dict[str, dict] = {}
        for file_entry in model.get("files", []):
            path = file_entry["path"]
            spec: dict[str, Any] = {}

            # Copy all fields except 'path' and 'type' (type is metadata for config_loader)
            for k, v in file_entry.items():
                if k in ("path", "type"):
                    continue
                spec[k] = v

            # Normalize fill_byte -> byte
            if "fill_byte" in spec:
                spec["byte"] = spec.pop("fill_byte")

            # Normalize hex_content -> content (for encoding=hex)
            if spec.get("encoding") == "hex" and "hex_content" in spec:
                spec["content"] = spec.pop("hex_content")

            files_dict[path] = spec

        file_types = {fe["path"]: fe.get("type", "signed") for fe in model.get("files", [])}
        signed = [p for p in files_dict if file_types.get(p, "signed") == "signed"]
        ignored = [p for p in files_dict if file_types.get(p) == "ignored"]
        result[name] = {"files": files_dict, "signed_files": signed, "ignored_files": ignored}
    return result


def _normalize_keys(raw: list[dict]) -> dict[str, dict]:
    """Convert the YAML keys array into a dict keyed by name.

    Handles two formats:

    Legacy (``outputs`` as string list)::

        [{"name": "certificate", "outputs": ["ca-cert.pem", ...], ...}]

    Enhanced (``files`` as object list with ``roles``)::

        [{"name": "certificate",
          "files": [{"name": "ca-cert.pem", "description": "..."}],
          "roles": [{"role": "sign_private_key", "file": "signing-key.pem"}]}]

    Output (dict format expected by generate_keys.py validation)::

        {"certificate": {"description": "...", "curve": "...", "files": [...]}}

    In both cases the output ``files`` value is a flat list of filenames.
    The ``roles``, ``chain``, ``purpose``, ``when_to_use``, and ``depends_on``
    fields are dropped here -- they are consumed by
    :func:`_normalize_key_roles`.
    """
    # Fields consumed only by role resolution, not by generate_keys.py
    _ROLE_ONLY_FIELDS = {"roles", "chain", "purpose", "when_to_use", "depends_on"}

    result: dict[str, dict] = {}
    for key_entry in raw:
        name = key_entry["name"]
        entry: dict[str, Any] = {}
        for k, v in key_entry.items():
            if k == "name" or k in _ROLE_ONLY_FIELDS:
                continue
            if k == "outputs":
                # Legacy format: plain list of filenames
                entry["files"] = v
            elif k == "files":
                # Enhanced format: array of objects with name/description
                if v and isinstance(v[0], dict):
                    entry["files"] = [f["name"] for f in v]
                else:
                    entry["files"] = v
            else:
                entry[k] = v
        result[name] = entry
    return result


def _normalize_transforms(raw: list[dict]) -> dict[str, dict]:
    """Convert a YAML array of named transforms into a dict keyed by name.

    Works for both mutations and handcrafts arrays in bundle-transforms.yaml.

    Input::

        [{"name": "wrong-mediatype", "operation": "set", "path": "mediaType", ...}]

    Output::

        {"wrong-mediatype": {"operation": "set", "path": "mediaType", ...}}
    """
    return {
        entry["name"]: {k: v for k, v in entry.items() if k != "name"}
        for entry in raw
    }


def _normalize_key_roles(raw: list[dict]) -> dict[str, dict[str, Any]]:
    """Build a role lookup from keys.yaml ``roles`` arrays.

    Each key group may define a ``roles`` list that maps logical role names
    (``sign_private_key``, ``verify_cert_chain``, etc.) to file paths
    within the ``keys/<group>/`` directory.

    Returns::

        {
            "certificate": {
                "sign_private_key": "keys/certificate/signing-key.pem",
                "verify_cert_chain": ["keys/certificate/ca-cert.pem"],
                ...
            },
            ...
        }

    A role entry with ``from_group`` resolves its file(s) from another
    group's directory (e.g. expired group referencing certificate's
    intermediate CA).
    """
    groups: dict[str, dict[str, Any]] = {}
    for key_entry in raw:
        name = key_entry["name"]
        roles_data: dict[str, Any] = {}
        for role_entry in key_entry.get("roles", []):
            role_name = role_entry["role"]
            from_group = role_entry.get("from_group")
            dir_name = from_group if from_group else name

            if "file" in role_entry:
                roles_data[role_name] = f"keys/{dir_name}/{role_entry['file']}"
            elif "files" in role_entry:
                roles_data[role_name] = [
                    f"keys/{dir_name}/{f}" for f in role_entry["files"]
                ]
        groups[name] = roles_data
    return groups


# ---------------------------------------------------------------------------
# key_group resolution
# ---------------------------------------------------------------------------

# Role-to-field mapping per method.  Only roles listed here are resolved
# for the given method; all others are silently ignored.  This prevents
# certificate-specific fields (signing_cert, cert_chain) from leaking
# into key-method commands that don't expect them.
_METHOD_SIGN_ROLES: dict[str, dict[str, str]] = {
    "key": {
        "sign_private_key": "private_key",
    },
    "certificate": {
        "sign_private_key": "private_key",
        "sign_cert": "signing_cert",
        "sign_cert_chain": "cert_chain",
    },
}

_METHOD_VERIFY_ROLES: dict[str, dict[str, str]] = {
    "key": {
        "verify_public_key": "public_key",
    },
    "certificate": {
        "verify_cert_chain": "cert_chain",
    },
}

# Fallback when method is unknown or None: resolve all roles.
_ALL_SIGN_ROLES: dict[str, str] = {
    "sign_private_key": "private_key",
    "sign_cert": "signing_cert",
    "sign_cert_chain": "cert_chain",
}

_ALL_VERIFY_ROLES: dict[str, str] = {
    "verify_public_key": "public_key",
    "verify_cert_chain": "cert_chain",
}


def _resolve_key_group_in_entry(
    key_roles: dict[str, dict[str, Any]],
    entry: dict,
    method: str | None = None,
) -> dict:
    """Resolve ``key_group`` / ``verify_key_group`` into sign/verify paths.

    If *entry* contains a ``key_group`` field, the corresponding roles are
    used to populate ``sign`` and ``verify`` sub-dicts with resolved file
    paths.  Which roles are populated depends on *method*:

    - ``"key"``: only ``sign.private_key`` and ``verify.public_key``
    - ``"certificate"``: ``sign.private_key``, ``sign.signing_cert``,
      ``sign.cert_chain``, and ``verify.cert_chain``
    - other / ``None``: all sign and verify roles

    If ``verify_key_group`` is also present, it overrides the verify block
    that would otherwise come from ``key_group``.

    Existing values in ``sign`` / ``verify`` are preserved (explicit paths
    take precedence over role-derived paths).

    Returns a **new** dict; the original *entry* is not mutated.
    """
    key_group = entry.get("key_group")
    verify_key_group = entry.get("verify_key_group")

    if not key_group and not verify_key_group:
        return entry

    # Determine effective method (entry value or caller-supplied)
    effective_method = entry.get("method", method)

    sign_role_map = _METHOD_SIGN_ROLES.get(effective_method, _ALL_SIGN_ROLES)
    verify_role_map = _METHOD_VERIFY_ROLES.get(effective_method, _ALL_VERIFY_ROLES)

    result = dict(entry)

    if key_group:
        if key_group not in key_roles:
            raise KeyError(
                f"Unknown key_group: {key_group!r}. "
                f"Available: {sorted(key_roles.keys())}"
            )
        roles = key_roles[key_group]

        # Populate sign block from applicable roles
        sign = dict(result.get("sign", {}))
        for role_name, field_name in sign_role_map.items():
            if role_name in roles and field_name not in sign:
                sign[field_name] = roles[role_name]
        if sign:
            result["sign"] = sign

        # Populate verify block from applicable roles
        # (unless verify_key_group will override)
        if not verify_key_group:
            verify = dict(result.get("verify", {}))
            for role_name, field_name in verify_role_map.items():
                if role_name in roles and field_name not in verify:
                    verify[field_name] = roles[role_name]
            if verify:
                result["verify"] = verify

    if verify_key_group:
        if verify_key_group not in key_roles:
            raise KeyError(
                f"Unknown verify_key_group: {verify_key_group!r}. "
                f"Available: {sorted(key_roles.keys())}"
            )
        vroles = key_roles[verify_key_group]
        verify = dict(result.get("verify", {}))
        # verify_key_group overrides: use ALL verify roles regardless
        # of method since the caller explicitly chose a different group.
        for role_name, field_name in _ALL_VERIFY_ROLES.items():
            if role_name in vroles:
                verify[field_name] = vroles[role_name]
        if verify:
            result["verify"] = verify

    return result


def _load_yaml(path: Path) -> Any:
    """Load a YAML file and return its parsed content."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Category name mapping
# ---------------------------------------------------------------------------

# Maps index.yaml test_suites keys to the category names used in conftest.py
# and downstream code.
_SUITE_KEY_TO_CATEGORY = {
    "roundtrip": "roundtrip",
    "historical": "historical",
    "policy_positive": "policy-positive",
    "policy_negative": "policy-negative",
}

# Maps category names to the verify/ subdirectory used for test_dir derivation.
# Roundtrip tests don't have test_dirs (no pre-committed bundles).
_CATEGORY_TO_VERIFY_DIR = {
    "policy-positive": "positive",
    "policy-negative": "negative",
    "historical": "historical",
}


# ---------------------------------------------------------------------------
# ConformanceSuite dataclass
# ---------------------------------------------------------------------------

@dataclass
class ConformanceSuite:
    """Holds the fully-loaded and normalized conformance configuration.

    Properties:
        spec_version: The spec version string from index.yaml.
        models: Normalized model definitions keyed by name.
        keys: Normalized key definitions keyed by name.
        fixtures: OCI fixture configuration dict.
        mutations: Config-driven bundle mutation transforms keyed by name.
        handcrafts: Config-driven bundle handcraft transforms keyed by name.
    """

    spec_version: str
    models: dict[str, dict] = field(default_factory=dict)
    keys: dict[str, dict] = field(default_factory=dict)
    fixtures: dict = field(default_factory=dict)
    mutations: dict[str, dict] = field(default_factory=dict)
    handcrafts: dict[str, dict] = field(default_factory=dict)
    _categories: dict[str, dict] = field(default_factory=dict)
    _key_roles: dict[str, dict] = field(default_factory=dict)

    def tests(self, category: str) -> list[dict]:
        """Return the test entries for a category."""
        cat = self._categories.get(category)
        if cat is None:
            raise KeyError(
                f"Unknown category {category!r}. "
                f"Available: {sorted(self._categories.keys())}"
            )
        return cat.get("tests", [])

    def defaults(self, category: str) -> dict:
        """Return the category-level defaults dict."""
        cat = self._categories.get(category)
        if cat is None:
            return {}
        return cat.get("defaults", {})

    def method_defaults(self, category: str, method: str) -> dict:
        """Return the method-level defaults for a category."""
        cat = self._categories.get(category)
        if cat is None:
            return {}
        return cat.get("method_defaults", {}).get(method, {})

    def resolve_key_paths(self, key_group: str) -> dict[str, Any]:
        """Resolve a key group's roles into actual file paths.

        Returns a dict mapping role names to resolved paths, e.g.::

            {"sign_private_key": "keys/certificate/signing-key.pem",
             "verify_cert_chain": ["keys/certificate/ca-cert.pem"]}

        Raises ``KeyError`` if *key_group* is not defined in keys.yaml.
        """
        if key_group not in self._key_roles:
            raise KeyError(
                f"Unknown key_group: {key_group!r}. "
                f"Available: {sorted(self._key_roles.keys())}"
            )
        return dict(self._key_roles[key_group])

    @property
    def key_roles(self) -> dict[str, dict]:
        """Access the raw key roles lookup."""
        return self._key_roles

    @property
    def categories(self) -> dict[str, dict]:
        """Access the raw categories dict (for backward compatibility)."""
        return self._categories


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_suite(
    config_dir: Path,
    test_cases_dir: Path,
) -> ConformanceSuite:
    """Load all YAML configs and return a unified ConformanceSuite.

    Args:
        config_dir: Path to ``conformance/config/`` containing ``index.yaml``.
        test_cases_dir: Path to ``conformance/test/test-cases/`` containing
            the test suite YAML files referenced by index.yaml.

    Returns:
        A fully-loaded ``ConformanceSuite`` with normalized data.
    """
    index = _load_yaml(config_dir / "index.yaml")

    spec_version = index.get("spec_version", "1.0")

    # Load config files (relative to config_dir)
    config_refs = index.get("config", {})

    # Models
    models_raw = _load_yaml(config_dir / config_refs["models"])
    models = _normalize_models(models_raw.get("models", []))

    # Keys
    keys_raw = _load_yaml(config_dir / config_refs["keys"])
    keys_list = keys_raw.get("keys", [])
    keys = _normalize_keys(keys_list)

    # Build key role lookup for key_group resolution
    key_roles = _normalize_key_roles(keys_list)

    # Fixtures
    fixtures_raw = _load_yaml(config_dir / config_refs["fixtures"])
    fixtures = fixtures_raw if fixtures_raw else {}

    # Bundle transforms (mutations and handcrafts)
    if "bundle_transforms" in config_refs:
        transforms_raw = _load_yaml(config_dir / config_refs["bundle_transforms"])
        mutations = _normalize_transforms(transforms_raw.get("mutations", []))
        handcrafts = _normalize_transforms(transforms_raw.get("handcrafts", []))
    else:
        mutations = {}
        handcrafts = {}

    # Load test suite files (paths in index.yaml are relative to config_dir)
    categories: dict[str, dict] = {}
    test_suites = index.get("test_suites", {})
    for suite_key, rel_path in test_suites.items():
        category_name = _SUITE_KEY_TO_CATEGORY.get(suite_key, suite_key)
        suite_file = (config_dir / rel_path).resolve()
        if not suite_file.exists():
            # Try relative to test_cases_dir as fallback
            suite_file = test_cases_dir / Path(rel_path).name
        if suite_file.exists():
            suite_data = _load_yaml(suite_file)
            cat_entry: dict[str, Any] = {}
            if "description" in suite_data:
                cat_entry["description"] = suite_data["description"]
            if "defaults" in suite_data:
                cat_entry["defaults"] = suite_data["defaults"]
            if "method_defaults" in suite_data:
                cat_entry["method_defaults"] = suite_data["method_defaults"]
            if "tests" in suite_data:
                # Derive test_dir from category + id if not explicitly set
                verify_dir = _CATEGORY_TO_VERIFY_DIR.get(category_name)
                for entry in suite_data["tests"]:
                    if "test_dir" not in entry and verify_dir:
                        entry["test_dir"] = f"{verify_dir}/{entry['id']}"
                cat_entry["tests"] = suite_data["tests"]
            categories[category_name] = cat_entry

    # Resolve key_group references in method_defaults and test entries
    # so that downstream consumers see fully-resolved sign/verify paths.
    if key_roles:
        for cat_data in categories.values():
            if "method_defaults" in cat_data:
                cat_data["method_defaults"] = {
                    method_name: _resolve_key_group_in_entry(
                        key_roles, mdef, method=method_name,
                    )
                    for method_name, mdef in cat_data["method_defaults"].items()
                }
            if "tests" in cat_data:
                cat_data["tests"] = [
                    _resolve_key_group_in_entry(key_roles, entry)
                    for entry in cat_data["tests"]
                ]

    # Derive expected_signed_files and ignore_paths from model file types.
    # Only applied when the test doesn't already set them explicitly.
    for cat_data in categories.values():
        for entry in cat_data.get("tests", []):
            model_name = entry.get("model")
            if model_name and model_name in models:
                model_def = models[model_name]
                if "expected_signed_files" not in entry and model_def.get("signed_files"):
                    entry["expected_signed_files"] = list(model_def["signed_files"])
                if model_def.get("ignored_files"):
                    verify = entry.get("verify")
                    if verify is None:
                        verify = {}
                        entry["verify"] = verify
                    if "ignore_paths" not in verify:
                        verify["ignore_paths"] = list(model_def["ignored_files"])

    # Merge bundle_source from category defaults into test entries that lack it.
    # This allows categories like policy-positive to set a default bundle_source
    # (e.g., type: sign) without repeating it on every test entry.
    for cat_data in categories.values():
        defaults = cat_data.get("defaults", {})
        default_bundle_source = defaults.get("bundle_source")
        if default_bundle_source:
            for entry in cat_data.get("tests", []):
                if "bundle_source" not in entry:
                    entry["bundle_source"] = dict(default_bundle_source)

    return ConformanceSuite(
        spec_version=spec_version,
        models=models,
        keys=keys,
        fixtures=fixtures,
        mutations=mutations,
        handcrafts=handcrafts,
        _categories=categories,
        _key_roles=key_roles,
    )
