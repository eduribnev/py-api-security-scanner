import json
from pathlib import Path
from typing import Any

import yaml


_HTTP_METHODS = {
    "get",
    "put",
    "post",
    "delete",
    "options",
    "head",
    "patch",
    "trace",
}


def load_openapi_json(filepath: str | Path) -> dict[str, Any]:
    """Load an OpenAPI or Swagger document serialized as JSON."""
    with Path(filepath).open(encoding="utf-8") as spec_file:
        spec = json.load(spec_file)

    if not isinstance(spec, dict):
        raise ValueError("The OpenAPI JSON document must contain a JSON object.")

    return spec


def load_openapi_document(filepath: str | Path) -> dict[str, Any]:
    """Load an OpenAPI or Swagger document from JSON or YAML."""
    path = Path(filepath)
    extension = path.suffix.lower()

    if extension == ".json":
        return load_openapi_json(path)

    if extension not in {".yaml", ".yml"}:
        raise ValueError(
            f"Unsupported OpenAPI file extension '{path.suffix}'. "
            "Supported extensions are .json, .yaml, and .yml."
        )

    try:
        with path.open(encoding="utf-8") as spec_file:
            spec = yaml.safe_load(spec_file)
    except yaml.YAMLError as error:
        raise ValueError(f"Invalid OpenAPI YAML document: {error}") from error

    if not isinstance(spec, dict):
        raise ValueError("The OpenAPI YAML document must contain a YAML mapping.")

    return spec


def extract_operations(spec: dict[str, Any]) -> list[dict[str, str]]:
    """Extract HTTP operations from an OpenAPI or Swagger specification."""
    if not isinstance(spec, dict):
        raise ValueError("The OpenAPI specification must be a JSON object.")

    paths = spec.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("The OpenAPI specification must contain a 'paths' object.")

    operations = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            raise ValueError(f"Path item for '{path}' must be a JSON object.")

        for method in path_item:
            normalized_method = method.lower()
            if normalized_method in _HTTP_METHODS:
                operations.append(
                    {
                        "path": path,
                        "method": normalized_method.upper(),
                    }
                )

    return operations
