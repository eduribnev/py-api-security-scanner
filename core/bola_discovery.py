import re


_RESOURCE_IDENTIFIERS = {"id", "userid", "accountid", "orderid"}
_PATH_PARAMETER_PATTERN = re.compile(r"\{([^{}]+)\}")


def discover_bola_candidates(
    operations: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Identify operations whose path contains a recognized resource identifier."""
    candidates = []

    for operation in operations:
        path = operation["path"]
        parameter_names = _PATH_PARAMETER_PATTERN.findall(path)
        if not any(
            parameter_name.lower() in _RESOURCE_IDENTIFIERS
            for parameter_name in parameter_names
        ):
            continue

        candidates.append(
            {
                "method": operation["method"],
                "path_template": path,
                "confidence": "HIGH",
                "assessment_status": "candidate",
            }
        )

    return candidates
