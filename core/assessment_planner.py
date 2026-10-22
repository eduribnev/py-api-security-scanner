def generate_assessment_plans(
    bola_candidates: list[dict[str, str]],
) -> list[dict[str, object]]:
    """Create informational assessment plans without performing requests."""
    return [
        {
            "candidate": candidate["path_template"],
            "method": candidate["method"],
            "confidence": candidate["confidence"],
            "assessment_status": "NOT_TESTED",
            "suggested_test_ids": ["1", "2"],
            "approval_required": True,
        }
        for candidate in bola_candidates
    ]
