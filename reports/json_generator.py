import json
from datetime import datetime


_SEVERITY_WEIGHTS = {
    "critical": 15,
    "high": 5,
    "medium": 3,
    "low": 1,
}


def _normalize_severity(severity):
    normalized = str(severity).strip().casefold()

    if normalized in {"critical", "crítica", "critica"}:
        return "critical"
    if normalized in {"high", "alta", "média/alta", "media/alta"}:
        return "high"
    if normalized in {"medium", "média", "media"}:
        return "medium"
    return "low"


def _calculate_findings_counts(header_findings, bola_findings):
    counts = {
        "critical": len(bola_findings),
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in header_findings:
        severity = _normalize_severity(finding["severity"])
        counts[severity] += 1

    return counts


def _calculate_security_score(counts):
    deductions = sum(
        counts[severity] * weight
        for severity, weight in _SEVERITY_WEIGHTS.items()
    )
    return max(0, 100 - deductions)


def _get_risk_level(score):
    if score >= 80:
        return "LOW"
    if score >= 60:
        return "MEDIUM"
    if score >= 40:
        return "HIGH"
    return "CRITICAL"


def generate_json_report(
    target_url,
    header_findings,
    bola_findings,
    output_file="security_report.json",
    bola_candidates=None,
    assessment_plans=None,
):
    summary = _calculate_findings_counts(header_findings, bola_findings)
    score = _calculate_security_score(summary)
    total_findings = sum(summary.values())
    summary["total_findings"] = total_findings

    report = {
        "target": target_url,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "score": score,
        "risk_level": _get_risk_level(score),
        "summary": summary,
        "header_findings": header_findings,
        "data_exposure_findings": bola_findings,
        "bola_candidates": bola_candidates if bola_candidates is not None else [],
        "assessment_plans": assessment_plans if assessment_plans is not None else [],
        "assessment_notice": (
            "Candidates and assessment plans are informational only and are not "
            "confirmed vulnerabilities."
        ),
    }

    with open(output_file, "w", encoding="utf-8") as report_file:
        report_file.write(json.dumps(report, indent=4, ensure_ascii=False))

    print(f"[+] JSON Report saved: {output_file}")
    return output_file
