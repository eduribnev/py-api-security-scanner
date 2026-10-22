from datetime import datetime
from html import escape


_SEVERITY_WEIGHTS = {
    "critical": 15,
    "high": 5,
    "medium": 3,
    "low": 1,
}

_STYLES = """
body {
    margin: 0;
    padding: 24px;
    background: #f4f4f4;
    color: #1e293b;
    font-family: Arial, sans-serif;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 30px;
    background: #fff;
    border-radius: 12px;
}

h1, h2 {
    color: #1e293b;
}

.metadata {
    color: #475569;
    overflow-wrap: anywhere;
}

.score {
    color: #0f172a;
    font-size: 36px;
    font-weight: bold;
}

.risk-level {
    font-weight: bold;
}

.risk-low {
    color: #16a34a;
}

.risk-medium {
    color: #a16207;
}

.risk-high {
    color: #ea580c;
}

.risk-critical {
    color: #dc2626;
}

.summary-box {
    margin: 20px 0 25px;
    padding: 15px;
    background: #f8fafc;
    border-left: 5px solid #1e293b;
    border-radius: 8px;
}

.summary-box h2 {
    margin-top: 0;
}

.summary-box p {
    line-height: 1.6;
}

.summary {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    margin-bottom: 30px;
}

.card {
    min-width: 120px;
    padding: 15px;
    border-radius: 8px;
    color: #fff;
    text-align: center;
}

.card h3 {
    margin: 0 0 8px;
}

.critical {
    background: #dc2626;
}

.high {
    background: #f97316;
}

.medium {
    background: #eab308;
    color: #111827;
}

.low {
    background: #16a34a;
}

.table-wrapper {
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    padding: 12px;
    border: 1px solid #ddd;
    text-align: left;
    vertical-align: top;
}

th {
    background: #1e293b;
    color: #fff;
}

@media (max-width: 600px) {
    body {
        padding: 12px;
    }

    .container {
        padding: 18px;
    }
}
"""


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


def _render_header_rows(header_findings):
    if not header_findings:
        return '<tr><td colspan="3">No header findings.</td></tr>'

    rows = []
    for finding in header_findings:
        rows.append(
            "<tr>"
            f"<td>{escape(str(finding['severity']))}</td>"
            f"<td>{escape(str(finding['header']))}</td>"
            f"<td>{escape(str(finding['status']))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _render_data_exposure_rows(bola_findings):
    if not bola_findings:
        return (
            '<tr><td colspan="4">'
            "No authorization or data exposure findings."
            "</td></tr>"
        )

    rows = []
    for finding in bola_findings:
        status_code = finding.get("status_code", "N/A")
        rows.append(
            "<tr>"
            f"<td>{escape(str(finding['endpoint']))}</td>"
            f"<td>{escape(str(status_code))}</td>"
            "<td>Critical</td>"
            f"<td>{escape(str(finding['detail']))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _render_bola_candidate_rows(bola_candidates):
    if not bola_candidates:
        return '<tr><td colspan="3">No OpenAPI BOLA candidates discovered.</td></tr>'

    rows = []
    for candidate in bola_candidates:
        rows.append(
            "<tr>"
            f"<td>{escape(str(candidate.get('method', 'N/A')))}</td>"
            f"<td>{escape(str(candidate.get('path_template', 'N/A')))}</td>"
            f"<td>{escape(str(candidate.get('confidence', 'N/A')))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _render_assessment_plan_rows(assessment_plans):
    if not assessment_plans:
        return '<tr><td colspan="5">No assessment plans generated.</td></tr>'

    rows = []
    for plan in assessment_plans:
        suggested_test_ids = plan.get("suggested_test_ids", [])
        if not isinstance(suggested_test_ids, list):
            suggested_test_ids = [suggested_test_ids]

        rows.append(
            "<tr>"
            f"<td>{escape(str(plan.get('method', 'N/A')))}</td>"
            f"<td>{escape(str(plan.get('candidate', 'N/A')))}</td>"
            f"<td>{escape(str(plan.get('assessment_status', 'N/A')))}</td>"
            f"<td>{escape(', '.join(str(value) for value in suggested_test_ids))}</td>"
            f"<td>{escape(str(plan.get('approval_required', 'N/A')))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def generate_html_report(
    target_url,
    header_findings,
    bola_findings,
    output_file="security_report.html",
    bola_candidates=None,
    assessment_plans=None,
):
    bola_candidates = bola_candidates if bola_candidates is not None else []
    assessment_plans = assessment_plans if assessment_plans is not None else []
    counts = _calculate_findings_counts(header_findings, bola_findings)
    score = _calculate_security_score(counts)
    risk_level = _get_risk_level(score)
    risk_class = f"risk-{risk_level.lower()}"
    total_findings = sum(counts.values())
    generated_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>API Sentinel Security Report</title>
    <style>{_STYLES}</style>
</head>
<body>
    <main class="container">
        <h1>API Sentinel Scanner</h1>
        <p class="metadata"><strong>Target:</strong> {escape(str(target_url))}</p>
        <p class="metadata"><strong>Generated on:</strong> {escape(generated_at)}</p>
        <p class="metadata">
            Candidates and assessment plans are informational only and are not confirmed vulnerabilities.
        </p>

        <section aria-labelledby="score-heading">
            <h2 id="score-heading">Security Score</h2>
            <div class="score">{score}/100</div>
            <h3>
                Risk Level:
                <span class="risk-level {risk_class}">{risk_level}</span>
            </h3>
        </section>

        <section class="summary-box" aria-labelledby="executive-summary-heading">
            <h2 id="executive-summary-heading">Executive Summary</h2>
            <p>
                The assessment identified {total_findings} security findings:
                {counts['critical']} critical, {counts['high']} high,
                {counts['medium']} medium, and {counts['low']} low.
                The overall security posture is classified as {risk_level} risk.
            </p>
        </section>

        <section class="summary" aria-label="Findings by severity">
            <div class="card critical"><h3>{counts['critical']}</h3>Critical</div>
            <div class="card high"><h3>{counts['high']}</h3>High</div>
            <div class="card medium"><h3>{counts['medium']}</h3>Medium</div>
            <div class="card low"><h3>{counts['low']}</h3>Low</div>
        </section>

        <section aria-labelledby="header-findings-heading">
            <h2 id="header-findings-heading">Security Header Findings</h2>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th scope="col">Severity</th>
                            <th scope="col">Finding</th>
                            <th scope="col">Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {_render_header_rows(header_findings)}
                    </tbody>
                </table>
            </div>
        </section>

        <section aria-labelledby="data-exposure-heading">
            <h2 id="data-exposure-heading">
                Authorization &amp; Data Exposure Findings
            </h2>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th scope="col">Endpoint</th>
                            <th scope="col">HTTP Status</th>
                            <th scope="col">Severity</th>
                            <th scope="col">Finding</th>
                        </tr>
                    </thead>
                    <tbody>
                        {_render_data_exposure_rows(bola_findings)}
                    </tbody>
                </table>
            </div>
        </section>

        <section aria-labelledby="bola-candidates-heading">
            <h2 id="bola-candidates-heading">OpenAPI BOLA Candidates</h2>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th scope="col">Method</th>
                            <th scope="col">Path Template</th>
                            <th scope="col">Confidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {_render_bola_candidate_rows(bola_candidates)}
                    </tbody>
                </table>
            </div>
        </section>

        <section aria-labelledby="assessment-plans-heading">
            <h2 id="assessment-plans-heading">Assessment Plans</h2>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th scope="col">Method</th>
                            <th scope="col">Candidate</th>
                            <th scope="col">Status</th>
                            <th scope="col">Suggested Test IDs</th>
                            <th scope="col">Approval Required</th>
                        </tr>
                    </thead>
                    <tbody>
                        {_render_assessment_plan_rows(assessment_plans)}
                    </tbody>
                </table>
            </div>
        </section>
    </main>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as report_file:
        report_file.write(html)

    print(f"[+] HTML Report saved: {output_file}")
    return output_file
