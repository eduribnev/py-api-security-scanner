from datetime import datetime


def generate_html_report(
    target_url,
    header_findings,
    bola_findings,
    output_file="security_report.html",
):
    critical = len(bola_findings)
    high = 0
    medium = 0
    low = 0

    for item in header_findings:
        if item["severity"] == "Média/Alta":
            high += 1
        elif item["severity"] == "Média":
            medium += 1
        else:
            low += 1

    score = max(
    0,
    100
    - (critical * 15)
    - (high * 5)
    - (medium * 3)
    - (low * 1)
)

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">

<title>API Sentinel Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    background: #f4f4f4;
    padding: 20px;
}}

.container {{
    background: white;
    padding: 30px;
    border-radius: 12px;
    max-width: 1200px;
    margin: auto;
}}

h1 {{
    color: #1e293b;
}}

.summary {{
    display: flex;
    gap: 20px;
    margin-bottom: 30px;
}}

.card {{
    padding: 15px;
    border-radius: 8px;
    color: white;
    min-width: 120px;
    text-align: center;
}}

.critical {{
    background: #dc2626;
}}

.high {{
    background: #f97316;
}}

.medium {{
    background: #eab308;
    color: black;
}}

.low {{
    background: #22c55e;
}}

.score {{
    font-size: 36px;
    font-weight: bold;
    color: #0f172a;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th, td {{
    border: 1px solid #ddd;
    padding: 12px;
}}

th {{
    background: #1e293b;
    color: white;
}}

</style>

</head>
<body>

<div class="container">

<h1>🛡 API Sentinel Scanner</h1>

<p>
Generated on: {datetime.now()}
</p>

<h2>Security Score</h2>

<div class="score">{score}/100</div>

<div class="card">

<h2>Executive Summary</h2>

<p>
The API Sentinel Scanner identified security weaknesses that should
be addressed to improve the security posture of the assessed API.
The findings include configuration issues, missing security headers
and potential authorization weaknesses.
</p>

</div>

<div class="summary">

<div class="card critical">
<h3>{critical}</h3>
Critical
</div>

<div class="card high">
<h3>{high}</h3>
High
</div>

<div class="card medium">
<h3>{medium}</h3>
Medium
</div>

<div class="card low">
<h3>{low}</h3>
Low
</div>

</div>

<h2>Findings</h2>

<table>
<tr>
<th>Severity</th>
<th>Finding</th>
<th>Description</th>
</tr>
"""

    for item in header_findings:
        html += f"""
<tr>
<td>{item['severity']}</td>
<td>{item['header']}</td>
<td>{item['status']}</td>
</tr>
"""

    html += """
    </table>

    <h2>Authorization & Data Exposure Findings</h2>

    <table>
    <tr>
        <th>Endpoint</th>
        <th>Status</th>
        <th>Finding</th>
    </tr>
    """

    for item in bola_findings:

        html += f"""
        <tr>
            <td>{item['endpoint']}</td>
            <td>Critical</td>
            <td>{item['detail']}</td>
        </tr>
        """

    html += """
    </table>

    </div>
    </body>
    </html>
    """

    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html)

    print(f"[+] HTML Report saved: {output_file}")
    return output_file
