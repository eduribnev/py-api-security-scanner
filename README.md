# API Sentinel Scanner

[![CI](https://github.com/eduribnev/py-api-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/eduribnev/py-api-security-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.14](https://img.shields.io/badge/Python-3.14-blue.svg)](https://www.python.org/)
[![OpenAPI JSON](https://img.shields.io/badge/OpenAPI-JSON-6BA539.svg)](https://www.openapis.org/)
[![OpenAPI YAML](https://img.shields.io/badge/OpenAPI-YAML-6BA539.svg)](https://www.openapis.org/)

API Sentinel Scanner is a learning-oriented AppSec tool for inspecting HTTP security headers and analyzing OpenAPI-described API routes. It can identify heuristic BOLA candidates and generate informational assessment plans; these are not proof of vulnerabilities.

## Project Status

This project is under active development and is suitable for local labs, demonstrations, and experimentation. The GitHub Actions workflow installs dependencies and compiles selected Python files with Python 3.14; it does not run a functional test suite.

| Capability | Status |
| --- | --- |
| Security header checks | Implemented |
| OpenAPI JSON and YAML parsing | Implemented |
| OpenAPI-driven security header scanning | Implemented |
| BOLA candidate discovery | Heuristic and informational |
| BOLA assessment planning | Informational; not executed |
| HTML and JSON reports | Implemented |
| Markdown report generation | Implemented; OpenAPI candidates and plans are not yet wired into the CLI-generated Markdown report |
| Identity-based BOLA confirmation | Not implemented |

## Overview

The scanner supports two OpenAPI workflows:

- **Specification analysis:** parse a local OpenAPI document, list operations, discover BOLA candidates, create assessment plans, and produce HTML and JSON reports without making requests to the API.
- **Header scanning with OpenAPI:** send requests to static GET paths discovered in a local specification and collect security-header findings.

The project also includes a deliberately vulnerable Flask API for local learning and demonstrations.

## Features

- Checks responses for missing `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, and `Content-Security-Policy` headers.
- Flags a wildcard `Access-Control-Allow-Origin` response header.
- Loads OpenAPI specifications from JSON and YAML files.
- Selects static GET operations from an OpenAPI document for header scanning; parameterized routes and non-GET operations are excluded from that header scan.
- Identifies heuristic BOLA candidates when a path parameter is named `{id}`, `{userId}`, `{accountId}`, or `{orderId}`.
- Creates assessment plans with status `NOT_TESTED`, illustrative IDs, and an approval-required indicator. Plans do not execute tests.
- Generates HTML, JSON, and Markdown reports. OpenAPI candidates and plans are currently passed to the HTML and JSON generators; the CLI does not yet pass them to Markdown generation.

## Security and Scope Notes

- Use the scanner only against systems you own or are explicitly authorized to assess. The `--url` workflows send HTTP requests to the target.
- BOLA candidates are based on path-parameter names. They are leads for review, not confirmed vulnerabilities.
- Assessment-plan IDs such as `1` and `2` are illustrative and are not checked against the target.
- This version does not perform identity-based authorization comparisons and cannot confirm BOLA.
- The legacy URL-only workflow includes hard-coded demonstration entries in its data-exposure report section. Do not interpret those entries as target-validated findings.
- Run the included vulnerable API only in a controlled local environment.

## Installation

```bash
git clone https://github.com/eduribnev/py-api-security-scanner.git
cd py-api-security-scanner
python -m venv .venv
```

Activate the virtual environment:

```bash
# Windows PowerShell
.venv\Scripts\Activate.ps1

# Linux or macOS
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Quick Start

### 1. Start the local demonstration API

In one terminal:

```bash
python tests/mock_api.py
```

The demo API listens at `http://127.0.0.1:5000`.

### 2. Analyze an OpenAPI specification without API requests

In another terminal:

```bash
python main.py --openapi test_openapi.json
```

This parses the specification and creates `security_report.html` and `security_report.json`. This mode does not create the Markdown report.

### 3. Scan static GET paths for security headers

Use a local API or another explicitly authorized target:

```bash
python main.py --url http://127.0.0.1:5000 --openapi test_openapi.json
```

The scanner sends requests to static GET paths in the specification. The legacy URL-only mode is also available:

```bash
python main.py --url http://127.0.0.1:5000
```

That mode sends requests to the target and uses legacy demonstration data in its data-exposure report section; see [Security and Scope Notes](#security-and-scope-notes).

## Supported OpenAPI Formats

The `--openapi` option accepts a local file with one of these extensions:

| Format | Example |
| --- | --- |
| JSON | `openapi.json` |
| YAML | `openapi.yaml` |
| YAML | `swagger.yaml` |
| YAML | `swagger.yml` |

Example:

```bash
python main.py --openapi test_openapi.yaml
```

The YAML parser uses PyYAML's safe loader. OpenAPI operations are extracted from the parsed document and then passed to discovery and reporting.

## Reports

| Report | Output file | Contents |
| --- | --- | --- |
| HTML | `security_report.html` | Header findings, OpenAPI BOLA candidates, and assessment plans |
| JSON | `security_report.json` | Structured header findings, candidates, and plans |
| Markdown | `relatorio_seguranca.md` | Header and legacy data-exposure sections; OpenAPI candidate and plan data is not yet wired through the CLI |

Candidates and assessment plans are informational data, separate from confirmed findings. This project does not currently confirm BOLA through testing across multiple identities.

## Architecture

```text
CLI (main.py)
├── OpenAPI workflow
│   ├── core/openapi_parser.py
│   ├── core/bola_discovery.py
│   └── core/assessment_planner.py
├── Request workflow
│   ├── core/requester.py
│   ├── scanners/headers_scanner.py
│   └── scanners/bola_scanner.py (legacy exploratory checks)
└── Reports
    ├── reports/html_generator.py
    ├── reports/json_generator.py
    └── reports/generator.py (Markdown)
```

- **OpenAPI parser:** loads JSON/YAML documents and extracts HTTP operations.
- **BOLA discovery:** classifies routes with recognized resource-identifier parameter names as candidates.
- **Assessment planner:** creates non-executed assessment plans.
- **Header scanner:** evaluates response headers received from requests.
- **Report generators:** render findings and, for HTML/JSON, OpenAPI candidates and assessment plans.

## CI

The [GitHub Actions workflow](.github/workflows/ci.yml) runs on `push` and `pull_request`. It uses Python 3.14, installs `requirements.txt`, and runs `py_compile` on the selected application modules. This checks dependency installation and Python syntax; it does not validate runtime behavior or replace functional tests.

## Roadmap

- [ ] Add functional tests for JSON/YAML parsing, candidate discovery, plans, and report output.
- [ ] Pass OpenAPI BOLA candidates and assessment plans through to the CLI-generated Markdown report.
- [ ] Replace demonstration BOLA report data with findings derived from actual, documented assessment evidence.
- [ ] Design safe, authorized, identity-based BOLA assessment workflows before claiming BOLA confirmation.
- [ ] Expand CI to run functional tests and define a tested Python-version support matrix.
- [ ] Review Docker usage and document a verified local workflow.

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes before submitting a pull request. Keep security claims evidence-based, add or update tests for behavior changes, and document changes to CLI options or report formats.

## License

This project is licensed under the [MIT License](LICENSE).

## Author

**Eduardo Ribeiro das Neves**  
Information Security Technologist | Cybersecurity Enthusiast | Automation Specialist  
[GitHub](https://github.com/eduribnev)
