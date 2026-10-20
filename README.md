# 🛡️ API Sentinel Scanner

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)]()
[![OWASP API Security](https://img.shields.io/badge/OWASP-API%20Security-red.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

API Sentinel Scanner is an automated security assessment tool designed to identify common vulnerabilities in REST APIs based on the OWASP API Security Top 10.

The project helps developers, security analysts, AppSec professionals, and DevSecOps teams quickly discover security weaknesses such as misconfigured HTTP security headers, sensitive data exposure, and Broken Object Level Authorization (BOLA) issues.

---

## 🚀 Key Features

### 🔍 Security Headers Audit

Automatically detects missing or insecure HTTP security headers, including:

- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Access-Control-Allow-Origin misconfigurations

---

### 🔐 BOLA Detection

Tests APIs for:

- Unauthorized object access
- ID enumeration vulnerabilities
- Broken Object Level Authorization (OWASP API1)

Example:

```http
GET /users/1
GET /users/2
GET /users/3
```

The scanner checks whether sensitive information can be accessed without proper authorization controls.

---

### 🧬 Sensitive Data Exposure Detection

Identifies potentially exposed fields such as:

- password
- password_hash
- cpf
- ssn
- token
- api_key
- secret_key

---

### 📝 Automated Security Reports

Generates structured Markdown reports containing:

- Vulnerability description
- Severity level
- Affected endpoint
- Findings summary
- Remediation recommendations

---

### 🧪 Integrated Testing Environment

Includes a deliberately vulnerable Flask API that allows users to test scanner capabilities in a controlled environment.

Perfect for:

- Security learning
- Demonstrations
- Workshops
- Portfolio projects
- AppSec labs

---

# 🏗️ Architecture

```text
api-sentinel-scanner/
│
├── core/
│   ├── __init__.py
│   └── requester.py
│
├── scanners/
│   ├── __init__.py
│   ├── headers_scanner.py
│   └── bola_scanner.py
│
├── reports/
│   ├── __init__.py
│   └── generator.py
│
├── tests/
│   └── mock_api.py
│
├── main.py
├── requirements.txt
└── relatorio_seguranca.md
```

---

# ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/eduribnev/py-api-security-scanner.git
```

Navigate to the project directory:

```bash
cd py-api-security-scanner
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# 🚦 Quick Start

### 1. Start the vulnerable API

```bash
python tests/mock_api.py
```

The API will be available locally.

---

### 2. Run the Scanner

```bash
python main.py
```

---

### 3. Review the Report

After the scan completes, a Markdown report will be generated:

```text
relatorio_seguranca.md
```

---

# 📊 Sample Findings

| Finding | Severity |
|----------|----------|
| Missing HSTS Header | High |
| Missing CSP Header | Medium |
| Data Exposure | High |
| BOLA Vulnerability | Critical |

---

# 🎯 Use Cases

### Application Security (AppSec)

Quick validation of REST APIs during development.

### DevSecOps Pipelines

Can be integrated into CI/CD workflows to identify security issues earlier.

### Security Training

Ideal for laboratory environments and OWASP-focused learning.

### Portfolio Demonstrations

Showcase practical security testing and automated vulnerability analysis.

---

# 🔥 OWASP API Security Coverage

Current focus:

| OWASP Category | Status |
|---------------|---------|
| API1: Broken Object Level Authorization | ✅ |
| API3: Broken Object Property Level Authorization | 🔄 Planned |
| API8: Security Misconfiguration | ✅ |
| Sensitive Data Exposure | ✅ |

---

# 🛣️ Roadmap

## Version 1.1

- [ ] HTML Reports
- [ ] JSON Reports
- [ ] Severity Scoring

## Version 1.5

- [ ] Docker Support
- [ ] GitHub Actions CI/CD
- [ ] CLI Arguments

## Version 2.0

- [ ] OpenAPI / Swagger Import
- [ ] JWT Security Assessment
- [ ] Rate Limiting Validation
- [ ] Authentication Testing

---

# 📈 Future Enhancements

Planned advanced capabilities include:

- OpenAPI specification parsing
- JWT vulnerabilities assessment
- API endpoint discovery
- Security scoring engine
- Interactive dashboard
- Risk classification system

---

# 🤝 Contributing

Contributions are welcome.

If you would like to improve the scanner, feel free to:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Submit a Pull Request

---

# 📜 License

This project is licensed under the MIT License.

---

# 👨‍💻 Author

**Eduardo Ribeiro das Neves**

Information Security Technologist | Cybersecurity Enthusiast | Automation Specialist

GitHub:
https://github.com/eduribnev

---

## ⭐ Support the Project

If you find this project useful, consider giving it a star.

Your support helps improve the project and encourages further development.

## 🐳 Docker Support

Build the image:

```bash
docker build -t api-sentinel .
```

Run the scanner:

```bash
docker run -it api-sentinel
```
