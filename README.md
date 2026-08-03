# 🛡️ API Sentinel Scanner - OWASP API Security

O **API Sentinel Scanner** é uma ferramenta em Python desenvolvida para realizar varreduras automatizadas e testes de segurança em APIs REST, com foco nas principais vulnerabilidades apontadas pelo **OWASP API Security Top 10**.

A aplicação automatiza a identificação de falhas em cabeçalhos HTTP, exposição indevida de dados sensíveis e acessos não autorizados a objetos (BOLA - Broken Object Level Authorization), gerando relatórios consolidados ao final do processo.

---

## 🚀 Funcionalidades

* **Security Headers Audit:** Varredura automática em busca de cabeçalhos essenciais ausentes (`HSTS`, `CORS` permissivo, `X-Frame-Options`, `Content-Security-Policy`).
* **Data Leakage & BOLA Detection:** Fuzzing e iteração sobre endpoints de usuários para identificar ausência de validação de permissões e vazamento de campos críticos (como `password_hash` e `cpf`).
* **Automated Report Generation:** Exportação automática dos achados da varredura para relatórios em Markdown estruturados em tabelas de severidade.
* **Ambiente de Teste Integrado (Mock API):** Acompanha uma API vulnerável criada em Flask para validação prática das detecções e simulação do laboratório.

---

## 🏗️ Arquitetura do Projeto

```text
py-api-security-scanner/
├── core/
│   ├── __init__.py
│   └── requester.py           # Engine HTTP centralizada
├── scanners/
│   ├── __init__.py
│   ├── headers_scanner.py     # Módulo de auditoria de cabeçalhos
│   └── bola_scanner.py        # Módulo de BOLA e vazamento de dados
├── reports/
│   ├── __init__.py
│   └── generator.py           # Gerador de relatórios Markdown
├── tests/
│   └── mock_api.py            # API vulnerável em Flask para testes
├── main.py                    # Script principal de orquestração
├── relatorio_seguranca.md     # Output gerado pelo scanner
└── requirements.txt