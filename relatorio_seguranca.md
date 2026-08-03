# 🛡️ Relatório de Varredura - API Sentinel Scanner

**Alvo Analisado:** `http://127.0.0.1:5000`  
**Data da Análise:** `2026-08-03 20:06:24`  
**Ferramenta:** API Sentinel Scanner v1.0  

---

## 1. Varredura de Cabeçalhos HTTP de Segurança

| Cabeçalho / Item | Status | Gravidade |
| :--- | :--- | :--- |
| `Strict-Transport-Security` | Ausente | **Média/Alta** |
| `X-Content-Type-Options` | Ausente | **Média/Alta** |
| `X-Frame-Options` | Ausente | **Média/Alta** |
| `Content-Security-Policy` | Ausente | **Média/Alta** |

---

## 2. Varredura BOLA e Vazamento de Dados

| Endpoint Analisado | Status HTTP | Alerta / Dados Expostos |
| :--- | :--- | :--- |
| `/api/v1/users/1` | `200` | Exposição de 'password_hash' e 'cpf' |
| `/api/v1/users/2` | `200` | Exposição de 'password_hash' e 'cpf' |

---
*Relatório gerado automaticamente pelo API Sentinel Scanner.*