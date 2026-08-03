# reports/generator.py
import datetime

class ReportGenerator:
    def __init__(self, target_url, header_findings, bola_findings):
        self.target_url = target_url
        self.header_findings = header_findings
        self.bola_findings = bola_findings
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_markdown(self, filename="relatorio_seguranca.md"):
        content = f"""# 🛡️ Relatório de Varredura - API Sentinel Scanner

**Alvo Analisado:** `{self.target_url}`  
**Data da Análise:** `{self.timestamp}`  
**Ferramenta:** API Sentinel Scanner v1.0  

---

## 1. Varredura de Cabeçalhos HTTP de Segurança

"""
        if self.header_findings:
            content += "| Cabeçalho / Item | Status | Gravidade |\n"
            content += "| :--- | :--- | :--- |\n"
            for item in self.header_findings:
                content += f"| `{item['header']}` | {item['status']} | **{item['severity']}** |\n"
        else:
            content += "Nenhuma vulnerabilidade de cabeçalho encontrada.\n"

        content += "\n---\n\n## 2. Varredura BOLA e Vazamento de Dados\n\n"
        if self.bola_findings:
            content += "| Endpoint Analisado | Status HTTP | Alerta / Dados Expostos |\n"
            content += "| :--- | :--- | :--- |\n"
            for item in self.bola_findings:
                content += f"| `{item['endpoint']}` | `{item['status_code']}` | {item['detail']} |\n"
        else:
            content += "Nenhuma falha de autorização ou vazamento detectado.\n"

        content += "\n---\n*Relatório gerado automaticamente pelo API Sentinel Scanner.*"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        
        return filename