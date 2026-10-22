import datetime


class ReportGenerator:
    def __init__(
        self,
        target_url,
        header_findings,
        bola_findings,
        bola_candidates=None,
        assessment_plans=None,
    ):
        self.target_url = target_url
        self.header_findings = header_findings
        self.bola_findings = bola_findings
        self.bola_candidates = bola_candidates if bola_candidates is not None else []
        self.assessment_plans = assessment_plans if assessment_plans is not None else []
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _markdown_cell(value):
        return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")

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
            content += (
                "| Endpoint Analisado | Status HTTP | Alerta / Dados Expostos |\n"
            )
            content += "| :--- | :--- | :--- |\n"

            for item in self.bola_findings:
                content += f"| `{item['endpoint']}` | `{item['status_code']}` | {item['detail']} |\n"

        else:
            content += "Nenhuma falha de autorização ou vazamento detectado.\n"

        content += "\n---\n\n## OpenAPI BOLA Candidates\n\n"
        content += (
            "Candidates and assessment plans are informational only and are not "
            "confirmed vulnerabilities.\n\n"
        )

        if self.bola_candidates:
            content += "| Method | Path Template | Confidence | Status |\n"
            content += "|----------|----------|----------|----------|\n"

            for candidate in self.bola_candidates:
                content += (
                    f"| {self._markdown_cell(candidate.get('method', 'N/A'))} "
                    f"| {self._markdown_cell(candidate.get('path_template', 'N/A'))} "
                    f"| {self._markdown_cell(candidate.get('confidence', 'N/A'))} "
                    f"| {self._markdown_cell(candidate.get('assessment_status', 'candidate'))} |\n"
                )
        else:
            content += "Nenhum candidato BOLA OpenAPI disponível.\n"

        content += "\n---\n\n## Assessment Plans\n\n"
        content += (
            "Candidates and assessment plans are informational only and are not "
            "confirmed vulnerabilities.\n\n"
        )

        if self.assessment_plans:
            content += (
                "| Method | Candidate | Status | Suggested IDs | Approval Required |\n"
            )
            content += "|----------|----------|----------|----------|----------|\n"

            for plan in self.assessment_plans:
                suggested_ids = plan.get("suggested_test_ids", [])
                if not isinstance(suggested_ids, (list, tuple)):
                    suggested_ids = [suggested_ids]
                ids_cell = ", ".join(str(test_id) for test_id in suggested_ids)
                content += (
                    f"| {self._markdown_cell(plan.get('method', 'N/A'))} "
                    f"| {self._markdown_cell(plan.get('candidate', 'N/A'))} "
                    f"| {self._markdown_cell(plan.get('assessment_status', 'N/A'))} "
                    f"| {self._markdown_cell(ids_cell)} "
                    f"| {self._markdown_cell(plan.get('approval_required', 'N/A'))} |\n"
                )
        else:
            content += "Nenhum plano de avaliação disponível.\n"

        content += (
            "\n---\n*Relatório gerado automaticamente pelo API Sentinel Scanner.*"
        )

        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)

        return filename
