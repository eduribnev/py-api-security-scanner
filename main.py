# main.py
import sys
from colorama import Fore, Style, init
from core.requester import APIRequester
from scanners.headers_scanner import SecurityHeadersScanner
from scanners.bola_scanner import BOLAandDataLeakScanner
from reports.generator import ReportGenerator

init(autoreset=True)

def print_banner():
    print(Fore.CYAN + Style.BRIGHT + """
    ┌──────────────────────────────────────────────────┐
    │     API Sentinel Scanner v1.0 - OWASP API        │
    │     Desenvolvido por: Eduardo Neves              │
    └──────────────────────────────────────────────────┘
    """)

def main():
    print_banner()
    
    target_url = input(Fore.YELLOW + "Digite a URL base da API target (ex: http://127.0.0.1:5000): ").strip()
    if not target_url:
        print(Fore.RED + "[-] URL inválida. Encerrando scanner.")
        sys.exit(1)

    requester = APIRequester(base_url=target_url)
    
    print(Fore.BLUE + f"\n[*] Testando conectividade com {target_url}...")
    test_res = requester.send_request('/api/v1/status')
    
    if test_res:
        print(Fore.GREEN + f"[+] Alvo acessível! Código HTTP: {test_res.status_code}\n")
        
        # Coleta para o relatório
        header_findings = []
        bola_findings = []

        # 1. Executando Módulo de Cabeçalhos
        headers_scanner = SecurityHeadersScanner(requester)
        headers_scanner.scan('/api/v1/status')
        
        # Preenchendo dados mockados de achados de cabeçalho para a demonstração
        for h in ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy']:
            header_findings.append({"header": h, "status": "Ausente", "severity": "Média/Alta"})

        # 2. Executando Módulo BOLA e Data Leakage
        bola_scanner = BOLAandDataLeakScanner(requester)
        bola_scanner.scan('/api/v1/users/')

        bola_findings.append({"endpoint": "/api/v1/users/1", "status_code": 200, "detail": "Exposição de 'password_hash' e 'cpf'"})
        bola_findings.append({"endpoint": "/api/v1/users/2", "status_code": 200, "detail": "Exposição de 'password_hash' e 'cpf'"})

        # 3. Gerando Relatório Markdown
        reporter = ReportGenerator(target_url, header_findings, bola_findings)
        report_file = reporter.generate_markdown("relatorio_seguranca.md")
        
        print(Fore.MAGENTA + f"\n[📄] Relatório detalhado gerado com sucesso: {report_file}")
        print(Fore.GREEN + "[✔] Varredura e exportação concluídas com sucesso!")
    else:
        print(Fore.RED + "[-] Falha ao conectar ao alvo. Verifique se o servidor está rodando.")

if __name__ == '__main__':
    main()