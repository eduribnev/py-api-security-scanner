# main.py
import sys
import argparse
from colorama import Fore, Style, init
from core.requester import APIRequester
from scanners.headers_scanner import SecurityHeadersScanner
from scanners.bola_scanner import BOLAandDataLeakScanner
from reports.generator import ReportGenerator
from reports.html_generator import generate_html_report
from reports.json_generator import generate_json_report
from core.openapi_parser import extract_operations, load_openapi_json
from core.bola_discovery import discover_bola_candidates

init(autoreset=True)


def print_banner():
    args = get_arguments()
    print(Fore.CYAN + Style.BRIGHT + """
    ┌──────────────────────────────────────────────────┐
    │     API Sentinel Scanner v1.0 - OWASP API        │
    │     Desenvolvido por: Eduardo Neves              │
    └──────────────────────────────────────────────────┘
    """)


def get_arguments():

    parser = argparse.ArgumentParser(description="API Sentinel Scanner")

    parser.add_argument("--url", help="Target API base URL")
    parser.add_argument(
        "--openapi",
        help="Path to an OpenAPI or Swagger specification in JSON format",
    )

    return parser.parse_args()


def main():
    print_banner()

    args = get_arguments()
    spec = None
    operations = []
    bola_candidates = []

    if args.openapi:
        try:
            spec = load_openapi_json(args.openapi)
            operations = extract_operations(spec)
            bola_candidates = discover_bola_candidates(operations)
        except (OSError, ValueError) as error:
            print(Fore.RED + f"[-] Não foi possível carregar a especificação: {error}")
            sys.exit(2)

        if not args.url:
            if not operations:
                print(Fore.YELLOW + "[!] Nenhuma operação encontrada na especificação.")
            else:
                print(Fore.CYAN + "[*] Operações encontradas na especificação OpenAPI:")
                for operation in operations:
                    print(f"{operation['method']} {operation['path']}")

            print(Fore.CYAN + f"[+] BOLA candidates discovered: {len(bola_candidates)}")
            for candidate in bola_candidates:
                print(
                    f"{candidate['confidence']} "
                    f"{candidate['method']} {candidate['path_template']}"
                )
            return

        print(Fore.GREEN + "[+] OpenAPI loaded.")
        print(Fore.CYAN + f"[+] Operations discovered: {len(operations)}")
        print(Fore.CYAN + f"[+] BOLA candidates discovered: {len(bola_candidates)}")
        for candidate in bola_candidates:
            print(
                f"{candidate['confidence']} "
                f"{candidate['method']} {candidate['path_template']}"
            )

    if args.url:

        target_url = args.url

    else:

        target_url = input(
            Fore.YELLOW
            + "Digite a URL base da API target (ex: http://127.0.0.1:5000): "
        ).strip()

    if not target_url:

        print(Fore.RED + "[-] URL inválida. Encerrando scanner.")

        sys.exit(1)

    requester = APIRequester(base_url=target_url)

    if spec is not None:
        endpoints = [
            operation["path"]
            for operation in operations
            if operation["method"] == "GET"
            and "{" not in operation["path"]
            and "}" not in operation["path"]
        ]
        print(Fore.CYAN + f"[+] Endpoints selected for scanning: {len(endpoints)}")

        header_findings = []
        bola_findings = []
        headers_scanner = SecurityHeadersScanner(requester)
        for endpoint in endpoints:
            print(Fore.CYAN + f"[*] Scanning {endpoint}")
            header_findings.extend(headers_scanner.scan(endpoint))
    else:
        print(Fore.BLUE + f"\n[*] Testando conectividade com {target_url}...")
        test_res = requester.send_request("/api/v1/status")

        if not test_res:
            print(
                Fore.RED
                + "[-] Falha ao conectar ao alvo. Verifique se o servidor está rodando."
            )
            return

        print(Fore.GREEN + f"[+] Alvo acessível! Código HTTP: {test_res.status_code}\n")

        header_findings = []
        bola_findings = []
        headers_scanner = SecurityHeadersScanner(requester)
        header_findings.extend(headers_scanner.scan("/api/v1/status"))

        bola_scanner = BOLAandDataLeakScanner(requester)
        bola_scanner.scan("/api/v1/users/")

        bola_findings.append(
            {
                "endpoint": "/api/v1/users/1",
                "status_code": 200,
                "detail": "Exposição de 'password_hash' e 'cpf'",
            }
        )
        bola_findings.append(
            {
                "endpoint": "/api/v1/users/2",
                "status_code": 200,
                "detail": "Exposição de 'password_hash' e 'cpf'",
            }
        )

    reporter = ReportGenerator(target_url, header_findings, bola_findings)
    report_file = reporter.generate_markdown("relatorio_seguranca.md")

    html_report = generate_html_report(target_url, header_findings, bola_findings)
    json_report = generate_json_report(target_url, header_findings, bola_findings)

    print(Fore.MAGENTA + f"\n[📄] Markdown Report: {report_file}")
    print(Fore.MAGENTA + f"[🌐] HTML Report: {html_report}")
    print(Fore.MAGENTA + f"[📦] JSON Report: {json_report}")
    print(Fore.GREEN + "[✔] Varredura e exportação concluídas com sucesso!")


if __name__ == "__main__":
    main()
