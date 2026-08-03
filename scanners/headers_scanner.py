# scanners/headers_scanner.py
from colorama import Fore

class SecurityHeadersScanner:
    def __init__(self, requester):
        self.requester = requester
        # Lista de cabeçalhos recomendados pela OWASP
        self.recommended_headers = [
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Content-Security-Policy'
        ]

    def scan(self, endpoint='/api/v1/status'):
        print(Fore.CYAN + "\n[=== Módulo: Varredura de Cabeçalhos de Segurança ===]")
        response = self.requester.send_request(endpoint)
        
        if not response:
            print(Fore.RED + "[-] Não foi possível realizar a requisição de cabeçalhos.")
            return

        headers = response.headers
        issues_found = 0

        # Verificação de cabeçalhos ausentes
        for header in self.recommended_headers:
            if header not in headers:
                print(Fore.YELLOW + f"[!] AVISO: Cabeçalho de segurança ausente: '{header}'")
                issues_found += 1
            else:
                print(Fore.GREEN + f"[+] Cabeçalho encontrado: '{header}'")

        # Verificação específica de CORS
        cors_header = headers.get('Access-Control-Allow-Origin')
        if cors_header == '*':
            print(Fore.RED + "[!] VULNERABILIDADE CRÍTICA: CORS permissivo detectado (Access-Control-Allow-Origin: *)")
            issues_found += 1

        if issues_found == 0:
            print(Fore.GREEN + "[+] Nenhum problema evidente detectado nos cabeçalhos.")
        else:
            print(Fore.RED + f"[-] Total de potenciais falhas de cabeçalho: {issues_found}")