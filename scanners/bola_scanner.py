# scanners/bola_scanner.py
from colorama import Fore

class BOLAandDataLeakScanner:
    def __init__(self, requester):
        self.requester = requester
        # Palavras-chave que não deveriam aparecer em respostas JSON públicas
        self.sensitive_keys = ['password', 'password_hash', 'cpf', 'secret', 'credit_card']

    def scan(self, base_endpoint='/api/v1/users/'):
        print(Fore.CYAN + "\n[=== Módulo: Varredura de BOLA & Vazamento de Dados ===]")
        
        # Testando fuzzed IDs (Iterando de 1 a 3 para testar BOLA)
        for user_id in range(1, 4):
            endpoint = f"{base_endpoint}{user_id}"
            response = self.requester.send_request(endpoint)

            if response and response.status_code == 200:
                print(Fore.GREEN + f"[+] Objeto acessado no endpoint '{endpoint}' (HTTP 200)")
                
                try:
                    data = response.json()
                    # Análise de vazamento de dados sensíveis
                    found_sensitive = []
                    for key in self.sensitive_keys:
                        if key in data:
                            found_sensitive.append(key)
                    
                    if found_sensitive:
                        print(Fore.RED + f"    [!] ALERTA DE VAZAMENTO: Campos sensíveis expostos no JSON: {found_sensitive}")
                    else:
                        print(Fore.BLUE + "    [*] Resposta sanitizada (nenhum campo sensível padrão encontrado).")
                        
                except Exception:
                    print(Fore.YELLOW + "    [*] Resposta não é um JSON válido.")
                    
            elif response and response.status_code == 404:
                print(Fore.YELLOW + f"[-] ID {user_id} não encontrado no endpoint '{endpoint}' (HTTP 404)")
            else:
                print(Fore.RED + f"[-] Falha ao acessar endpoint '{endpoint}'")