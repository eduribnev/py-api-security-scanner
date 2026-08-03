# tests/mock_api.py
from flask import Flask, jsonify, request

app = Flask(__name__)

# Simulação de banco de dados em memória
USERS_DB = {
    1: {"id": 1, "username": "admin", "email": "admin@empresa.com", "role": "admin", "cpf": "123.456.789-00", "password_hash": "$2b$12$eImiTXuWVfxm0.0637"},
    2: {"id": 2, "username": "joao_silva", "email": "joao@email.com", "role": "user", "cpf": "987.654.321-11", "password_hash": "$2b$12$k8Z3n9X0z1Y2w3v4u5t6e7"}
}

@app.route('/api/v1/users/<int:user_id>', methods=['GET'])
def get_user_profile(user_id):
    # VULNERABILIDADE 1 (BOLA): Não valida se quem requisitou tem permissão
    # VULNERABILIDADE 2 (Data Leakage): Retorna CPF e Hash de senha no JSON público
    user = USERS_DB.get(user_id)
    if user:
        return jsonify(user), 200
    return jsonify({"error": "Usuário não encontrado"}), 404

@app.route('/api/v1/status', methods=['GET'])
def status():
    # Retorna cabeçalhos inseguros por padrão (sem HSTS, sem CORS restrito)
    return jsonify({"status": "online", "environment": "production"}), 200

if __name__ == '__main__':
    print("🚀 API Mock Vulnerável rodando em http://127.0.0.1:5000")
    app.run(port=5000, debug=False)