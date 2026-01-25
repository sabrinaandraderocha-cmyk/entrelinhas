# Entrelinhas 🎬🌒
Um app intimista para registrar o que um filme deixa em você — sem notas, sem ranking, sem barulho.

## Como rodar (Windows / Mac / Linux)

### 1) Criar ambiente (opcional, mas recomendado)
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Mac/Linux:
source .venv/bin/activate
```

### 2) Instalar dependências
```bash
pip install -r requirements.txt
```

### 3) Rodar
```bash
python app.py
```

Abra no navegador:
http://127.0.0.1:5000

## Dados
Tudo fica salvo localmente no arquivo `entrelinhas.db` (SQLite) dentro da pasta do projeto.

## Dica de segurança
Se você for colocar online, troque o SECRET_KEY e use um servidor WSGI (ex: gunicorn) + HTTPS.