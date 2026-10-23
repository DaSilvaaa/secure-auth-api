# Secure Web API — backend de autenticação pronto a usar

Backend de autenticação para a tua app ou loja online: registo, login, **reset de password por email**, **2FA (TOTP, Google Authenticator)** e proteção contra ataques comuns. Pronto para correr em Docker.

**Problema que resolve:** quase todos os produtos precisam de login seguro, e é onde mais se falha (passwords mal guardadas, contas enumeráveis, sem 2FA, reset inseguro).

| Endpoint | Função |
|---|---|
| `POST /register` | Criar conta (resposta uniforme) |
| `POST /token` | Login (+ `otp` se 2FA ativo) → JWT |
| `GET /me` | Utilizador autenticado |
| `POST /2fa/setup`, `/2fa/enable` | Ativar 2FA com QR/URI `otpauth://` |
| `POST /password/forgot`, `/password/reset` | Reset por email, token de uso único (30 min) |
| `GET /health` | Verificação de saúde |

Documentação interativa em `/docs` (Swagger). Modelo de ameaças: [`docs/threat-model.md`](docs/threat-model.md).

## Funcionalidades de segurança
- **Argon2id** (`argon2-cffi`) para hashing de passwords.
- **JWT HS256 real** (`pyjwt`) com `algorithms=["HS256"]` explícito (bloqueia `alg: none`), claims `exp`, `sub`, `iat` e `jti` obrigatórios/gerados, TTL de 15 minutos.
- **Chave por variável de ambiente:** `SECRET_KEY` (≥ 32 caracteres). A aplicação recusa arrancar sem ela.
- **Sem enumeração de utilizadores:** `/register` responde sempre igual; `/token` executa sempre o Argon2 (hash simulado quando o utilizador não existe).
- **Rate limiting** por IP (20 pedidos/min) com memória limitada (`MAX_TRACKED_IPS`).
- **2FA TOTP** (`pyotp`): falhas de 2FA devolvem a mesma resposta que password errada.
- **Reset de password:** token aleatório de 256 bits, guardado só como hash SHA-256, uso único, expira em 30 min; `/password/forgot` não revela se o email existe.
- **Persistência SQLite** com queries parametrizadas.
- **Security headers:** `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `HSTS`.

## Executar
```bash
cd secure-auth-api
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
uvicorn main:app --app-dir src
```

## Deploy
- **Docker Compose:** `cp .env.example .env`, preencher `SECRET_KEY` (e SMTP) e `docker compose up -d` (dados persistidos no volume `/data`).
- **Render:** ligar o repositório; o `render.yaml` cria o serviço no **plano gratuito** com `SECRET_KEY` gerada. No plano gratuito a instância adormece após ~15 min sem tráfego e o SQLite é efémero (serve para demo); para produção usar um plano pago com disco ou PostgreSQL. Definir `SMTP_*` no painel.
- Em produção, colocar atrás de HTTPS (o Render já o faz).

## Testes
```bash
python -m pytest tests/
```
Cobrem (26 testes): reset (uso único, expiração, token guardado em hash), 2FA, fluxo registo/login, `alg: none`, token expirado, adulterado, assinado com outra chave, sem `exp`, enumeração no registo, igualização de tempo no login, Argon2id, chave em falta e rate limit.

## Docker
```bash
docker build -t secure-auth-api .
docker run -e SECRET_KEY="$SECRET_KEY" -p 8000:8000 secure-auth-api
```

## Limitações conhecidas
SQLite (uma instância); rate limiter em memória por processo; sem revogação de tokens nem códigos de recuperação 2FA. Para escalar: PostgreSQL e Redis (rate limit, revogação por `jti`).
