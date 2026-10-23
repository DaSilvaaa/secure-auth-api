# Modelo de Ameaças STRIDE — secure-web-api

| Ameaça | Cenário | Mitigação | Teste |
|---|---|---|---|
| **S**poofing | Token forjado (`alg: none`, assinatura inválida, outra chave) | HS256 explícito, `exp`/`sub` obrigatórios | `test_alg_none_token_rejected`, `test_tampered_token_rejected`, `test_token_signed_with_other_key_rejected` |
| **T**ampering | Alteração do payload do JWT | Verificação da assinatura HMAC | `test_tampered_token_rejected` |
| **R**epudiation | Ações sem registo | *Não mitigado*: falta logging de auditoria | — |
| **I**nformation disclosure | Enumeração de utilizadores (registo e timing no login); fuga de hashes | Resposta uniforme, Argon2 com hash simulado, Argon2id | `test_register_does_not_reveal_existing_user`, `test_login_unknown_user_costs_similar_time` |
| **D**enial of service | Força bruta / inundação de pedidos; esgotar memória com muitos IPs | Rate limit por IP, `MAX_TRACKED_IPS` | `test_rate_limit_returns_429` |
| **E**levation of privilege | Reutilização de token expirado; chave fraca ou por defeito | TTL 15 min, `SECRET_KEY` obrigatória (≥ 32 chars) | `test_expired_token_rejected`, `test_missing_secret_key_fails` |

## Risco residual
Sem revogação de tokens, rate limit apenas por IP e por processo, armazenamento em memória, sem logging de auditoria.
