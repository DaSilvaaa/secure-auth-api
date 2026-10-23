# Armadilhas na Implementação de JWT e Como Evitá-las

Falhas de segurança em JSON Web Tokens (JWT) raramente decorrem de fragilidades criptográficas dos algoritmos; surgem quase sempre de erros de validação e verificação nas bibliotecas ou no código de aplicação. O projeto `projects/secure-web-api` foi desenhado especificamente para mitigar os quatro vetores de ataque mais comuns.

## 1. O Ataque `alg: none`

O cabeçalho de um JWT permite tecnicamente ao remetente declarar qual o algoritmo utilizado. Bibliotecas que honram cegamente o algoritmo `none` aceitam tokens forjados sem qualquer assinatura válida.
**Mitigação:** Passar uma lista explícita e imutável de algoritmos permitidos (`algorithms=["HS256"]`) ao descodificador, ignorando o cabeçalho declarado pelo utilizador. *(Validado no teste: `test_alg_none_token_rejected`)*.

## 2. Ausência ou Não-Validação da Expiração (`exp`)

Um token sem o *claim* `exp` é válido indefinidamente, transformando um roubo de sessão num acesso perpétuo.
**Mitigação:** Exigir obrigatoriamente a presença dos claims `exp` e `sub` (`options={"require": ["exp", "sub"]}`), fixar uma janela curta de validade (TTL de 15 minutos) e incluir um identificador único aleatório (`jti`, gerado na emissão). *(Validado no teste: `test_expired_token_rejected`)*.

## 3. Enumeração de Utilizadores no Login

Devolver códigos de erro distintos (ex.: "utilizador não encontrado" vs. "password incorreta") ou apresentar tempos de resposta assimétricos permite a agentes maliciosos mapear contas legítimas através de ataques de temporização (*timing attacks*).
**Mitigação:** Executar sempre o cálculo de derivação criptográfica (usando um hash simulado `DUMMY_HASH` quando o utilizador não existe) e retornar rigorosamente a mesma resposta HTTP 401. *(Validado no teste: `test_login_unknown_user_costs_similar_time`)*.

## 4. Força Bruta Ilimitada

Ataques online automatizados contornam hashes fortes se não houver controlo de ritmo.
**Mitigação:** Limitação de pedidos por IP (20 por minuto) com memória limitada, respondendo com HTTP 429. *(Validado no teste: `test_rate_limit_returns_429`)*. Melhoria futura: limite por `ip:username` e cabeçalho `Retry-After`.

## Risco Residual e Próximos Passos

O uso de HS256 partilha a mesma chave secreta entre emissor e verificador. Em arquiteturas distribuídas de grande escala, a transição recomendada passa por chaves assimétricas (EdDSA / RS256) e listas de revogação distribuídas em memória (Redis) indexadas pelo claim `jti`.
