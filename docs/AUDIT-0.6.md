# Auditoria técnica 0.6 — persistência distribuída

- Data: 2026-07-30
- Escopo: Core, PostgreSQL, Redis, SQLite v6, migração offline, Node, CI e documentação
- Resultado: aprovado no gate técnico local; publicação continua condicionada à matriz CI e auditoria externa
- Nota final: **9,5/10**

## Resultado por critério

| Critério | Nota | Evidência e limite |
|---|---:|---|
| Arquitetura | 9,7 | PostgreSQL implementa ports; Redis implementa somente rate limit; bindings traduzem DTOs |
| Segurança | 9,6 | TLS seguro por padrão, falha fechada, chaves keyed-BLAKE3, migração/import fail-closed |
| Performance | 9,5 | Pool limitado, Lua em um round-trip, outbox em lote e import em lotes de 256; falta baseline de carga |
| Escalabilidade | 9,6 | PostgreSQL multi-instância, Redis distribuído e leasing concorrente; active-active foi adiado |
| Legibilidade | 9,5 | Separação por capability; adapter SQL é necessariamente extenso |
| Acoplamento | 9,7 | Core não conhece SQLx, Redis, N-API nem motores concretos |
| Coesão | 9,6 | Cada adapter possui uma finalidade; migração vive em binário separado |
| API pública | 9,6 | APIs antigas preservadas/depreciadas; factory PostgreSQL é assíncrona e explícita |
| Bugs e concorrência | 9,6 | Contratos reais cobrem leasing, rate limit, IAM race, passkeys e MFA |
| Memória e leaks | 9,5 | Entradas limitadas, pool limitado e respostas Redis delimitadas; não há retenção local infinita conhecida |
| `unsafe` | 9,8 | Crates Rust próprias proíbem `unsafe`; fronteira gerada N-API permanece isolada |
| Dívida técnica | 9,5 | N+1 limitado em scopes de API keys e ausência de load baseline documentados |
| Complexidade | 9,5 | Transações e compatibilidade são explícitas; não há abstração genérica de banco artificial |
| Testes e documentação | 9,6 | Contratos cruzados e runtime real local; matriz 16–18/7–8 depende do CI remoto |

Não há achado crítico ou alto conhecido. A nota não declara invulnerabilidade,
certificação NIST/FIPS ou garantia de disponibilidade.

## Arquitetura e responsabilidades

- `sdk-auth-core` continua dono das regras de identidade, autenticação, MFA,
  sessão, autorização, passkeys, rate limit e outbox.
- `sdk-auth-postgres` traduz todos os ports persistentes para SQL parametrizado e
  transações. Ele não decide política de senha, assurance ou permissão.
- `sdk-auth-redis` implementa exclusivamente `RateLimitStore`. IAM, sessões e
  tokens nunca dependem de cache eventual.
- `sdk-auth-sqlite` permanece adequado a processo único e usa schema v6.
- `sdk-auth-migrate` é ferramenta offline, não caminho implícito de startup.
- `sdk-auth-node` preserva o construtor SQLite síncrono e adiciona factories
  assíncronas para migrar/conectar PostgreSQL e compor Redis opcional.

Não foram criadas dependências circulares. Core não depende de adapters.
PostgreSQL não depende de Redis. A composição do rate limiter dedicado acontece
somente no composition root.

## Persistência e consistência

- Startup PostgreSQL exige schema v6, conjunto completo de tabelas e import com
  estado `complete`; schema parcial ou import interrompido falha fechado.
- Migrações usam checksum e advisory lock para impedir aplicação concorrente.
- IAM revalida autoridade dentro da mesma transação e serializa mutações por
  realm com advisory lock, inclusive bootstrap e proteção do último owner.
- Outbox usa lease de 5 segundos a 15 minutos, claim id opaco,
  `FOR UPDATE SKIP LOCKED`, acknowledgement vinculado ao claim e release.
- A entrega é **at-least-once**. Consumidores devem ser idempotentes; exactly-once
  não é prometido.
- Rate limit PostgreSQL mantém timestamps exatos por bucket sob row lock.
- SQLite v6 remove contadores agregados antigos porque não é possível reconstruir
  com segurança uma janela exata a partir deles.

## Segurança

Controles implementados:

- PostgreSQL exige validação de certificado e hostname fora de loopback; bypass
  inseguro precisa ser explicitamente habilitado para teste local.
- Pool, acquire, connect, statement e lock timeouts são limitados.
- URLs e segredos usam tipos redigidos e não são incluídos em mensagens de erro.
- Redis exige `rediss://` fora de loopback; erro, timeout ou resposta inválida
  nega a tentativa. Não existe fallback em memória.
- Buckets Redis não contêm realm, email ou fingerprint em claro. Identificadores
  usam BLAKE3 keyed e a chave primária permanece segredo do host.
- O script Lua atualiza buckets de conta e rede atomicamente em uma instância
  Redis primária e implementa sliding window exata.
- Ausência de fingerprint de rede não cria bucket global `unknown`.
- Login bem-sucedido limpa somente o bucket da conta; pressão de rede permanece.
- Inputs, lease, lote, duração e identificadores possuem limites antes de I/O.
- SQL usa bind parameters. Nomes de tabela e schema não vêm de input externo.
- Migração lê a URL PostgreSQL de variável de ambiente, bloqueia escritores
  SQLite com `BEGIN IMMEDIATE`, verifica integridade/FKs, exige destino vazio e
  copia tudo em uma única transação.

Ameaças mitigadas incluem brute force distribuído, credential stuffing, replay
de claim, dupla entrega concorrente, schema downgrade/parcial, import parcial,
SQL injection, exposição acidental de subjects no Redis, pool exhaustion e race
de privilege escalation no IAM.

Fora de escopo: comprometimento do host, proteção física de chaves, DDoS de
camada de rede, configuração de firewall/TLS do operador, Redis Cluster/Sentinel,
multi-region active-active e garantia exactly-once.

## Performance e benchmark esperado

Não foi inventado limite absoluto de latência. Hardware, TLS, rede e fsync tornam
qualquer número local inadequado como SLO portátil. A estrutura esperada é:

- Redis rate limit: um script Lua e um round-trip por tentativa;
- PostgreSQL rate limit: uma transação curta e no máximo dois buckets bloqueados;
- outbox claim: uma CTE por lote com `SKIP LOCKED`, sem lock global de fila;
- migração: `INSERT` parametrizado em lotes de 256 linhas por tabela;
- pooling: espera limitada e erro tipado quando o pool é esgotado.

Próximo gate de performance: Criterion para preparação local, `pgbench`/k6 para
concorrência distribuída e histórico p50/p95/p99 em runner dedicado. Não se deve
falhar CI compartilhado por limiar absoluto sem baseline estável.

## Evidências executadas localmente

- PostgreSQL 18 real: migração de SQLite v6 com três linhas passou.
- PostgreSQL 18 real: contrato completo de identidade, sessão, MFA, rewrap,
  trusted devices, IAM, corrida de bootstrap, API keys, audit e passkeys passou.
- PostgreSQL 18 real: contratos de sliding-window e leased outbox passaram.
- Redis 8 real: contrato distribuído passou, incluindo 5 tentativas permitidas,
  sexta bloqueada, buckets independentes e clear somente da conta.
- Node N-API release build, smoke test e `npm audit --audit-level=high` passaram.
- Target `wasm32-unknown-unknown` passou.
- `cargo audit --deny warnings` e `cargo deny check` passaram antes do gate final;
  versões transitivas duplicadas continuam warnings permitidos.

A matriz PostgreSQL 16/17/18 e Redis 7/8 está declarada no GitHub Actions, mas
não foi executada localmente em todas as combinações. Release público exige o
job remoto verde; configuração de CI não é evidência de execução.

## Achados residuais

1. **Baixo — listagem de API keys:** scopes são buscados por chave, gerando N+1
   queries. Resultado é correto, mas precisa paginação/batch antes de realms com
   grande cardinalidade.
2. **Baixo — baseline distribuído:** faltam resultados persistidos de carga e
   contenção. A estrutura das queries foi revisada, mas throughput não foi alegado.
3. **Baixo — duplicações transitivas:** `cargo-deny` reporta múltiplas versões
   permitidas por dependências upstream. Aumentam superfície de atualização.
4. **Baixo — suporte de contratos:** o teste PostgreSQL reutiliza fontes de
   contrato internas por caminho. Funciona e evita divergência, mas deve migrar
   para módulos públicos de `sdk-auth-testing` se outros adapters forem criados.
5. **Operacional — chaves Redis:** não há dual-read para rotação. A 0.6 exige
   manter a chave primária durante a janela de lockout ou aceitar reset dos buckets.

## Decisões difíceis de reverter

- Semântica de lease/claim e at-least-once da outbox.
- Schema v6 e representação temporal dos buckets exatos.
- Códigos públicos de erro e factory assíncrona PostgreSQL no binding Node.
- Subjects Redis derivados por keyed-BLAKE3 e divisão conta/rede.
- PostgreSQL como source of truth; Redis nunca autoriza por cache.

## Adiado conscientemente

- 0.7: home-region por realm, roteamento multi-region e fencing explícito.
- Depois de demanda comprovada: Redis Sentinel/Cluster, read replicas, DynamoDB,
  Kafka/NATS e adapters mobile adicionais.
- 2.0 somente se necessário: remoção das APIs de outbox depreciadas e mudança
  incompatível de envelopes/claims.
- Rejeitado: migração online sem CDC, fallback de rate limit em memória,
  autorização eventual em Redis e promessa exactly-once.

## Conclusão crítica

A 0.6 resolve o salto de processo único para implantação multi-instância sem
contaminar o Core com infraestrutura. O ponto mais forte é a consistência entre
ports, transações e contratos reais. O principal risco restante é operacional:
TLS, sizing, observabilidade e capacidade precisam ser configurados e medidos no
ambiente do consumidor. A arquitetura pode seguir para a próxima fase somente
após a matriz CI completa ficar verde.

## Referências primárias

- [PostgreSQL 18 — SELECT locking e SKIP LOCKED](https://www.postgresql.org/docs/18/sql-select.html)
- [PostgreSQL 18 — client connection defaults e timeouts](https://www.postgresql.org/docs/18/runtime-config-client.html)
- [PostgreSQL 18 — advisory locks](https://www.postgresql.org/docs/18/functions-admin.html)
- [Redis — rate limiting](https://redis.io/docs/latest/develop/use-cases/rate-limiter/)
- [Redis — atomicidade de scripts Lua](https://redis.io/docs/latest/develop/programmability/eval-intro/)
- [SQLx 0.9.0](https://docs.rs/sqlx/0.9.0/sqlx/)
- [redis-rs 1.4.1](https://docs.rs/redis/1.4.1/redis/)
