# ADR 0006 — Persistência distribuída, throttling e outbox leased

- Status: aceito
- Release: 0.6.0
- Data: 2026-07-30

## Contexto

Memory e SQLite preservam invariantes em uma instância, mas não sustentam
concorrência entre réplicas. O rate limit anterior também acoplava conta e rede,
criava bucket `unknown` quando a rede não existia e usava janela fixa. O outbox
sem lease permitia que dois dispatchers processassem o mesmo lote sem ownership.

## Decisão

- PostgreSQL 16–18 é o adapter transacional distribuído oficial.
- SQLx 0.9.0 é fixado; MSRV sobe para Rust 1.94.
- Migrações PostgreSQL são explícitas, checksummed e serializadas por advisory lock.
- TLS PostgreSQL usa `verify-full`; exceção plaintext exige loopback explícito.
- Pool e sessões têm limites e timeouts finitos.
- Redis 7/8 é adapter opcional exclusivo de `RateLimitStore`.
- Rate limit usa janela sliding exata, Lua atômico, buckets independentes e
  identificadores keyed-BLAKE3. Falha Redis é fail-closed.
- Outbox ganha `claim`, `acknowledge_claim` e `release_claim`, com lease de 5s–15m
  e `FOR UPDATE SKIP LOCKED` no PostgreSQL.
- A entrega continua at-least-once; idempotência pertence ao consumidor.
- SQLite evolui para schema v6 com os mesmos contratos.
- Migração SQLite→PostgreSQL é offline, aceita destino vazio e bloqueia startup
  enquanto `sdk_import_status` não estiver `complete`.
- Node mantém o construtor SQLite e ganha `connectPostgres` assíncrono.

## Invariantes

1. Sucesso de login limpa somente o bucket de conta; nunca o de rede.
2. Ausência de fingerprint de rede não cria bucket compartilhado artificial.
3. Limite cinco permite exatamente cinco falhas; a sexta bloqueia.
4. IAM revalida autoridade dentro da mesma transação da mutação.
5. Mutações IAM por realm são serializadas para preservar último owner e limites.
6. Um evento leased só pode ser reconhecido pelo claim correto e ainda válido.
7. Schema parcial, importação interrompida ou dependência indisponível falham fechado.

## Alternativas rejeitadas

- Janela fixa: permite rajada no limite entre duas janelas.
- Fallback local quando Redis cai: permite bypass por troca de réplica.
- Redis como source of truth de sessão/IAM: perde atomicidade com o journal SQL.
- JWT como solução de escala: revogação e permissões atuais continuam exigindo estado.
- Migração online/dual-write: aumenta estados intermediários e risco de divergência.
- Exactly-once no outbox: promessa falsa sem transação distribuída com o destino.

## Consequências

O deploy distribuído passa a ter contrato real de concorrência e falha. O custo é
operacional: PostgreSQL/Redis, certificados, migrations e consumidores
idempotentes. Redis não é obrigatório; PostgreSQL mantém rate limit correto com
maior contenção. Home region, multi-region active-active, Sentinel e Cluster ficam
fora da 0.6.
