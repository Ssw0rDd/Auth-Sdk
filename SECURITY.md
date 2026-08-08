# Política de segurança

## Relato

Não abra issue pública para vulnerabilidades. Envie um relatório privado aos
mantenedores com componente, impacto, pré-condições e forma segura de reproduzir.
Não inclua credenciais, dados pessoais ou tokens reais.

## Controles do 0.6

- `unsafe` proibido no workspace.
- Senhas protegidas por Argon2id e salts aleatórios.
- Tokens opacos com 256 bits; somente digests persistidos.
- Refresh token de uso único com revogação da família em caso de reuse.
- Erros públicos não expõem storage, stacktrace ou existência de conta.
- Toda identidade é isolada por `RealmId`.
- Seeds TOTP são selados com XChaCha20-Poly1305 e AAD contextual.
- TOTP, recovery codes e trusted devices possuem proteção contra replay.
- Nenhuma sessão é criada antes da conclusão da segunda prova.
- RBAC usa permissões exatas e deny-by-default; wildcard e herança não existem.
- API keys têm 256 bits, são persistidas por digest, limitadas por scopes,
  expiram, rotacionam e podem ser revogadas.
- Role e status do principal são reavaliados em toda autorização.
- O control plane exige sessão humana, senha atual, MFA fresco e permissão;
  API keys não podem administrar IAM.
- Mutação e revalidação do ator são atômicas nos adapters oficiais.
- Passkeys exigem user verification, RP ID estável e allow-list de origem exata.
- Estado WebAuthn permanece server-side e cerimônias são expiradas e single-use.
- Counter positivo anômalo revoga a passkey e nunca cria sessão.
- Email é usado somente para ownership/recovery; não existe login por magic link.
- PostgreSQL exige TLS `verify-full` fora de loopback, pool limitado e timeouts.
- Redis usa TLS fora de loopback, subjects keyed-BLAKE3 e falha fechado.
- Rate limit de login usa janela sliding exata e buckets de conta/rede independentes.
- Outbox distribuído exige claim válido, lease ativo e consumidor idempotente.
- Schema parcial e migração SQLite→PostgreSQL interrompida bloqueiam startup.

## Responsabilidade do host

O host deve aplicar TLS, cookies seguros, CSRF, origem confiável do endereço IP,
política de retenção, autorização por recurso contra IDOR, redaction de logs e
entrega segura dos eventos de email.
O keyring do vault deve vir de secret manager/HSM, nunca do banco ou repositório.
Mantenha chaves antigas até concluir e verificar o rewrap.
Mantenha OpenSSL e `webauthn-rs` atualizados; somente a versão upstream mais
recente suportada deve permanecer em produção.
