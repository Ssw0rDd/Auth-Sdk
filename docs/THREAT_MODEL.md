# Modelo de ameaças

## Atualização 0.7

- Identidade externa usa issuer HTTPS exato mais subject estável; e-mail,
  username, UPN e `preferred_username` nunca autenticam nem são chave durável.
- E-mail verificado igual exige link explícito com sessão e prova fresca; não há
  auto-link. Primeiro login sem conta grava usuário sem senha, identidade,
  sessão, audit e outbox atomicamente.
- Constraints de e-mail e issuer/subject mais retry tipado impedem duplicação em
  corridas. Login local de conta sem senha usa fake verification.
- Sessão de provedor permanece AAL1 até existir profile de assurance explícito;
  claims do provedor não promovem MFA ou phishing resistance implicitamente.
- O caminho padrão isola WebAuthn/OpenSSL dos crates portáveis e possui gate
  zero-setup em Windows, Linux e macOS.
- O pacote Node público exigirá prebuilds assinados, checksums e proveniência;
  distribuição a partir de build local não verificado não faz parte do contrato.
- Respostas HTTP de recuperação/verificação pertencem ao BFF e devem ser
  indistinguíveis para contas existentes e inexistentes. O dispatch opcional
  nunca pode atravessar a fronteira confiável do host.
- Browser não recebe access/refresh, PKCE verifier, nonce pendente, link token,
  challenge MFA ou ceremony token. Cookies carregam apenas IDs aleatórios.
- Stores BFF distribuídos selam estado com AES-256-GCM e AAD contextual; replay
  de ciphertext sob outro tipo/ID falha autenticação.
- Refresh rotation da sessão backend é persistida durante a inspeção; token
  predecessor não permanece como única cópia após uma resposta bem-sucedida.
- Inspeções concorrentes são serializadas por sessão em todas as réplicas;
  múltiplos refreshes simultâneos não podem acionar revogação falsa por replay.
- Código browser é assumido público. Ausência de source maps e minificação
  reduzem exposição acidental, sem substituir controles server-side.

## Atualização 0.6

- PostgreSQL usa TLS `verify-full`, pool limitado, timeouts e transações para
  todas as mudanças que combinam estado, audit e outbox.
- Rate limit é sliding-window exato; conta e rede são buckets independentes.
- Redis oculta subjects com BLAKE3 keyed e falha fechado sem fallback local.
- Outbox usa claims opacos, lease expirável e ack vinculado ao claim.
- IAM serializa mutações por realm para preservar último owner e limites sob corrida.
- Migração offline bloqueia escritores SQLite e startup PostgreSQL até `complete`.

- WebAuthn exige UV, RP ID imutável, origens exatas e estado exclusivamente
  server-side, expirável e single-use.
- Credential ID é único; registro é ligado à sessão e ao usuário que o iniciou.
- Counter positivo não monotônico revoga a passkey e bloqueia criação de sessão.
- Email não é autenticador: não existe magic-link login nem bypass de step-up.
- Password reset preserva passkeys e MFA, mas revoga sessões e trusted devices.
- Estado e credencial do provider persistem `provider_id` e versão e falham
  fechados quando incompatíveis.

- Journaled mutations gravam estado, audit append-only e, quando aplicável,
  outbox na mesma unidade atômica; falha de qualquer escrita causa rollback.
- Audit e outbox são tabelas e APIs distintas para impedir que acknowledgement
  de entrega apague evidência operacional.
- Ciphertexts registram versão, algoritmo e key ID; valores desconhecidos falham
  fechados.
- O provider software não declara FIPS. Um provider validado dependerá do módulo
  e ambiente de execução específicos.
- Assurance é conservador: trusted-device não eleva AAL; TOTP e recovery code não
  são classificados como phishing-resistant.
- BLAKE3 continua como digest legado de tokens em 0.4. A migração para HMAC será
  dual-read para não revogar credenciais silenciosamente.

## Ativos

Senhas, seeds TOTP, recovery codes, passkeys, estado WebAuthn, chaves do vault, bearer tokens, API keys,
sessões, estado OAuth/BFF, papéis, permissões, service accounts, eventos e
isolamento entre realms.

## Adversários considerados

- cliente controlando todos os campos de entrada;
- atacante com senha, token ou banco roubado;
- credential stuffing, enumeração e brute force de MFA;
- replay de refresh, challenge, TOTP, recovery code ou trusted token;
- replay de cerimônia WebAuthn, origin/RP mismatch e authenticator clone;
- concorrência intencional em tokens de uso único;
- tentativa de acesso cross-realm/IDOR;
- privilege escalation por role, scope excessivo ou mutação IAM concorrente;
- replay de API key durante rotação e uso de principal desabilitado;
- leitor do banco sem a chave externa do vault;
- dependência, CI ou binding comprometido.
- indisponibilidade/manipulação de Redis para liberar brute force;
- dispatcher concorrente, crashado ou malicioso tentando ack de claim alheio;
- pool exhaustion, lock contention, schema drift e migração parcial;

## Controles

- Argon2id e verificação falsa para reduzir enumeração por timing;
- tokens aleatórios de 256 bits persistidos somente como BLAKE3 digest;
- TOTP RFC 6238 com janela ±1 e maior counter aceito persistido;
- recovery codes de 80 bits, digest e consumo único;
- XChaCha20-Poly1305 com nonce aleatório, key ID e AAD contextual;
- trusted tokens rotativos, validade absoluta e revogação em replay;
- nenhuma sessão antes da prova MFA;
- email não substitui MFA;
- passkeys com user verification obrigatória e verifier-name binding;
- ceremony state armazenado somente no servidor, com handle de 256 bits, TTL,
  limite de tentativas e consumo atômico;
- allow-list exata de origens HTTPS e identidades Android por signing certificate;
- credential IDs globais únicos, blobs limitados e provider formats versionados;
- signature counter positivo monotônico; anomalia revoga a credencial e gera audit;
- reset de senha preserva fator, revoga sessões e trusted devices;
- senha mais segundo fator para substituir/desativar MFA ou regenerar códigos;
- rate limit sliding exato para login, com conta/rede independentes e rede nunca
  limpa por sucesso de uma conta;
- Lua Redis atômico, chaves keyed-BLAKE3 e falha fechada;
- operações de consumo e criação dentro da mesma transação;
- SQL parametrizado, foreign keys e isolamento obrigatório por realm;
- eventos sem segredo em outbox transacional;
- RBAC exato e deny-by-default, sem wildcard ou herança implícita;
- catálogo isolado por realm e limites de cardinalidade contra abuso de memória;
- API keys aleatórias de 256 bits, digest BLAKE3, expiração máxima de 365 dias,
  scopes obrigatórios e grace period de rotação limitado a 24 horas;
- roles, scopes e status do principal reavaliados em toda autorização;
- somente usuário com email verificado, sessão, senha e MFA frescos opera IAM;
- permissão administrativa revalidada dentro da transação da mutação;
- proteção atômica do bootstrap e do último owner humano;
- outbox `FOR UPDATE SKIP LOCKED`, lease limitado e acknowledgement claim-bound;
- schema checksummed, conjunto de tabelas validado e import status fail-closed;
- `unsafe` proibido no código próprio, exceto código gerado pela fronteira N-API;
  WebAuthn/OpenSSL são dependências externas isoladas e auditadas por supply-chain gates.

## Compromisso do banco

Um dump expõe metadados IAM, public keys passkey, ceremony state ainda válido,
ciphertext TOTP e digests. Não expõe private keys do authenticator, seeds, recovery
codes, bearer tokens ou API keys em texto. Se banco e key material forem comprometidos,
confidencialidade do TOTP é perdida; o host deve rotacionar chaves, fatores e
sessões conforme seu plano de incidente.

## Limitações

- TOTP é resistente a replay, não a phishing em tempo real. Passkeys/WebAuthn
  são o autenticador phishing-resistant preferido.
- SHA-1 é usado somente dentro de HMAC-TOTP por interoperabilidade; não é usado
  como hash geral ou assinatura.
- Trusted device não elimina verificação de senha.
- PostgreSQL ou Redis distribuem throttling entre réplicas, mas não substituem
  rate limit global/WAF contra DoS volumétrico.
- JavaScript não oferece zeroização confiável de strings e buffers.
- Memory adapter não é durável nem multiprocesso.
- RBAC 0.3 não modela atributos, relações, contexto ou ownership. O host deve
  fazer a checagem de objeto/tenant depois do grant genérico.
- API keys são bearer credentials e não são phishing-resistant; use validade
  curta, escopo mínimo, TLS, rotação e secret manager.
- Login passkey 0.5 é username-first. A etapa de descoberta pode expor diferenças
  entre conta inexistente, conta sem passkey e conta com passkey; rate limit do
  host e mensagens genéricas continuam obrigatórios. Usernameless/conditional UI
  foi adiado por maturidade da API upstream.
- Attestation é `none`; a SDK não afirma AAL3, hardware-bound ou enterprise provenance.
- OpenSSL aumenta superfície nativa e exige patching operacional rápido.
- Redis Cluster/Sentinel, leitura em réplica e active-active multi-region estão
  fora da 0.6. Redis é um acelerador de segurança, não source of truth de IAM.
- Outbox é at-least-once; consumidores não idempotentes podem repetir efeitos.

## Responsabilidade do host

TLS, cookies, CSRF, CORS, CSP, proxy confiável, WAF, rate limit global, secret
manager/HSM, rotação operacional de chaves, SMTP, backup, retenção, SIEM,
autorização HTTP/por recurso e resposta a incidentes ficam fora da biblioteca.
