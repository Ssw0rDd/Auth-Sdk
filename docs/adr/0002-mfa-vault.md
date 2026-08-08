# ADR 0002: MFA, trusted devices e vault versionado

Status: aceito em 2026-07-28.

## Contexto

MFA precisava permanecer no Core, funcionar em Memory/SQLite/Node e permitir
troca de storage e binding sem duplicar regras. Seeds TOTP não podem ser
persistidos em texto e uma migração de chave não pode exigir indisponibilidade.

## Decisão

- TOTP RFC 6238: HMAC-SHA1, 6 dígitos, período de 30 segundos e janela ±1.
- Um fator TOTP ativo por usuário; replacement é explícito.
- Maior counter aceito é persistido para bloquear replay.
- Dez recovery codes de 80 bits, uso único, armazenados por digest.
- Seeds são selados por `SecretVault` com XChaCha20-Poly1305, key ID e AAD.
- O host injeta keyring e chave ativa; storage guarda somente ciphertext.
- Trusted device usa bearer token de 256 bits, rotação por uso, validade absoluta
  de 30 dias e revogação no replay.
- Login retorna resultado discriminado e não cria sessão antes de MFA.
- Reset de senha preserva MFA, mas revoga sessões e trusted devices.
- Mudança de fator exige senha atual e TOTP/recovery code.

## Alternativas rejeitadas

- Seed em texto no banco: compromisso do banco comprometeria todos os fatores.
- AES-GCM com nonce de 96 bits gerado no adapter: seguro quando correto, porém
  XChaCha reduz risco operacional de colisão de nonce aleatório.
- JWT para challenge MFA: dificulta revogação e consumo atômico; challenge opaco
  persistido é mais simples e auditável.
- Email como fallback MFA: reduz a conta ao nível de segurança do email e cria
  bypass do fator.
- Trusted cookie não rotativo: replay seria indistinguível de uso legítimo.

## Consequências

O host precisa operar migração SQLite e ciclo de vida das chaves. Perder todas as
chaves retidas perde os fatores criptografados. TOTP continua suscetível a
phishing; WebAuthn é a próxima evolução recomendada.
