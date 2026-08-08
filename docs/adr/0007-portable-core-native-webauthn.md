# ADR 0007 — Core portátil e WebAuthn nativo isolado

- Status: aceito
- Release: 0.7.0
- Data: 2026-08-08

## Contexto

O workspace 0.6 não compilava em uma instalação limpa do Windows. A API segura
de `webauthn-rs 0.5.5` depende obrigatoriamente de OpenSSL; seu upstream 0.6 em
desenvolvimento mantém a mesma dependência. Ativar `openssl/vendored` não elimina
a toolchain nativa: transfere o requisito para compilador C, Perl e make.

O restante da SDK usa Rust puro ou dependências que já possuem caminho portátil.
Obrigar todos os consumidores e contribuidores a instalar OpenSSL por causa de
uma capability opcional viola o contrato de instalação simples.

## Decisão

- O workspace define como membros padrão somente os 14 crates portáveis.
- `sdk-auth-webauthn` e `sdk-auth-node` continuam membros do workspace e gates
  completos continuam a testá-los explicitamente com `--workspace`.
- CI executa `cargo test --all-features` sem instalar dependências nativas em
  Windows, Linux e macOS para proteger o caminho zero-setup.
- O pacote Node público só poderá ser lançado quando tiver prebuilds assinados
  para as plataformas suportadas; o usuário final não deve compilar OpenSSL.
- WebAuthn continua atrás do port `WebAuthnEngine`. A implementação segura
  consolidada permanece preferida a uma reimplementação criptográfica própria.

## Invariantes

1. `cargo test --all-features` na raiz não exige OpenSSL, Perl, make ou C compiler.
2. `cargo test --workspace --all-features` continua sendo o gate completo e não
   pode omitir WebAuthn ou Node.
3. A ausência da capability WebAuthn nunca altera as garantias de senha, MFA,
   sessão, IAM ou persistência.
4. Binário nativo público precisa de checksums, proveniência e matriz por target.

## Alternativas rejeitadas

- `openssl/vendored`: ainda exige toolchain externa e aumenta muito o tempo de build.
- Remover WebAuthn: eliminaria o autenticador phishing-resistant preferido.
- Migrar imediatamente para uma crate pure-Rust jovem e não auditada: reduziria
  maturidade justamente na verificação criptográfica mais sensível.
- Esconder o erro apenas na documentação: mantém a instalação padrão quebrada.

## Consequências

O Core volta a compilar em ambiente limpo e a dependência nativa fica visível na
arquitetura. Mantenedores de WebAuthn ainda precisam de OpenSSL. A release Node
passa a depender de automação de prebuild, assinatura e proveniência antes de ser
considerada pública.

## Fontes

- `webauthn-rs 0.5.5`: https://docs.rs/crate/webauthn-rs/0.5.5
- build vendored de OpenSSL: https://docs.rs/openssl/0.10.81/openssl/#vendored

