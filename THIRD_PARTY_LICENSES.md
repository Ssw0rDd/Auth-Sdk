# Licenças de terceiros

O código próprio do workspace usa `MIT OR Apache-2.0`.

## WebAuthn

`sdk-auth-webauthn` depende de `webauthn-rs` 0.5.5 e crates relacionadas sob
MPL-2.0. A dependência é usada sem modificação e permanece isolada no adapter.
Distribuidores devem preservar notices/licenças aplicáveis e cumprir a MPL-2.0.

## Persistência distribuída

`sqlx` 0.9.0 e `redis` 1.4.1 são usados nos adapters PostgreSQL e Redis. A árvore
Redis inclui `xxhash-rust` sob Boost Software License 1.0 (`BSL-1.0`), licença
permissiva aprovada no gate. Versões permanecem fixadas para revisão reproduzível.

O inventário completo e as licenças transitivas são validados por
`cargo deny check` a partir do `Cargo.lock`. Este arquivo não substitui análise
jurídica para um modelo de distribuição específico.
