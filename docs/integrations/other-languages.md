# Rust, Python, Go, Java e outros hosts

## Rust

Rust é a API nativa e mais completa. Componha `SdkAuth` com Memory/SQLite ou
PostgreSQL, um `CryptoProvider`, vault e, opcionalmente, `WebAuthnEngine`. O
exemplo principal está no [README](../../README.md).

## Python, Go e Java hoje

O contrato estável entre browser e autenticação é HTTP e está descrito em
[`bff.yaml`](../openapi/bff.yaml). Para um host não-Node:

1. execute o Core/BFF como sidecar Node dentro do mesmo domínio operacional;
2. faça reverse proxy de `/auth/*` para o sidecar sem reescrever `Origin`, path
   ou múltiplos `Set-Cookie`;
3. mantenha o sidecar inacessível diretamente da internet;
4. gere clientes a partir do OpenAPI apenas para tipos/rotas — cookies e CSRF
   continuam sob controle do browser client oficial;
5. autorizações por recurso continuam no serviço da aplicação, depois da
   validação de sessão/permission no SDK.

```text
Browser ─HTTPS─> Python/Go/Java app ─private proxy /auth─> SDK-Auth sidecar
   │                    │                                  │
   └── cookie opaco ────┘                        Rust Core + DB/KMS
```

Não reimplemente OIDC/JWT, PKCE, linking ou refresh rotation em cada linguagem.
Bindings Python/UniFFI ainda estão no roadmap para 1.0 e não são apresentados
como suporte estável no alpha. Essa distinção evita uma falsa promessa de
portabilidade e preserva uma única política de segurança.

## Operação

- TLS externo e mTLS/rede privada entre app e sidecar;
- health/readiness sem dados de usuário;
- chaves em KMS/HSM/secret manager, separadas do banco;
- timeout, limite de body e pool bounded no proxy;
- logs estruturados com redaction e correlação sem bearer;
- deploy coordenado com migrations explícitas e rollback de binário, nunca de
  schema destrutivo.
