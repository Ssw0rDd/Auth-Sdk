# Migração 0.6 para 0.7-alpha

Esta migração adiciona identidade federada, contas sem senha local e a camada
BFF/browser/UI. Ela é intencionalmente incompatível no schema: depois que a
versão 7 for aplicada, processos 0.6 devem permanecer desligados.

## Antes da janela

1. Fixe exatamente a revisão/versão 0.7-alpha em todos os serviços e bindings.
2. Faça backup testado do banco e registre o ponto de restauração. A migração
   não oferece downgrade destrutivo automático.
3. Drene tráfego, workers/outbox e todas as réplicas 0.6.
4. Confirme que nenhuma identidade externa existente foi vinculada apenas por
   e-mail. Migre-a somente com um mapeamento confiável de `issuer` + `subject`.
5. Configure os providers no servidor; nunca coloque client secrets no browser,
   Wasm, bundle Vite ou variáveis `VITE_*`.

## Banco de dados

Execute uma única migração operacional antes de iniciar as réplicas 0.7:

```rust,no_run
use sdk_auth_sqlite::SqliteMigrator;

# fn migrate() -> Result<(), Box<dyn std::error::Error>> {
let report = SqliteMigrator::migrate("auth.db")?;
assert_eq!(report.to, 7);
# Ok(())
# }
```

```rust,no_run
use sdk_auth_postgres::{PostgresConfig, PostgresMigrator};
use sdk_auth_types::SecretString;

# async fn migrate() -> Result<(), Box<dyn std::error::Error>> {
let config = PostgresConfig::new(SecretString::new(
    "postgres://sdk_auth:secret@db.example.com/sdk_auth",
));
let report = PostgresMigrator::migrate(&config).await?;
assert_eq!(report.to, 7);
# Ok(())
# }
```

O schema v7:

- torna `users.password_hash` anulável para contas federadas;
- cria `federated_identities` com unicidade por
  `(realm_id, issuer, subject)`;
- cria desafios de link de uso único;
- declara `min_reader_version = 7` e `min_writer_version = 7`.

Não preencha `password_hash` artificialmente para contas federadas e não use o
e-mail como chave do provider. O e-mail verificado é metadado/candidato a link,
nunca uma prova de que duas contas pertencem à mesma pessoa.

## Contrato do BFF

O `@sdk-auth/bff` 0.7 usa resultados discriminados e pode devolver um fluxo
pendente em vez de uma sessão imediata:

- `AuthBackend.password` retorna `authenticated` ou
  `second_factor_required`;
- `AuthBackend.federated` retorna `authenticated`, `link_required` ou
  `registration_required`;
- `AuthBackend.inspect` retorna tanto a sessão backend possivelmente rotacionada
  quanto a visão pública allowlisted;
- `AuthBffConfig.pendingFlows` é obrigatório;
- `BrowserSessionStore.runExclusive` é obrigatório e deve ser distribuído em
  produção;
- passkeys são habilitadas por `PasskeyBackend`, sem enviar o ceremony token ao
  navegador.

Para uma única instância de desenvolvimento, use `MemoryOAuthTransactionStore`,
`MemoryBrowserSessionStore` e `MemoryPendingFlowStore`. Em produção, use
`createEncryptedBffStores` com um `AtomicBlobStore` compartilhado, ou o adapter
Redis fornecido. `putIfAbsent`, `getAndDelete` e `runExclusive` precisam manter
suas garantias entre todos os processos; um simples `GET` seguido de `DELETE`
não é equivalente.

Ao implementar um adapter próprio, traduza apenas rejeições reais de
credencial para `AuthenticationRejectedError`. Indisponibilidade de banco,
provider, KMS ou Redis deve continuar sendo erro 503 e nunca parecer senha
inválida.

## Browser e UI

Troque armazenamento de bearer tokens no frontend por cookies opacos `HttpOnly`
emitidos pelo BFF. O cliente `@sdk-auth/browser` gerencia CSRF e retorna estados
tipados; a UI opcional expõe:

```ts
import '@sdk-auth/ui'
import '@sdk-auth/ui/theme.css'

// <sdk-auth-login show-passkey></sdk-auth-login>
// <sdk-auth-challenge></sdk-auth-challenge>
```

Configure CSP e fontes para o host real. Os bundles são minificados e não
publicam source maps, mas todo código executado no browser continua público por
definição. Somente decisões e segredos no servidor formam uma fronteira de
confidencialidade.

## Ordem de rollout

1. backup e teste de restauração;
2. parar réplicas/workers 0.6;
3. aplicar schema v7 e validar o relatório;
4. subir stores BFF compartilhados e keyring ativo/retido;
5. subir backends 0.7 sem providers habilitados e executar smoke tests locais;
6. habilitar um provider por vez, validando callback, cancelamento, link e
   logout;
7. habilitar UI/passkey depois de sessão, MFA e rotação estarem observáveis;
8. manter métricas separadas para rejeição, erro de infraestrutura, replay,
   latência do lock e falha de callback.

## Validação e rollback

Antes de liberar tráfego, rode os gates de [QUALITY_GATES](QUALITY_GATES.md) e
confirme login por senha com/sem MFA, primeiro/repetido login federado, conflito
de link, passkey, refresh concorrente e revogação.

Se a validação falhar depois da migração, pare 0.7 e restaure o backup completo
para voltar a 0.6. Não altere manualmente os metadados de compatibilidade e não
remova apenas as tabelas federadas: a nulabilidade da senha e as escritas v7 já
podem ter tornado os dados ilegíveis para 0.6.
