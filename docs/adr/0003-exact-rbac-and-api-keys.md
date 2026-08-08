# ADR 0003: RBAC exato e API keys restritas

- Status: aceito
- Data: 2026-07-29

## Contexto

O SDK precisava autorizar usuários e workloads sem duplicar regra nos bindings.
Wildcards, role hierarchy e ABAC aumentariam ambiguidade e superfície de bypass
antes de existir um modelo de domínio estável.

## Decisão

- `sdk-auth-authorization` mantém value objects e avaliação pura; Core orquestra
  credenciais e adapters persistem estado.
- Permissões usam `resource:action`, lowercase ASCII, comparação exata e
  deny-by-default. Não há wildcard, hierarquia ou explicit deny em 0.3.
- Catálogo, roles e assignments pertencem a um realm.
- API keys têm segredo aleatório de 256 bits, digest persistido, scopes não
  vazios, TTL padrão de 90 dias, máximo de 365 dias e overlap máximo de 24 horas.
- Roles e principal são reavaliados em toda autorização. O scope restringe, mas
  nunca amplia as permissões atuais.
- Bootstrap é único. Toda leitura sensível e mutação IAM exige usuário humano,
  email verificado, sessão ativa, senha atual, MFA fresco e permissão explícita.
- Adapters revalidam o ator no mesmo lock/transação da mutação.
- WASM só valida sintaxe. Node apenas traduz tipos. Nenhuma regra é duplicada.

## Consequências

O modelo é previsível, testável e revoga acesso imediatamente. Em troca, pode
produzir mais permission keys e não resolve ownership, relações ou contexto.
Essas decisões ficam no Core de domínio do consumidor; ABAC só será introduzido
com requisitos concretos. Step-up em toda consulta IAM é seguro, porém mais
friccional para consoles administrativos.

## Referências

- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [NIST SP 800-63B-4: Authenticators](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/)
