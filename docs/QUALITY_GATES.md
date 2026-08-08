# Quality gates

Cada módulo recebe notas de 0 a 10 em arquitetura, segurança, performance,
escalabilidade, legibilidade, acoplamento, coesão, API pública, bugs, memória,
`unsafe`, dívida técnica, complexidade, testes e documentação.

Um módulo só está liberado quando:

- média ponderada igual ou superior a 9,5;
- segurança igual ou superior a 9,5;
- arquitetura e API pública iguais ou superiores a 9;
- nenhum achado crítico ou alto permanece aberto;
- build, Clippy, testes, rustdoc, audit e deny passam;
- cobertura da lógica security-critical em core, crypto, validation, MFA,
  authorization e WebAuthn orchestration é igual ou superior a 90%.

O adapter `sdk-auth-webauthn` exige OpenSSL development/runtime libraries. Os
jobs Windows, Linux e macOS configuram a dependência explicitamente. Fuzzing
inclui respostas WebAuthn hostis contra estado válido server-side.

Os adapters distribuídos possuem contratos executados com PostgreSQL 16, 17 e
18 e Redis 7 e 8. Teste sem URL configurada compila e pula; somente o job
`distributed`, com serviços reais e variáveis obrigatórias, vale como evidência
de runtime. A migração SQLite→PostgreSQL copia linhas reais antes de liberar o
startup do adapter.

O gate de cobertura mede lógica própria security-critical. Exclui bindings,
stores concretos, composition root/facades e o adapter fino `webauthn-rs`;
esses componentes possuem contratos e smoke tests próprios. A orquestração
WebAuthn em `sdk-auth-core/src/webauthn.rs` permanece integralmente no gate.

Benchmarks não usam limites absolutos em runners compartilhados. O CI preserva
resultados como artefatos para análise de tendência. Mutation testing deve ser
executado periodicamente sobre Core, MFA, authorization e crypto. Até existir
runner dedicado e baseline estável, falha de infraestrutura é registrada como
risco e não convertida em score inventado.

Nota 10 em segurança não é usada como promessa de invulnerabilidade. O gate
exige ausência de achados críticos/altos, riscos residuais documentados e
controles verificáveis.
