# ADR 0010 — código público e estado confidencial

- Status: aceito
- Release: 0.7.0
- Data: 2026-08-08

## Contexto

O projeto é open source e parte dele executa no browser. Qualquer JavaScript,
Wasm, CSS, fonte ou asset entregue ao cliente pode ser lido, formatado,
instrumentado e depurado pelo próprio cliente. Ofuscação, “criptografia de
criptomoeda” ou uma chave embutida no bundle não criam confidencialidade: o
runtime precisa receber código e chave suficientes para executar.

Há, porém, dados que precisam permanecer confidenciais: client secrets OAuth,
PKCE verifier, nonce enquanto pendente, link/challenge/ceremony tokens, access e
refresh tokens, chaves de vault e material de sessão backend.

## Decisão

1. Segurança não depende de esconder implementação. Toda decisão de autenticação
   e autorização ocorre no Core/BFF confiável; o browser é sempre não confiável.
2. Builds browser são minificados e não publicam source maps nem declaration
   maps. Isso reduz exposição acidental de comentários/caminhos, mas não é
   listado como controle criptográfico.
3. Nenhum secret é compilado em bundle, Wasm ou binário distribuído. Configuração
   secreta vem do ambiente/secret manager do host.
4. Estado BFF de produção é selado por `@sdk-auth/bff/stores` com AES-256-GCM,
   nonce aleatório, key ID e AAD contendo deployment, tipo, record ID e versão.
   A chave ativa e chaves antigas vêm de KMS/HSM/secret manager e nunca do mesmo
   banco/KV.
5. O Core Rust continua usando XChaCha20-Poly1305 versionado para secrets de
   longa duração. Algoritmos próprios, blockchain e cifra sem autenticação são
   proibidos.
6. O host deve servir CSP estrita, TLS, `nosniff`, proteção de framing e SRI para
   assets de CDN imutáveis. CSP reduz exploração de XSS; não torna o bundle
   secreto.
7. Binários N-API podem elevar o custo de engenharia reversa, mas sua lógica é
   tratada como publicamente conhecível e seus símbolos/metadados não podem
   conter secrets.

## Consequências

O pacote é auditável e não faz promessa impossível de “source invisível”. Um
atacante que obtenha apenas assets públicos não recebe credenciais nem estado de
servidor. Um atacante que comprometa simultaneamente o KV e o keyring pode abrir
o estado BFF; resposta a incidente deve revogar sessões e rotacionar chaves.
Key rotation é gradual: novas escritas usam a chave ativa, leituras aceitam
chaves retidas e uma reescrita normal sela novamente com a chave ativa.

## Alternativas rejeitadas

- JavaScript auto-descriptografável: a chave acompanha o ciphertext.
- Ofuscação como controle de acesso: dificulta manutenção e não bloqueia DevTools.
- Criptografia própria/blockchain: não resolve entrega de chave e amplia risco.
- Source map “hidden” publicado no npm: ainda distribui o conteúdo original.
