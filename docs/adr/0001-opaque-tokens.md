# ADR 0001: tokens opacos no 0.1

## Decisão

Access e refresh tokens serão opacos. Refresh é rotativo, stateful e vinculado
a uma família de sessão.

## Motivo

Revogação imediata, detecção de replay e contrato FFI menor são mais importantes
que eliminar um lookup. JWT e PASETO permanecem estratégias futuras.

## Consequência

Recursos protegidos consultam o session store ou um cache confiável. Escala será
tratada por adapter, não por remoção das garantias de revogação.

