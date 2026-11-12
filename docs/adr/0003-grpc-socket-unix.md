# ADR 0003: gRPC sobre socket Unix entre clientes y núcleo

Fecha: 2026-11-03 · Estado: aceptado

## Contexto

Hace falta un contrato tipado, streaming en tiempo real y ningún puerto TCP abierto.

## Decisión

gRPC sobre `$XDG_RUNTIME_DIR/macuahuitl/core.sock`, permisos 0600 y verificación `SO_PEERCRED` del UID. Contratos en `api/proto/macuahuitl/v1`, validados con buf.

## Consecuencias

El auditor lee el contrato completo en un solo lugar. Los cambios incompatibles los detecta `buf breaking`.
