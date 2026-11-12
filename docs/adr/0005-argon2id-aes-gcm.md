# ADR 0005: Argon2id + AES-256-GCM con jerarquía KEK/DEK

Fecha: 2026-11-03 · Estado: aceptado

## Contexto

Se necesita cifrado local fuerte, demostrable y con primitivas estándar.

## Decisión

KEK derivada con Argon2id; DEK aleatoria cifrada con la KEK; cada entrada cifrada con la DEK en AES-256-GCM con datos asociados. Formato en `docs/security/CRYPTO.md`.

## Consecuencias

Cambiar la contraseña maestra es barato. Perder la contraseña maestra hace la bóveda irrecuperable, de forma intencional.
