# ADR 0006: SQLite con un driver en Go puro

Fecha: 2026-11-03 · Estado: aceptado

## Contexto

SQLite para metadatos y auditoría. Un driver con cgo complica la compilación reproducible.

## Decisión

`modernc.org/sqlite` en modo WAL, con migraciones versionadas.

## Consecuencias

Compilación sin cgo para el núcleo. Algo más lento que el driver en C, irrelevante para este volumen.
