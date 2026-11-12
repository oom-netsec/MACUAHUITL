# ADR 0002: Wails con React y TypeScript para la UI

Fecha: 2026-11-03 · Estado: aceptado

## Contexto

Solo Linux. Se busca un binario ligero con UI web moderna, sin cargar un Chromium entero ni un runtime extra que auditar.

## Decisión

Wails, que usa WebKitGTK del sistema. Frontend en React + TypeScript + Vite, por React Flow (editor de ACLs) y TanStack Table (grillas de estado).

## Consecuencias

Depende de que WebKitGTK esté instalado. El frontend no hace llamadas de red; la CSP lo prohíbe.
