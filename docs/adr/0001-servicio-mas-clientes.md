# ADR 0001: Núcleo como servicio y clientes separados

Fecha: 2026-11-03 · Estado: aceptado

## Contexto

El brief exige separación estricta entre frontend y backend, arquitectura no monolítica y un programador de recolecciones. Una app de un solo binario detiene el programador al cerrar la ventana.

## Decisión

El núcleo `macuahuitld` corre como servicio de usuario de systemd. La UI de Wails y `mctl` son clientes sin estado propio.

## Consecuencias

Patrol corre con la UI cerrada y la frontera es real. A cambio hay más piezas que instalar, y los trabajos nocturnos requieren mantener la DEK en memoria durante una ventana acotada (ADR 0005).
