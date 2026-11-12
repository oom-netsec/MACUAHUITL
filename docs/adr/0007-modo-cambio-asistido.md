# ADR 0007: Modo de cambio asistido

Fecha: 2026-11-05 · Estado: aceptado

## Contexto

MACUAHUITL nació de solo lectura: observa, valida y compara. El dueño quiere que la herramienta sirva para todo el trabajo diario, no solo para leer: aplicar configuración en lote, snippets, aprovisionar puertos, restaurar respaldos, rotar credenciales, ejecutar upgrades, aplicar rollback, aislar nodos (GIR), EEM temporal e inyectar tramas de prueba.

## Decisión

Esas funciones viven en un **modo de cambio asistido**, separado del producto de solo lectura:

- Apagado por defecto. Se habilita por ejecución, nunca de forma global ni permanente.
- Cada cambio muestra el comando exacto y pide confirmación paso a paso. Nada corre sin que el ingeniero lo vea.
- Todo cambio lleva pre-check, post-check y reversa definida antes de empezar. Sin reversa no se ejecuta.
- `write memory` solo si el plan lo pide, al final y confirmado. Sin él, la ejecución termina en un paso de cierre: el ingeniero deja el cambio solo en la configuración en ejecución o pide la reversa de todos los equipos. Si nadie decide en el tope de espera (o el núcleo se apaga), la ejecución queda `abandoned` con el cambio solo en ejecución, y el aviso dice qué equipos quedaron cambiados.
- Tras la reversa, el núcleo relee el running-config de la línea base y lo compara sin importar el orden: si quedó una línea que el equipo agregó solo al aplicar (p. ej. `spanning-tree portfast edge` con la VLAN de voz) o falta una, la ejecución no se da por `rolled-back`: se detiene con las líneas que sobran o faltan y ofrece reintentar la reversa o abortar.
- `mctl` sale con código distinto de 0 en todo lo que no sea `done`, también tras una reversa completa: el cambio pedido no quedó aplicado y un guion no debe tomarlo por éxito.
- Usa la ventana de la bóveda, el EgressGuard y la auditoría. La auditoría registra cada comando de cambio y su resultado.
- La política de comandos de Patrol (`CheckDenied`) no se relaja. El modo asistido tiene su propia lista cerrada de operaciones permitidas por función.
- El generador de tramas no agrega código privilegiado (ADR 0004 sigue vigente). Funciona solo si el usuario otorga la capacidad al binario de forma explícita, y la app lo explica.

## Consecuencias

Patrol, el análisis y las herramientas siguen siendo de solo lectura. El riesgo de cambiar la red queda en un camino explícito, auditado y con reversa. Cada función que use este modo documenta su lista de operaciones en su plan de fase.
