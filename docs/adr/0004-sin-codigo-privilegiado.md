# ADR 0004: Sin código propio con privilegios

Fecha: 2026-11-03 · Estado: aceptado

## Contexto

PCAP y escaneos SYN requieren capacidades de red. La primera idea fue un ayudante propio con `CAP_NET_RAW`.

## Decisión

No hay ayudante propio. Se usan `dumpcap` de Wireshark (grupo `wireshark`), `nmap` del sistema, `iperf3`, `tracepath` e ICMP sin privilegios. El núcleo los invoca sin shell con argumentos validados.

## Consecuencias

Ningún código del proyecto corre con privilegios. A cambio dependemos de que esas herramientas estén instaladas y configuradas.
