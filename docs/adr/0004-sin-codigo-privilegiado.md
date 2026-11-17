# ADR 0004: Sin código propio con privilegios

Fecha: 2026-11-03 · Estado: aceptado

## Contexto

PCAP y escaneos SYN requieren capacidades de red. La primera idea fue un ayudante propio con `CAP_NET_RAW`.

## Decisión

No hay ayudante propio. Se usan `dumpcap` de Wireshark (grupo `wireshark`), `nmap` del sistema, `iperf3`, `tracepath` e ICMP sin privilegios. El núcleo los invoca sin shell con argumentos validados.

## Consecuencias

Ningún código del proyecto corre con privilegios. A cambio dependemos de que esas herramientas estén instaladas y configuradas.

## Enmienda 2026-11-16: puertos estándar (decisión del dueño)

Alcance: los servidores de transferencia, Campo, syslog, traps y flujos. iperf3 server queda como estaba (sigue rechazando puertos menores de 1024 en Linux).

Un upgrade de IOS no usa puertos propios: el servidor de transferencias usa los estándar (TFTP 69, FTP 21, SCP/SFTP 22, HTTP 80).

- El código sigue sin privilegios: sin `setcap`, sin ayudante, sin binarios con capacidades. La unit de systemd tiene `NoNewPrivileges=yes` (que además ignora `setcap`) y no se toca.
- La app ya no rechaza los puertos menores de 1024 al validar: intenta el `bind` y lo decide el kernel. Si `net.ipv4.ip_unprivileged_port_start` es ≤ al puerto pedido, escucha.
- Con `EACCES` en Linux el error (`fileserve.err.port_denied`) trae la única orden a correr una vez: `echo 'net.ipv4.ip_unprivileged_port_start=N' | sudo tee /etc/sysctl.d/60-macuahuitl.conf && sudo sysctl --system`. N es el puerto que falló (cada servidor sugiere el suyo, mínimo 21); como bajar el umbral a N cubre todo lo de N para arriba, empezar por el más bajo que se use (21 o 69) deja los demás resueltos. Advierte que el cambio es persistente y que, desde N hasta el 1023, cualquier proceso sin privilegios, de cualquier usuario, podrá abrir esos puertos. Para deshacerlo: `sudo rm /etc/sysctl.d/60-macuahuitl.conf && sudo sysctl -w net.ipv4.ip_unprivileged_port_start=1024`. La redirección con nftables queda como alternativa.
- El paquete .deb NO instala ese sysctl: es decisión del usuario, que lo corre él.
- Con `EADDRINUSE` (por ejemplo el 22 con sshd) el error dice que otro servicio usa el puerto y que elija otro, sin la orden de sysctl.
- Windows (ADR 0012 h) no tiene puertos privilegiados: un `EACCES` allí es «otro proceso o el firewall lo impide», sin sysctl.
- Puertos por omisión que NO cambian: syslog 5514, traps 1162 y flujos 2055. No hay un equipo con una imagen que obligue a esos puertos (a diferencia del TFTP de IOS), son escuchas de larga duración que se abren sin ninguna orden previa, y cambiarlos haría fallar el arranque por omisión a quien no corrió el sysctl. Quien pasa un puerto explícito (514, 162) lo obtiene: ya no se rechaza y el `bind` decide, con el mismo error de arriba.
