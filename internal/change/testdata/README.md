# Fixtures de pre/post

`pre.txt` y `post.txt` siguen el formato de salida de Patrol y la documentación
pública de Cisco IOS-XE 17.x (show ip interface brief, show cdp/lldp neighbors detail,
show ip ospf neighbor, show ip bgp summary, show ip route summary, show mac
address-table, show ip arp, show standby brief, show spanning-tree root).
Escritas a mano, **sin validar en laboratorio**. IPs de rangos de documentación.

`post.txt` sale de `pre.txt` con: recarga (uptime corto) y versión nueva, Gi1/0/2
caída y Gi1/0/3 arriba, vecino CDP ACC-02 perdido y LLDP ACC-03 nuevo, OSPF con
192.0.2.3 en INIT, BGP 203.0.113.9 en Idle, menos rutas OSPF y BGP, MACs y ARP de la
VLAN 20 a la baja, HSRP del grupo 20 de Standby a Active, raíz STP de la VLAN 10
distinta y exec-timeout nuevo en la configuración (ntp clock-period cambia y se ignora).
