# Fixtures del asistente de upgrade

Salidas escritas a mano siguiendo el formato de la documentación pública de Cisco
(guías de upgrade de Catalyst 9600 e ISR 4000, referencia de comandos IOS-XE 17.x).
**Sin validar en laboratorio.** Hostnames, IPs (rangos de documentación), series y
hashes MD5 son inventados.

- `c9600-install-sso.txt`: formato de Patrol; modo install, supervisor redundante en SSO,
  imagen nueva ya copiada, configuración guardada.
- `isr4451-bundle.txt`: sesión pegada con prompts; modo bundle, sin redundancia, sin la
  imagen nueva, poco espacio y cambios sin guardar.
