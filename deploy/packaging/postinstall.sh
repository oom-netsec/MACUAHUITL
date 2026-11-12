#!/bin/sh
# Solo informa: el servicio es de usuario y lo activa cada ingeniero en su sesión.
set -e
command -v systemctl >/dev/null 2>&1 && systemctl --global daemon-reload >/dev/null 2>&1 || true
cat <<'MSG'
MACUAHUITL instalado. Para cada usuario que lo use:
  systemctl --user enable --now macuahuitld
  mctl vault create
Para bloquear toda la memoria del núcleo, el administrador puede crear
/etc/systemd/user.conf.d/macuahuitl.conf con:
  [Manager]
  DefaultLimitMEMLOCK=infinity
Captura de paquetes: instala wireshark-common y agrega al usuario al grupo wireshark.
MSG
