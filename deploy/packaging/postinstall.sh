#!/bin/sh
# Solo informa: el servicio es de usuario y lo activa cada ingeniero en su sesión. El texto va en inglés (lengua canónica).
set -e
cat <<'MSG'
MACUAHUITL installed. For each user who will use it:
  systemctl --user enable --now macuahuitld
  then open MACUAHUITL from the applications menu, or run: mctl vault create
To let the core lock all of its memory, an administrator can create
/etc/systemd/system/user@.service.d/macuahuitl.conf with:
  [Service]
  LimitMEMLOCK=infinity
and then reboot.
Packet capture: install wireshark-common (Debian/Ubuntu) or wireshark-cli (Fedora)
and add the user to the wireshark group.
Long Patrol jobs with the session closed: loginctl enable-linger <user>
MSG
