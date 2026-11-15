#!/bin/sh
# Solo informa: el servicio es de usuario y lo activa cada ingeniero en su sesión. El texto va en inglés (lengua canónica).
set -e
command -v systemctl >/dev/null 2>&1 && systemctl --global daemon-reload >/dev/null 2>&1 || true
cat <<'MSG'
MACUAHUITL installed. For each user who will use it:
  systemctl --user enable --now macuahuitld
  then open MACUAHUITL from the applications menu, or run: mctl vault create
To let the core lock all of its memory, an administrator can create
/etc/systemd/user.conf.d/macuahuitl.conf with:
  [Manager]
  DefaultLimitMEMLOCK=infinity
Packet capture: install wireshark-common and add the user to the wireshark group.
Long Patrol jobs with the session closed: loginctl enable-linger <user>
MSG
