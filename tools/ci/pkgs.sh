#!/usr/bin/env bash
# Reparte los paquetes de Go entre los jobs de CI: core, rest y mask cubren ./... exactamente una vez.
# Uso: tools/ci/pkgs.sh core|rest|mask|check
set -euo pipefail
core='^(internal/core|internal/platform|cmd|internal/service)(/|$)'
mask='^internal/mask(/|$)'
mod=$(go list -m)
grupo() { # imprime «grupo<TAB>paquete» por cada paquete
  go list ./... | while read -r p; do
    r=${p#"$mod"/}; [[ "$p" == "$mod" ]] && r=.
    if [[ $r =~ $mask ]]; then g=mask; elif [[ $r =~ $core ]]; then g=core; else g=rest; fi
    printf '%s\t%s\n' "$g" "$p"
  done
}
case "${1:-}" in
  core|rest|mask) grupo | awk -F'\t' -v g="$1" '$1==g{print $2}' ;;
  check) # cada paquete en un solo grupo y ningún grupo vacío
    diff <(grupo | cut -f2 | sort) <(go list ./... | sort -u) >&2 || { echo "paquetes sin grupo o repetidos" >&2; exit 1; }
    for g in core rest mask; do [[ -n $("$0" "$g") ]] || { echo "grupo vacío: $g" >&2; exit 1; }; done ;;
  *) echo "uso: $0 core|rest|mask|check" >&2; exit 2 ;;
esac
