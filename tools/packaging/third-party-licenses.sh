#!/usr/bin/env bash
# Regenera THIRD_PARTY_LICENSES: el texto de licencia (y NOTICE) de Go y de cada módulo compilado en los binarios.
# Correr tras cambiar go.mod; tools/packaging/notice_test.go falla si falta un módulo.
set -euo pipefail
cd "$(dirname "$0")/../.."
# Mismo resultado en cualquier máquina: orden por bytes y la plataforma que se empaqueta.
export LC_ALL=C GOOS=linux
shopt -s nullglob nocaseglob
fmt='{{with .Module}}{{if not .Main}}{{.Path}} {{.Dir}}{{end}}{{end}}'
mods=$( { go list -deps -f "$fmt" ./cmd/...; go list -tags 'wails gtk3' -deps -f "$fmt" ./ui; } | sort -u)
seccion() { # nombre carpeta
  local files=("$2"/{LICEN[CS]E,COPYING,NOTICE}*)
  ((${#files[@]})) || { echo "sin archivo de licencia: $1 ($2)" >&2; exit 1; }
  printf '\n\n======== %s ========\n' "$1"
  for p in "${files[@]}"; do
    printf '\n--- %s ---\n\n' "${p##*/}"
    cat "$p"
  done
}
{
  echo "Licencias de Go y de los módulos compilados en macuahuitld, mctl y macuahuitl."
  echo "Las bibliotecas de JavaScript de la interfaz están en NOTICE. Generado por tools/packaging/third-party-licenses.sh."
  seccion "Go (runtime y biblioteca estándar)" "$(go env GOROOT)"
  while read -r path dir; do seccion "$path" "$dir"; done <<< "$mods"
} > THIRD_PARTY_LICENSES
echo "THIRD_PARTY_LICENSES: Go y $(wc -l <<< "$mods") módulos"
