#!/usr/bin/env bash
# Regenera THIRD_PARTY_LICENSES: el texto de licencia (y NOTICE) de cada módulo Go compilado en los binarios.
# Correr tras cambiar go.mod; tools/packaging/notice_test.go falla si falta un módulo.
set -euo pipefail
cd "$(dirname "$0")/../.."
fmt='{{with .Module}}{{if not .Main}}{{.Path}} {{.Dir}}{{end}}{{end}}'
mods=$( { go list -deps -f "$fmt" ./cmd/...; go list -tags 'wails gtk3' -deps -f "$fmt" ./ui; } | sort -u)
{
  echo "Licencias de los módulos Go compilados en macuahuitld, mctl y macuahuitl."
  echo "Las bibliotecas de JavaScript de la interfaz están en NOTICE. Generado por tools/packaging/third-party-licenses.sh."
  while read -r path dir; do
    printf '\n\n======== %s ========\n' "$path"
    for f in $(cd "$dir" && ls | grep -iE '^(LICEN[CS]E|COPYING|NOTICE)' | sort); do
      printf '\n--- %s ---\n\n' "$f"
      cat "$dir/$f"
    done
  done <<< "$mods"
} > THIRD_PARTY_LICENSES
echo "THIRD_PARTY_LICENSES: $(wc -l <<< "$mods") módulos"
