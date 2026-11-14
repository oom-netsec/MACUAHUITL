#!/usr/bin/env bash
# Reglas de versión de packs/ para un release (núcleo v* o solo paquetes packs-*):
#  1. un paquete que cambió desde el release anterior sube a una versión mayor;
#  2. una versión ya etiquetada antes conserva su contenido. Se compara contra todos los tags anteriores, también los
#     de un release que falló: con eso un tag fallido no sirve para colar un cambio sin subir la versión.
# Uso: tools/packaging/packs-version.sh <tag del release en curso>
set -euo pipefail
ver() { git show "$1:$2manifest.yaml" 2>/dev/null | sed -n 's/^version: *//p' || true; }
prev=$(git describe --tags --abbrev=0 --match 'v[0-9]*' --match 'packs-*' "$1^" 2>/dev/null || true)
[ -z "$prev" ] && exit 0
tags=$(git tag --merged "$1^" -l 'v[0-9]*' 'packs-*')
for d in packs/*/; do
	new=$(sed -n 's/^version: *//p' "${d}manifest.yaml")
	if ! git diff --quiet "$prev" -- "$d"; then
		old=$(ver "$prev" "$d")
		# mayor, no solo distinta: el núcleo rechaza instalar una versión igual o más vieja
		[ -z "$old" ] || { [ "$old" != "$new" ] && [ "$(printf '%s\n%s\n' "$old" "$new" | sort -V | tail -1)" = "$new" ]; } ||
			{ echo "::error::${d} cambió desde $prev sin subir version ($old -> $new)"; exit 1; }
	fi
	for t in $tags; do
		[ "$(ver "$t" "$d")" = "$new" ] || continue
		git diff --quiet "$t" -- "$d" ||
			{ echo "::error::${d} $new ya existe en $t con otro contenido: sube la versión"; exit 1; }
	done
done
