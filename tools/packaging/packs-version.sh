#!/usr/bin/env bash
# Exige versión mayor en cada paquete de packs/ que cambió desde el release anterior (núcleo v* o solo paquetes packs-*).
# Uso: tools/packaging/packs-version.sh <tag del release en curso>
set -euo pipefail
prev=$(git describe --tags --abbrev=0 --match 'v*' --match 'packs-*' "$1^" 2>/dev/null || true)
[ -z "$prev" ] && exit 0
for d in packs/*/; do
	git diff --quiet "$prev" -- "$d" && continue
	old=$(git show "$prev:${d}manifest.yaml" 2>/dev/null | sed -n 's/^version: *//p' || true)
	new=$(sed -n 's/^version: *//p' "${d}manifest.yaml")
	# mayor, no solo distinta: el núcleo rechaza instalar una versión igual o más vieja
	[ -z "$old" ] || { [ "$old" != "$new" ] && [ "$(printf '%s\n%s\n' "$old" "$new" | sort -V | tail -1)" = "$new" ]; } ||
		{ echo "::error::${d} cambió desde $prev sin subir version ($old -> $new)"; exit 1; }
done
