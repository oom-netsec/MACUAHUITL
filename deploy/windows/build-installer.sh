#!/usr/bin/env bash
# Arma el instalador de Windows con NSIS (deploy/windows/macuahuitl.nsi). Corre en Linux (paquete nsis) o en Windows (Git
# Bash con NSIS). Uso:
#   VERSION=1.2.3 BIN=<carpeta> deploy/windows/build-installer.sh <instalador.exe>
# BIN trae macuahuitl.exe, macuahuitld.exe, mctl.exe y MicrosoftEdgeWebview2Setup.exe; el .ico se genera aquí.
# SIGN_CMD (opcional) es la orden de firma con %1 en lugar del archivo: sin ella el instalador sale sin firmar, que es lo
# decidido para la beta (ADR 0012, «Firma»). Así firmar después no obliga a rehacer nada.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${VERSION:?falta VERSION (X.Y.Z)}" "${BIN:?falta BIN}"
out=${1:?uso: VERSION=… BIN=… $0 instalador.exe}
v=${VERSION#v}
[[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "VERSION debe ser X.Y.Z: $VERSION" >&2; exit 1; }
for f in macuahuitl.exe macuahuitld.exe mctl.exe MicrosoftEdgeWebview2Setup.exe; do
  [[ -f $BIN/$f ]] || { echo "falta $BIN/$f" >&2; exit 1; }
done
go run ./tools/icowin "$BIN/macuahuitl.ico" deploy/packaging/icons/{16,24,32,48,64,128,256}/macuahuitl.png
# NSIS en Windows quiere rutas de Windows: pwd -W las da en Git Bash; en Linux no existe y se usa la normal.
abs() { (cd "$1" && { pwd -W 2>/dev/null || pwd; }); }
mkdir -p "$(dirname "$out")"
args=(-V2 -DVERSION="$v" -DBIN="$(abs "$BIN")" -DSRC="$(abs .)" -DOUT="$(abs "$(dirname "$out")")/$(basename "$out")")
[[ -n ${SIGN_CMD:-} ]] && args+=(-DSIGN="$SIGN_CMD")
makensis "${args[@]}" deploy/windows/macuahuitl.nsi
echo "instalador: $out"
