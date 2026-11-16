#!/usr/bin/env bash
# Arma el instalador de Windows con NSIS (deploy/windows/macuahuitl.nsi). Corre en Linux (paquete nsis) o en Windows (Git
# Bash con NSIS). Uso:
#   VERSION=1.2.3 BIN=<carpeta> deploy/windows/build-installer.sh <instalador.exe>
# BIN trae macuahuitl.exe, macuahuitld.exe y mctl.exe; el .ico se genera aquí. WebView2 no se empaqueta (ADR 0012).
# SIGN_CMD (opcional) es la orden de firma con %1 en lugar del archivo: sin ella el instalador sale sin firmar, que es lo
# decidido para la beta (ADR 0012, «Firma»). Así firmar después no obliga a rehacer nada.
set -euo pipefail
: "${VERSION:?falta VERSION (X.Y.Z)}" "${BIN:?falta BIN}"
out=${1:?uso: VERSION=… BIN=… $0 instalador.exe}
# BIN y la salida se resuelven desde donde se llamó, antes de ir a la raíz del repo.
BIN=$(realpath "$BIN") out=$(realpath -m "$out")
cd "$(dirname "$0")/../.."
v=${VERSION#v}
[[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "VERSION debe ser X.Y.Z: $VERSION" >&2; exit 1; }
for f in macuahuitl.exe macuahuitld.exe mctl.exe; do
  [[ -f $BIN/$f ]] || { echo "falta $BIN/$f" >&2; exit 1; }
done
go run ./tools/icowin "$BIN/macuahuitl.ico" deploy/packaging/icons/{16,24,32,48,64,128,256}/macuahuitl.png
# NSIS en Windows quiere rutas de Windows: pwd -W las da en Git Bash; en Linux no existe y se usa la normal.
abs() { (cd "$1" && { pwd -W 2>/dev/null || pwd; }); }
mkdir -p "$(dirname "$out")"
args=(-V2 -DVERSION="$v" -DBIN="$(abs "$BIN")" -DSRC="$(abs .)" -DOUT="$(abs "$(dirname "$out")")/$(basename "$out")")
[[ -n ${SIGN_CMD:-} ]] && args+=(-DSIGN="$SIGN_CMD")
# Solo la prueba del borrado de datos (test-installer.ps1); un release nunca lo pasa.
[[ -n ${TEST_DELETE_DATA:-} ]] && args+=(-DTEST_DELETE_DATA)
makensis "${args[@]}" deploy/windows/macuahuitl.nsi
echo "instalador: $out"
