#!/usr/bin/env bash
# Artefactos de Windows de un release (ADR 0012, 43c): los tres .exe reproducibles, un zip con ellos y el instalador NSIS.
# Corre en Linux (compilación cruzada sin cgo: en Windows Wails usa WebView2 en Go puro). Uso:
#   deploy/windows/build-release.sh vX.Y.Z <carpeta de salida>
# Necesita ui/frontend/dist ya armado (go:embed de la app), makensis (paquete nsis) y zip.
set -euo pipefail
export TZ=UTC # zip guarda la hora local: en UTC el zip da los mismos bytes en cualquier huso
tag=${1:?uso: $0 vX.Y.Z OUT}
out=$(realpath -m "${2:?uso: $0 vX.Y.Z OUT}")
cd "$(dirname "$0")/../.."
v=${tag#v}
[[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "la versión debe ser vX.Y.Z: $tag" >&2; exit 1; }
[[ -f ui/frontend/dist/index.html ]] || { echo "falta ui/frontend/dist: arma la interfaz antes" >&2; exit 1; }

ld="-s -w -buildid= -X github.com/oom-netsec/MACUAHUITL/internal/version.Version=$tag"
# Sin consola: el núcleo y la app son -H windowsgui (el núcleo escribe su registro en State); mctl es de consola.
# Subshell ( ): el GOOS=windows no debe quedar para el resto del script (go run ./tools/icowin corre en Linux).
build() (
  rm -rf "$1" && mkdir -p "$1"
  export GOOS=windows GOARCH=amd64 CGO_ENABLED=0
  go build -trimpath -ldflags "$ld" -o "$1/mctl.exe" ./cmd/mctl
  go build -trimpath -ldflags "$ld -H windowsgui" -o "$1/macuahuitld.exe" ./cmd/macuahuitld
  go build -tags 'wails production' -trimpath -ldflags "$ld -H windowsgui" -o "$1/macuahuitl.exe" ./ui
  cd "$1" && sha256sum macuahuitl.exe macuahuitld.exe mctl.exe
)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Los tres son Go puro: dos compilaciones deben dar los mismos bytes, como macuahuitld y mctl en Linux.
build "$tmp/a" >"$tmp/a.sum" # una tras otra: si go build falla, set -e corta aquí y no en un cp confuso
build "$tmp/b" >"$tmp/b.sum"
diff "$tmp/a.sum" "$tmp/b.sum"
bin=$tmp/a

mkdir -p "$out"
zipdir=$tmp/macuahuitl_${v}_windows_amd64
mkdir "$zipdir"
umask 022 # permisos del zip que no dependen del umask de quien lo arma
cp "$bin"/{macuahuitl,macuahuitld,mctl}.exe "$zipdir/"
cp LICENSE NOTICE THIRD_PARTY_LICENSES TRADEMARK.md "$zipdir/"
# Fecha del commit y sin atributos extra: el zip sale igual en cada armado del mismo commit.
find "$zipdir" -exec touch -d "@${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}" {} +
(cd "$tmp" && find "$(basename "$zipdir")" -type f | LC_ALL=C sort | zip -X -q -D "$out/$(basename "$zipdir").zip" -@)

VERSION=$v BIN=$bin deploy/windows/build-installer.sh "$out/MACUAHUITL-$v-setup.exe"
