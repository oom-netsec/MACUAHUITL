#!/usr/bin/env bash
# Compila MACUAHUITL y abre la app con su núcleo. Uso: ./dev.sh        (compila y abre)
#                                                       ./dev.sh test   (corre todas las pruebas)
set -euo pipefail
cd "$(dirname "$0")"
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"

if [[ "${1:-}" == "test" ]]; then
  go test -race ./...
  go run ./tools/noegress/cmd/noegress ./...
  go run ./tools/archcheck/cmd/archcheck ./...
  (cd ui/frontend && npm test)
  echo "Pruebas en verde. Ojo: la prueba de empaquetado reescribe bin/; corre ./dev.sh para recompilar."
  exit 0
fi

echo "== compilando núcleo y CLI"
CGO_ENABLED=0 go build -trimpath -o bin/ ./cmd/...
echo "== compilando interfaz"
# npm ci solo si cambiaron las dependencias (npm deja su copia del lock en node_modules).
(cd ui/frontend && { [[ node_modules/.package-lock.json -nt package-lock.json ]] || npm ci; } && npm run build >/dev/null)
rm -f bin/macuahuitl # la prueba de empaquetado deja aquí un script que go build no sobrescribe
CGO_ENABLED=1 go build -tags 'wails gtk3' -trimpath -o bin/macuahuitl ./ui

# Lanzador e ícono en ~/.local para que GNOME (Wayland) muestre el macuahuitl y no el engrane genérico:
# lo busca por el app_id de la ventana (macuahuitl, ui/main.go). Se sobrescriben en cada corrida.
# Con el paquete instalado ya están en /usr/share y una copia de usuario los taparía.
if [[ -e /usr/share/applications/macuahuitl.desktop ]]; then
  :
elif [[ "$PWD" == *[\"\`\$\\%\|\&]* ]]; then
  echo "== sin lanzador en ~/.local: la ruta del repo tiene caracteres que el .desktop no admite tal cual"
else
  apps="$HOME/.local/share/applications" icons="$HOME/.local/share/icons/hicolor"
  sed "s|^Exec=.*|Exec=\"$PWD/bin/macuahuitl\"|" deploy/packaging/macuahuitl.desktop | install -Dm644 /dev/stdin "$apps/macuahuitl.desktop"
  install -Dm644 ui/frontend/public/favicon.svg "$icons/scalable/apps/macuahuitl.svg"
  for png in deploy/packaging/icons/*/macuahuitl.png; do
    n=$(basename "$(dirname "$png")")
    install -Dm644 "$png" "$icons/${n}x${n}/apps/macuahuitl.png"
  done
fi

# Reusa un núcleo que ya esté corriendo; si no hay, levanta uno y lo apaga al cerrar la app.
if ./bin/mctl vault status >/dev/null 2>&1; then
  echo "== usando el núcleo que ya está corriendo (si es de una compilación anterior, ciérralo y vuelve a correr esto)"
else
  echo "== levantando el núcleo (registro en bin/macuahuitld.log)"
  ./bin/macuahuitld >bin/macuahuitld.log 2>&1 &
  core=$!
  trap 'kill $core 2>/dev/null; wait $core 2>/dev/null' EXIT
  for _ in $(seq 50); do
    ./bin/mctl vault status >/dev/null 2>&1 && break
    kill -0 $core 2>/dev/null || { echo "el núcleo no arrancó:"; cat bin/macuahuitld.log; exit 1; }
    sleep 0.1
  done
fi

echo "== abriendo MACUAHUITL"
# Desde la terminal de VS Code (snap) se heredan esquemas y módulos GTK del snap y GTK aborta.
if [[ -n "${SNAP:-}" ]]; then
  unset GSETTINGS_SCHEMA_DIR GTK_PATH GTK_EXE_PREFIX GTK_IM_MODULE_FILE GIO_MODULE_DIR \
    GDK_PIXBUF_MODULE_FILE GDK_PIXBUF_MODULEDIR LOCPATH
  export XDG_DATA_DIRS="${XDG_DATA_DIRS_VSCODE_SNAP_ORIG:-/usr/local/share:/usr/share}"
fi
./bin/macuahuitl
