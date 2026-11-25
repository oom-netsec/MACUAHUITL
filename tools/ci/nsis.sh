#!/usr/bin/env bash
# Busca makensis para los jobs de Windows del CI sin depender de choco (que da 503/504 y tumbaba todos los PR) e imprime la
# carpeta donde está, para agregarla al PATH:  d=$(tools/ci/nsis.sh "$RUNNER_TEMP/nsis"); export PATH="$PATH:$d"
#   1. el que ya trae la imagen del runner (en el PATH o en Program Files);
#   2. el zip portable oficial de NSIS con versión fija: el de la caché (actions/cache) o bajado, y en los dos casos con
#      su SHA256 verificado antes de extraerlo;
#   3. choco, solo si lo anterior falla.
# La versión y el hash cambian juntos; el md5 que publica SourceForge sirve para cotejar el SHA256 al subir de versión.
set -euo pipefail
ver=3.13
sha=ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8
url="https://downloads.sourceforge.net/project/nsis/NSIS%203/$ver/nsis-$ver.zip"
cache=${1:?uso: $0 <carpeta de la caché>}
command -v cygpath >/dev/null && cache=$(cygpath -u "$cache")

if m=$(command -v makensis); then dirname "$m"; exit 0; fi
for d in "/c/Program Files (x86)/NSIS" "/c/Program Files/NSIS"; do
  [[ -f $d/makensis.exe ]] && { echo "$d"; exit 0; }
done

zip=$cache/nsis-$ver.zip
ok() { [[ -f $zip ]] && echo "$sha  $zip" | sha256sum -c --quiet - >/dev/null 2>&1; }
mkdir -p "$cache"
if ! ok; then
  echo "NSIS $ver: no está en la caché o no cuadra su SHA256; se baja" >&2
  rm -f "$zip"
  curl -fsSL --retry 3 --retry-all-errors --max-time 180 -o "$zip" "$url" || echo "::warning::no se pudo bajar NSIS $ver" >&2
fi
if ok; then
  out=$cache/x
  rm -rf "$out" && mkdir -p "$out"
  if command -v unzip >/dev/null; then unzip -q "$zip" -d "$out"; else 7z x -y -bd -o"$out" "$zip" >/dev/null; fi
  [[ -f $out/nsis-$ver/makensis.exe ]] && { echo "$out/nsis-$ver"; exit 0; }
  echo "::warning::el zip de NSIS $ver no trae makensis.exe" >&2
elif [[ -f $zip ]]; then
  echo "::warning::el SHA256 de nsis-$ver.zip no cuadra; no se usa" >&2
  rm -f "$zip"
fi

echo "::warning::NSIS $ver portable no disponible; último recurso: choco" >&2
if choco install nsis -y --no-progress >&2; then
  for d in "/c/Program Files (x86)/NSIS" "/c/Program Files/NSIS"; do
    [[ -f $d/makensis.exe ]] && { echo "$d"; exit 0; }
  done
fi
echo "::error::no hay makensis: ni en el runner, ni el zip de NSIS $ver, ni choco" >&2
exit 1
