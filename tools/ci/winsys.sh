#!/usr/bin/env bash
# golang.org/x/sys/windows solo en los paquetes de winSysOK (tools/archcheck/analyzer.go, ADR 0012), mirando también
# los archivos _windows.go que archcheck no carga en Linux. Usa go list -e, que no necesita compilar: hasta cerrar 43a,
# archcheck no puede correr con GOOS=windows sobre ./... (sys, ipc y diag aún no compilan). Se borra en 43a8.
set -euo pipefail
ok='^github.com/oom-netsec/MACUAHUITL/(internal/sys|internal/ipc|internal/diag|internal/diag/serialcon|internal/core/power|ui)$'
bad=$(GOOS=windows go list -e -tags wails -f '{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... |
	awk '{ for (i = 2; i <= NF; i++) if ($i == "golang.org/x/sys/windows" || index($i, "golang.org/x/sys/windows/") == 1) { print $1; break } }' |
	{ grep -Ev "$ok" || true; })
if [[ -n $bad ]]; then
	echo "golang.org/x/sys/windows fuera de los paquetes permitidos (ADR 0012):"
	echo "$bad"
	exit 1
fi
