# Guía para auditores

Cómo verificar cada promesa de [SECURITY.md](../../SECURITY.md) sin confiar en nuestra palabra. Los comandos marcados *(Fase N)* existirán al terminar esa fase.

## 1. Ninguna credencial en claro a disco

- Lee el formato en [CRYPTO.md](CRYPTO.md) y compáralo con `internal/vault`.
- Corre la prueba de no-filtración *(Fase 1)*: `go test ./test/e2e/ -run TestNoLeak`. Crea una bóveda con una contraseña marcador aleatoria, corre un Patrol completo contra el simulador y busca el marcador en bruto, en base64 y en hex en todos los archivos que tocó la app.
- Por tu cuenta: crea una credencial con un valor único y busca ese valor con `grep -r` en `~/.local/share/macuahuitl`, `~/.local/state/macuahuitl`, `~/.config/macuahuitl` y la carpeta de outputs.

## 2. Ninguna credencial en logs, auditoría, outputs ni volcados

- Revisa que todo secreto use el tipo `Secret` de `internal/secret` y que sus métodos `String`, `Format`, `MarshalJSON` y `LogValue` devuelvan `[REDACTED]`.
- La misma prueba de no-filtración cubre logs, SQLite y outputs.
- Volcados: con el núcleo corriendo, `prlimit --pid $(pidof macuahuitld) --core` debe mostrar `0`. Además `stat -c %U /proc/$(pidof macuahuitld)/mem` debe mostrar `root`: es el efecto de `PR_SET_DUMPABLE=0`, que impide a otros procesos del usuario leer su memoria sin ptrace.

## 3. Solo destinos escritos por el ingeniero

- **Estático:** `go run ./tools/noegress/cmd/noegress ./...` debe salir con código 0. Prohíbe fuera de los paquetes permitidos: la familia `net/` (salvo `net/netip`, `net/url` y `net/mail`), `golang.org/x/net/...`, `crypto/tls`, `log/syslog`, `syscall`, `golang.org/x/sys/unix`, `os/exec`, cgo (`import "C"`), `golang.org/x/crypto/ssh` y la raíz de gRPC.
- **Paquetes permitidos:** `internal/transport`, `internal/diag` e `internal/ipc` tienen la red del producto; léelos completos. `internal/sys` usa `golang.org/x/sys/unix` solo para `prctl`, `setrlimit` y `mlockall`; léelo completo, es corto. `gen/` es código generado de gRPC que también va en el binario. `test/simulator` y `tools/` no van en el binario.
- **Límites del análisis estático:** no ve `os.StartProcess`, ni el código de dependencias externas, que se revisan con `go list -deps ./cmd/...` y `govulncheck`. Una verificación transitiva de dependencias llega en la Fase 6.
- **Sin telemetría:** `grep -rn "http" --include=*.go internal/ cmd/` no debe mostrar URLs fijas.
- **En ejecución *(Fase 1)*:** corre un trabajo y observa con `ss -tnp | grep macuahuitld` o con un firewall de salida. Solo deben aparecer los destinos del trabajo. Los intentos rechazados por `EgressGuard` aparecen en la auditoría.
- **Herramientas externas *(Fase 4)*:** cada ejecución de nmap, ping, traceroute, iperf3 o dumpcap queda en la auditoría con su línea de argumentos completa.

## 4. La contraseña maestra nunca se guarda

- En [CRYPTO.md](CRYPTO.md) no hay ningún campo que la contenga ni un hash de ella. Solo la sal y los parámetros de Argon2id.
- La DEK cifrada es la única forma de comprobar que la contraseña es correcta: si GCM falla, la contraseña es incorrecta.

## 5. El binario corresponde al código

Cada release en GitHub publica `SHA256SUMS`, `BUILD-INFO.txt` (versión de Go, tag y commit), un SBOM en SPDX y los paquetes. Para reproducir el núcleo y la CLI:

```sh
git checkout vX.Y.Z
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -buildid= -X github.com/oom-netsec/MACUAHUITL/internal/version.Version=vX.Y.Z" -o verif/ ./cmd/macuahuitld ./cmd/mctl
sha256sum verif/macuahuitld verif/mctl   # deben coincidir con SHA256SUMS del release
```

Hace falta la misma versión de Go que dice `BUILD-INFO.txt`. La UI (`macuahuitl`) se compila con cgo contra WebKitGTK y no es reproducible byte a byte; su suma se publica igual. CI compila el núcleo dos veces en cada push y falla si las sumas difieren.

## 6. Integridad del log de auditoría

- *(Fase 1)* `mctl audit verify` recorre la cadena y reporta el primer registro roto.
- Cada `manifest.json` entregado incluye el hash de cabeza de la cadena en ese momento. Compara ese valor con el registro correspondiente del log.
