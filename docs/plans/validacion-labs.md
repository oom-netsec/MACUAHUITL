# Validación de paquetes en laboratorio

Runbook del día de laboratorio: correr **todos** los playbooks de cada paquete, una ronda, contra cuatro equipos, y
sacar por playbook lo que falló. Todo es de solo lectura (CheckDenied solo deja pasar `show` y similares).

| Equipo | Dirección | Paquete | Plataforma | Datos que piden sus playbooks |
|---|---|---|---|---|
| 9120 EWC (9800 embebido) | 192.168.3.3 | `oom/wlc-9800` | wlc-9800 | `mac` (un cliente), `ap` (un AP) |
| 3560CX (regresión) | 192.168.3.2 | `oom/ios` | ios | ninguno |
| DevNet NX-OS | `<HOST>:<PUERTO>` | `oom/nx-os` | nx-os | `ip`, `interface`, `mac` |
| DevNet Cat8000v | `<HOST>:<PUERTO>` | `oom/ios-xe` | ios-xe | ninguno |

Reglas que no cambian:

- 3560CX: `show` libres. 9120 EWC: **solo show**. Ningún paso de este runbook escribe en un equipo.
- DevNet sale a Internet: solo con el «listo» del dueño. Las credenciales están en la bóveda.
- La huella SSH de cada equipo la confirma el dueño antes de armar.
- El reporte puede traer líneas con secretos que el enmascarado no atrapó: **no lo pegues** en un PR, un issue ni nada
  público. Se comparte solo entre las sesiones locales.

## 1. Preparación (una vez)

Desde el checkout del repo, con el núcleo corriendo (`./dev.sh` o el paquete instalado, v0.4.7 o posterior).

```sh
mctl vault unlock
mctl pack list                      # qué paquetes y versiones hay

# Paquetes firmados del release (si `pack list` ya muestra la misma versión, sáltalo)
mkdir -p ~/MACUAHUITL/mpack && cd ~/MACUAHUITL/mpack
gh release download v0.4.7 -R oom-netsec/MACUAHUITL \
  -p 'oom-wlc-9800-*.mpack' -p 'oom-ios-[0-9]*.mpack' -p 'oom-nx-os-*.mpack' -p 'oom-ios-xe-*.mpack'
for f in oom-*.mpack; do mctl pack inspect "$f" && mctl pack install "$f"; done
cd -

# La versión instalada debe ser la de packs/*/manifest.yaml en el checkout: labcheck lee esos playbooks
mctl pack list
grep -H '^version' packs/{wlc-9800,ios,nx-os,ios-xe}/manifest.yaml

# Carpeta de salida: 0700 y fuera de /tmp (Ajustes → Almacenamiento lo exige)
D=~/MACUAHUITL/outputs/validacion-$(date +%Y%m%d)
mkdir -p -m 700 "$D"

# Credenciales por etiqueta: el job pide el ID de la bóveda
mctl cred list
SW=$(mctl cred list | awk '$2=="Sw" {print $1}')
DEVNET=$(mctl cred list | awk '$2=="<ETIQUETA_DEVNET>" {print $1}')   # la de DevNet
echo "Sw=$SW DevNet=$DEVNET"                                          # ninguno puede salir vacío

# IDs de todos los playbooks de un paquete (los ocultos con `pack items --hide` no salen)
ids() { mctl playbooks --platform "$1" | grep -F "[$2]" | awk '{print "  - " $1}'; }
ids ios oom/ios | wc -l              # 3560CX: 52 playbooks
```

Las variables (`D`, `SW`, `DEVNET`, `ids`) se usan en lo que sigue: todo va en la misma terminal.

### Datos de los playbooks que los piden

Un job con `params` que falten no se crea. Se sacan con un `show` (mismo `mctl run` de solo lectura; la primera vez
pide la huella, ver el paso 3):

```sh
# 9120 EWC: el nombre del AP (columna AP Name) y la MAC de un cliente conectado
mctl run -d 192.168.3.3 -c "show ap summary" -c "show wireless client summary" --cred "$SW"
# DevNet NX-OS: una IP de interfaz, una interfaz arriba y una MAC de la tabla
mctl run -d <HOST>:<PUERTO> -c "show ip interface brief vrf all" -c "show interface brief" \
  -c "show mac address-table" --cred "$DEVNET"
```

## 2. Un job.yaml por equipo

Cada bloque escribe su archivo con las variables ya resueltas. Sin `schedule` el job corre **una sola ronda**.
Los valores de `params` van entre comillas: un nombre de AP que sea solo
números se leería como número y el job no se crearía. `zip: ZIP_POLICY_NONE` deja los archivos sueltos, que es lo que lee labcheck. El enmascarado queda encendido, que es
lo que trae por defecto.

```sh
cat > "$D/job-9120.yaml" <<EOF
name: validacion-9120-ewc
targets:
  - address: 192.168.3.3
    device_id: ewc-9120
default_credential_id: $SW
output_dir: $D
zip: ZIP_POLICY_NONE
window_hours: 4
params:
  mac: "<MAC_DE_UN_CLIENTE>"
  ap: "<NOMBRE_DEL_AP>"
playbook_ids:
$(ids wlc-9800 oom/wlc-9800)
EOF

cat > "$D/job-3560cx.yaml" <<EOF
name: validacion-3560cx
targets:
  - address: 192.168.3.2
    device_id: sw-3560cx
default_credential_id: $SW
output_dir: $D
zip: ZIP_POLICY_NONE
window_hours: 4
playbook_ids:
$(ids ios oom/ios)
EOF

cat > "$D/job-devnet-nxos.yaml" <<EOF
name: validacion-devnet-nxos
targets:
  - address: <HOST>
    port: <PUERTO>
    device_id: devnet-nxos
default_credential_id: $DEVNET
output_dir: $D
zip: ZIP_POLICY_NONE
window_hours: 4
params:
  ip: "<IP_DE_UNA_INTERFAZ>"
  interface: "<INTERFAZ_ARRIBA>"
  mac: "<MAC_DE_LA_TABLA>"
playbook_ids:
$(ids nx-os oom/nx-os)
EOF

cat > "$D/job-devnet-c8000v.yaml" <<EOF
name: validacion-devnet-c8000v
targets:
  - address: <HOST>
    port: <PUERTO>
    device_id: devnet-c8000v
default_credential_id: $DEVNET
output_dir: $D
zip: ZIP_POLICY_NONE
window_hours: 4
playbook_ids:
$(ids ios-xe oom/ios-xe)
EOF

grep -c '^  - ' "$D"/job-*.yaml     # cuántos playbooks lleva cada uno; ninguno en 0
grep -l '<' "$D"/job-*.yaml          # quedó algún <...> sin reemplazar: corrígelo antes de crear
```

## 3. Crear, Login Test, huella, armar, una ronda

Por equipo, uno a la vez (ejemplo con el 9120; cambia el archivo para los demás):

```sh
ID=$(mctl job create -f "$D/job-9120.yaml") && echo "$ID"
mctl job logintest "$ID"
```

Si la huella ya se aceptó con `mctl run` (datos de los playbooks), el Login Test pasa a la primera: arma con
`mctl job arm "$ID"`, sin `--accept`, y sigue con `job watch`.

Si no, el Login Test falla en el paso de la llave de host y muestra
`fingerprint=SHA256:… (confirm it with: mctl job arm --accept SHA256:… ID)`.
**El dueño compara esa huella** con la del equipo (consola o la que ya tiene anotada). Solo si coincide:

```sh
mctl job arm --accept 'SHA256:…' "$ID"
mctl job watch "$ID"                 # progreso comando a comando; termina cuando el trabajo pasa a closed
```

Si el Login Test falla por otra cosa (credencial, prompt, plataforma), no armes: anota la línea de `FAILED` (`FALLA` con
`--lang es`) y pásala tal cual.

La ronda deja `"$D"/validacion-9120-ewc_AAAAMMDD-HHMMSS/` con `manifest.json` y una carpeta por equipo con
`r001_….txt`. Los playbooks de tech-support (`ctrl-tech-support` en el 9800 y `plat-tech-support*` en NX-OS)
tardan minutos: es normal que salgan como lentos.

## 4. Reporte por playbook

`tools/labcheck` lee la carpeta del job y los playbooks del paquete. No habla con el núcleo ni con los equipos.
Necesita el job cerrado, porque el `manifest.json` se escribe al final.

```sh
go run ./tools/labcheck -pack packs/wlc-9800 -lento 30s "$D"/validacion-9120-ewc_*        > "$D/reporte-9120.md"
go run ./tools/labcheck -pack packs/ios      -lento 30s "$D"/validacion-3560cx_*          > "$D/reporte-3560cx.md"
go run ./tools/labcheck -pack packs/nx-os    -lento 30s "$D"/validacion-devnet-nxos_*     > "$D/reporte-devnet-nxos.md"
go run ./tools/labcheck -pack packs/ios-xe   -lento 30s "$D"/validacion-devnet-c8000v_*   > "$D/reporte-devnet-c8000v.md"
```

Cada reporte trae:

- El estado del equipo según el manifest: completed o failed con su motivo, comandos e inválidos, y si se enmascaró
  con los conteos por tipo.
- Una sección por playbook con algún problema; los que salieron limpios solo se cuentan. Por comando:
  - `rechazado: …`: la línea de error en las primeras de la salida. Cuenta toda línea que empieza con `%`
    (`% Invalid`, `% Incomplete`, `% Ambiguous`, `% Permission denied`…), además de `Incorrect usage` (AireOS),
    `Syntax error`, `ERROR: %` (ASA/FTD) y `Command authorization failed` (AAA).
  - `incompleto`: el comando se cortó o falló.
  - `truncado al leer`: pasó el tope de lectura.
  - `salida vacía`.
  - `lento: N s`: el tiempo hasta el siguiente comando superó `-lento`. Es aproximado, a ±1 s.
  - `no corrió`: falta en la evidencia. Lo que el playbook marca para otra plataforma (`platforms:`) no se espera.
  - Un playbook que no está en `-pack` o cuyos datos no sirven sale con ese problema, nunca como limpio.
- **Fuera de playbook**: comandos de la evidencia que no son de ningún playbook dado. Si aparece algo aquí, revisa
  que `-pack` y la versión instalada coincidan.
- **Avisos**: lo que el lector no pudo leer entero, o la carpeta sin salidas (equipo que no conectó).
- **Posibles secretos sin enmascarar**: valores tras `password`, `secret`, `key-string`, `community`,
  `pre-shared-key`, `psk`, `key 7`, `message-digest-key`, `auth`/`priv 0x…` (SNMPv3), un hash `$n$…` o una llave
  privada, que no son `<MASKED:…>`. Son candidatos a revisar a mano: muchos son
  texto inocente («Password encryption…»). Uno real es un hueco de `internal/mask`.

Complemento con lo que mctl ya da: `mctl analyze "$D"/validacion-3560cx_*` corre las reglas de análisis (avisa de los
comandos rechazados que usan) y `mctl audit verify` confirma la cadena de auditoría del día.

## 5. Qué devolver

Los cuatro `reporte-*.md` y, de cada job, la línea de estado del equipo. Todo eso va a Backend/Release por la vía
local, nunca a GitHub. Con eso se corrigen los playbooks (comando rechazado → variante o `platforms:`), el driver
(incompleto, lento) o el enmascarado (secreto real), cada uno con su prueba.
