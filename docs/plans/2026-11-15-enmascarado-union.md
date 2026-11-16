# Enmascarado de comandos abreviados sin regresiones (v0.6.6)

Estado: diseño revisado; base para la implementación y referencia para reglas futuras.

## Por qué

La v0.6.5 (main 100652c) enmascara bien la configuración tal como la imprime el equipo y las formas completas de los comandos. Lo que deja pasar son los comandos **abreviados** tecleados en la terminal o citados por los logs del equipo (CFGLOG, archive, accounting, ASA 111008/10, el texto citado de show tech). Por ejemplo: `enable secret lev 15 X`, `snmp-s ho IP X`, `tacacs-ser k X`.

`mask.Command` (rama fix-mask-r3) tapa todo lo que sigue a la primera palabra clave de secreto, por prefijo. Las cinco rondas fallaron al **combinarlo** con las reglas de la v0.6.5: cada forma de mezclar las dos cadenas dejó ver algo que la v0.6.5 tapaba.

## Garantía

**Todo lo que la v0.6.5 deja visible es un superconjunto de lo que deja visible la versión nueva.** Lo nuevo solo puede tapar más, nunca menos. La garantía sale de la construcción, no de las pruebas: las pruebas la vigilan.

## Construcción: corte sobre S1

Para cada texto que hoy pasa por la cadena de la v0.6.5:

1. **S1** es la salida exacta de la v0.6.5. El código actual de `internal/mask`, la terminal y syslogd **no se modifica**: se llama igual que hoy.
2. **Los tramos de M₂** se calculan sobre el **texto original** con `mask.Command` (por segmento ` ; `). Cada segmento da como mucho un tramo [s, t), que va de la palabra clave hasta el fin del segmento.
3. **La salida** es S1 con la región correspondiente reemplazada por un solo `<MASKED:secret>`:
   - `c = min(s, lcp(orig, S1))`, donde lcp es el prefijo común;
   - `c' = max(len(S1) − (len(orig) − t), len(S1) − lcs(orig, S1))`, donde lcs es el sufijo común;
   - c y c' se ajustan **hacia afuera** hasta no partir un `<MASKED:…>`;
   - salida = `S1[:c] + "<MASKED:secret>" + S1[c':]`.
   
   Con varios segmentos: si el original y S1 tienen la misma cantidad de separadores ` ; `, se corta por segmento; si no, un solo corte desde el primer s hasta el último t.
4. Como la salida es S1 con una región reemplazada, todo lo que S1 tapa sigue tapado. La función vive **en un solo lugar** (`internal/mask/union.go`, `cut(orig, s1 string, spans [][2]int) string`) y la usan todas las vías.

**Lo que se acepta perder:**
- tapar de más cuando la v0.6.5 cambió algo a la izquierda de la palabra clave (por ejemplo una URL con credencial antes de `password`): se tapa desde ahí;
- el tipo específico del marcador, porque el tramo cortado queda como `secret`.

`counts` (patrol/output.go) = las cuentas de la v0.6.5, más 1 `secret` por cada corte que no estaba ya tapado del todo.

## Dónde se aplica M₂

Solo a texto que es un **comando** (tecleado o citado), nunca a la configuración impresa (salidas de `show`):
- **Comandos citados en logs:** CFGLOG (`logged command:`), archive, accounting `:cmd=`, `CMD: '…'`, ASA 111008/10, diff `+/-` y `mask.Cmd`. Se usa un detector **sobre el original** con las mismas expresiones de la v0.6.5 (mask.go ~674-716) para saber qué parte de la línea es el comando citado.
- **Texto entre comillas** (show tech de ASA, `ERROR: "…"`): sobre el texto citado del original. Con comillas impares, también a todo lo que sigue a la primera comilla, como hace la v0.6.5.
  - **Lista negra de prosa:** no se aplica M₂ si la palabra que sigue a la palabra clave es `mismatch`, `failed`, `expired`, `rejected`, `changed`, `will`, `is`, `has`, `for` o `from` (token completo, sin distinguir mayúsculas, solo en esta vía).
  - La lista nunca resta a S1: como mucho deja visible lo que la v0.6.5 ya dejaba visible.
- **Terminal, lo tecleado en modo config y su eco:** con el bloque del prompt (`CommandIn`).

`mask.Command` necesita una API de tramos: `commandSpans(block, cmd string) [][2]int`, que devuelve [s, t) en el original. La lógica de combinación de r3 que está dentro de `CommandIn` (que mete `maskLine` a la izquierda) se descarta.

## Terminal

- **Todo el estado y toda decisión se toman con S1, como hoy:** `cont`, `sent`, `acc`, `pi`, el prompt débil, el stream de PEM y la elección de `sq`. M₂ solo posprocesa la cadena que se **emite**.
- **Tapa por contenido, dos listas separadas, cada una con su tope:**
  - **M₁:** lo que recuerda hoy `noteSecrets`, sin tocarlo (tramo completo, ≥4 caracteres);
  - **M₂:** los valores de `SecretValues` de r3, con el primero que pasa el filtro tras saltar estructurales con su operando. Por ejemplo, en `enable secret lev 15 X` el valor es X.
- Primero corre la tapa de la v0.6.5. La de M₂ corre después y nunca dentro de un `<MASKED:…>`.

## Syslogd

S1 es la salida completa de la v0.6.5 con sus dos pasadas (`maskRaw`). M₂ se calcula sobre el mensaje normalizado (`norm(raw)`), y el corte se hace al final, sobre S1.

## Pruebas (permanentes)

- **Oráculo:** una copia congelada de la v0.6.5 (mask.go, el command.go viejo y la parte de enmascarado del recorder y de syslogd) en un paquete solo de pruebas, `internal/mask/internal/ref065`. No es un golden estático.
- **Propiedad diferencial, en todas las vías** (Apply, Stream, Typed/Prompted, terminal con troceo aleatorio por semilla, sesiones de varias líneas y pegado, y syslogd): **todo marcador `Zq#####` visible en la salida nueva también es visible en ref065**. Es la garantía.
- **Ningún valor visible** en las vías de comando: los 13 canales de `canales_test.go` (r3), más un segundo generador independiente (≥170 plantillas, 18 vías) con:
  - valores con `"`, `'`, `\` y espacios;
  - primeras palabras sin lista (`sntp`, `vpdn-group`, `l2tp-class`, `smtp-server`, `macsec`, `lisp`, `site`, `repository`, `webauth`, `dialer`, `group-policy`);
  - ` ; `;
  - sha256 y `peer`.
- **Idempotencia:** `Apply(Apply(x)) == Apply(x)`.
- **Negativos:** `show run | sec snmp` y todo filtro tras `|`, `set/match community`, `pri N`, `tunnel key N`, `ntp server IP key N`, y la prosa de la lista negra.
- **Mutaciones:** quitar el corte, o calcular M₂ sobre S1 en vez del original, hace fallar la propiedad diferencial.
- **Pruebas exactas existentes** que cambien con M₂: solo se actualizan si la nueva tapa un superconjunto, comprobado con el helper diferencial y nunca a mano.

## Cómo agregar una regla nueva sin romper la garantía

- Una regla para **configuración impresa** se agrega a la cadena de la v0.6.5, es decir, a S1. ref065 no cambia, así que la propiedad diferencial sigue valiendo, porque solo puede tapar más.
- Una palabra clave para **comandos tecleados** se agrega a `mask.Command`. El corte solo puede tapar más.
- **Nunca** se cambia ref065, salvo para congelar una versión publicada nueva como oráculo, y entonces con su propia revisión.

## Riesgos y límites

- **Consumidores que comparan texto enmascarado:** drift.go:132/139, backup/diff.go:83, compliance.go:131 y assist/run.go:1095. Tapar de más en líneas con comillas (EEM `cli command "…"`) puede cambiar su resultado. Lleva prueba.
- **`key N` en un key chain** solo se reconoce con el bloque `keychain`. En un log, `key 1` se tapa: es tapado de más aceptado.
- **Rendimiento:** dos pasadas (v0.6.5 y Command) más el corte, que es lineal. Va con un benchmark contra ref065 en el PR.

## Notas de la segunda auditoría (antes de la v1.0.0)

- **Resto de un eco con `#` o `>` en el secreto** (`Pa55w0rd#Xq7z9`, `Cisco>Admin123`): con el eco partido por un syslog, el resto se leía como un prompt y quedaba el prefijo visible. Ahora un estado aparte (`esent`, `eacc`, `epart`, `eshift`; no lo leen ni escriben las decisiones de la v0.6.5: `sent`, `pi`, `acc`, `cont` y la red por contenido corren idénticos) reconoce el resto de un eco pendiente contra todas las líneas enviadas (también con el eco desplazado con `$` y partido más de una vez), y solo al final la línea emitida se tapa como `<MASKED:secret>`: la salida es S1 con más tapado. Un diferencial de la terminal contra ref065 con salida posterior vigila que ningún 4-grama del valor se vea más veces que en la v0.6.5. Prueba por bytes (ningún 4-grama del valor) en todas las posiciones de corte, pegado y carácter a carácter.
- **Espacios Unicode** (NBSP, U+2009, U+202F, U+3000, U+1680, U+0085…; y ZWSP/ZWNJ/ZWJ/U+2060/BOM como espacio): `normSpaces` (span.go) hace una copia con cada uno cambiado por tantos espacios ASCII como bytes ocupa, y los tramos de M₂ se calculan sobre el original y sobre esa copia y se juntan (IOS toma el NBSP como parte del token, así que un valor puede llevarlo adentro); el corte se aplica sobre S1 con los mismos índices. Solo M₂: las reglas de la v0.6.5 (configuración impresa, p. ej. `api-key X`, `crypto pki export … terminal 3des X`) no ven esos espacios y siguen igual. `SecretValues` también salta los algoritmos exactos (`sha1`, `hmac-sha256`, `aes-128`…), no cualquier palabra que empiece con sha, aes o hmac.

## Cierre de los hallazgos medios (antes de la v0.7.0)

Todo va como cortes M₂ sobre S1 o como tapado al final de lo que se emite; ref065 y la cadena de reglas no cambian. Pruebas en `internal/mask/medios_test.go` y `internal/platform/iosxe/memoria_test.go`.

- **a. « | » y « ; » dentro de un secreto.** Tras una palabra de secreto no hay filtro: el valor llega al fin del segmento aunque haya una barra (el filtro solo se respeta antes de la palabra, y los `show` ya salen antes). Donde la plataforma no separa con « ; » (todas menos `nx-os` e `ise`, y la desconocida, que es la de la terminal) el primer tramo se alarga hasta el fin de la línea; se sigue evaluando por segmento para reconocer el primer comando de cada uno. Límite: en NX-OS e ISE un « ; » dentro del valor es indistinguible de un separador de comandos y lo que sigue queda como otro comando.
- **b. Comilla dentro del valor en `ERROR: "…"`.** `quoteTail`: si las reglas tapan algo dentro de la cita y tras ese punto quedan al menos dos comillas, se tapa hasta la última (o hasta el fin si la última va pegada a texto y no cierra la cita). Una sola comilla tras el cambio es el cierre normal y no se toca (la prosa citada no cambia).
- **c. ASA 111008/111010 sin `' command.`.** `cmdSyslogOpen`: sin cierre, el comando citado va hasta el fin de la línea.
- **d. `+NO …`, `+ENABLE …`, BOM.** `diffLineM2` (solo M₂), con mayúsculas y BOM.
- **e. Secreto tipo 0 de varias palabras con el eco partido.** M₂ recuerda cada palabra del valor (`SecretValues` ya no se detiene tras la primera) y, aparte, el resto de un eco partido se tapa por posición: `echoCover` mira desde dónde empieza el secreto de la línea tecleada (`mask.SecretStart`) y `mask.CutFrom` corta desde ahí. No se tocan `sent`, `pi`, `acc` ni `cont`. De 162 de 368 posiciones con fuga a 0 (prueba por bytes en cada corte, uno y dos cortes, con y sin `$`).
- **f. Abreviaturas y citas de avisos.** `tac k X` y `rad k X` (mínimo 3 letras); `session-key` es palabra de secreto; `% Ambiguous command`, `% Invalid input detected`, `error:`/`warning:`/`info:` en cualquier caja y las comillas simples reciben M₂ como `ERROR:`. `% Incomplete command "key "` queda fuera a propósito: cita un comando sin valor y tapar ahí cambiaba la salida normal. Las abreviaturas `ena`, `usern`, `snmp-s`, `cry isa` ya las cubría la búsqueda por prefijo de las palabras de secreto.
- **g. Espacios Unicode en configuración impresa.** `LineS1` corre la misma cadena (con el estado de antes de la línea) sobre una copia con cada espacio Unicode cambiado por un solo espacio ASCII (`normOne`, con la tabla de desplazamientos); lo que tapa se lleva a las coordenadas del original (`twinSpans`) y se corta sobre S1. Lo mismo en `CutText`, `Cmd` y `CutCommand`. Límite: en `CutCommand` la copia corre sin plataforma (la terminal no la conoce), así que una forma solo de ASA con espacio Unicode tecleada no se ve por esta vía (sí por la de líneas de salida).
- **h. Valor de varias palabras repetido más tarde.** La red M₂ de la terminal no vence con el prompt sin pendientes cuando el valor viene de un secreto de varias palabras (la M₁ y los valores de una sola palabra siguen la ventana de la v0.6.5); vence por las 50 líneas. La prueba de aceptación `TestSecretoDeVariasPalabrasRepetidoDespues` cubre los seis comandos, pegado, carácter a carácter y eco partido, con y sin `$`. `standby N authentication X` (y `glbp`) tapa el valor. Límite: un trozo del interior de un valor, sin límites de palabra, en una línea posterior no se persigue (tampoco en la v0.6.5).
- **i. Driver (iosxe).** Medido: cerrar una salida de 64 MiB asignaba 5,98 veces su tamaño en copias de `clean(string(buf))`. `cleanBuf` limpia por trozos que terminan en salto de línea (ninguna expresión de `clean` cruza uno) y, sin borrados ni `--More--` en el trozo, solo quita los `\r` directo al `strings.Builder`: 1,00 veces. La prueba fija el tope en 2,5 veces (8 MiB con -short o -race) y otra comprueba que `cleanBuf` da lo mismo que `clean` con ruido y trozos que cortan en cualquier parte.
