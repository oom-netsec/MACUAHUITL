# Criptografía de la bóveda

Referencia: diseño §10.2–§10.4. Solo primitivas estándar: `crypto/aes`, `crypto/cipher`, `crypto/rand`, `golang.org/x/crypto/argon2`.

## Jerarquía de llaves

```
contraseña maestra ──Argon2id(sal, m, t, p)──► KEK (32 B)
                                                │
                                   AES-256-GCM  ▼
DEK (32 B aleatorios) ◄──── descifra ──── DEK cifrada (en el encabezado)
   │
   └── AES-256-GCM ──► cada entrada de credencial
```

- Cambiar la contraseña maestra solo vuelve a cifrar la DEK.
- La KEK existe solo mientras se descifra la DEK y se borra enseguida.

## Formato de `vault.mcv` (versión 1)

Todos los enteros en big-endian.

| Desplazamiento | Tamaño | Campo |
|---|---|---|
| 0 | 4 | Mágico `MCV1` (`0x4D 0x43 0x56 0x31`) |
| 4 | 2 | Versión de formato = 1 |
| 6 | 16 | ID de bóveda (aleatorio) |
| 22 | 4 | Argon2id memoria en KiB |
| 26 | 4 | Argon2id iteraciones |
| 30 | 1 | Argon2id hilos |
| 31 | 16 | Sal |
| 47 | 12 | Nonce de la DEK cifrada |
| 59 | 48 | DEK cifrada (32 B + etiqueta GCM de 16 B) |
| 107 | 4 | Número de entradas N |
| 111 | … | N entradas |

Datos asociados de la DEK cifrada: los bytes 0–46 del encabezado. Cambiar cualquier parámetro invalida la DEK.

### Entrada

| Tamaño | Campo |
|---|---|
| 16 | ID de entrada (aleatorio) |
| 12 | Nonce |
| 4 | Longitud L del texto cifrado, incluida la etiqueta GCM de 16 bytes (L ≥ 16) |
| L | Texto cifrado + etiqueta GCM |

- Datos asociados: ID de bóveda (16 B) ‖ ID de entrada (16 B) ‖ versión de formato (2 B, big-endian).
- Texto en claro: 6 campos `uint32 longitud (big-endian) ‖ bytes`, en orden etiqueta, usuario, contraseña, enable, llave SSH y uno reservado vacío. Todo va cifrado, incluida la etiqueta. Se eligió este formato y no Protocol Buffers para no depender de código generado dentro del paquete criptográfico y poder borrar cada campo de memoria.
- El nonce es aleatorio de 96 bits y se renueva en cada escritura de la entrada. Con el volumen de una bóveda individual, el riesgo de colisión es despreciable.

## Validación al leer

Antes de derivar cualquier llave, el archivo se rechaza como dañado si:

- mide menos de 111 bytes, el mágico no es `MCV1` o la versión no es 1;
- la memoria de Argon2id está fuera de [256 MiB, 4 GiB], las iteraciones fuera de [1, 10] o los hilos fuera de [1, 16];
- el número de entradas no cabe en el resto del archivo, alguna entrada tiene L < 16 o excede el archivo, o sobran bytes al final.

Así un encabezado alterado no puede pedir terabytes de memoria.

## Parámetros de Argon2id

- Base: 256 MiB, 3 iteraciones, 4 hilos.
- En `Create` se calibran para tardar cerca de 1 s en la máquina, sin bajar de la base de memoria.
- Los parámetros quedan en el encabezado, así que una bóveda creada en una máquina abre en otra.

## Escritura

Archivo temporal en el mismo directorio, `fsync`, `rename`, `fsync` del directorio. Antes se copia el archivo vigente a `vault.mcv.bak`. Permisos 0600.

## Vida en memoria

- DEK en un búfer bloqueado (`mlock`, páginas guardia) vía `memguard`. Su expansión AES vive en memoria normal: se crea una sola vez al abrir la bóveda y se suelta al destruir la DEK (límite declarado 10 del modelo de amenazas).
- Al cambiar la contraseña maestra también se reescribe `vault.mcv.bak`, para que ninguna copia quede sellada con la contraseña anterior.
- El respaldo `.bak` se escribe igual que el archivo principal: temporal, `fsync`, `rename`.
- Una credencial se descifra justo antes de autenticar y se borra al terminar. Ver límite declarado sobre `x/crypto/ssh` en el [modelo de amenazas](THREAT_MODEL.md#límites-declarados).

## Sobre `MCK1` (llaves de la PKI de laboratorio)

Las llaves privadas que genera la herramienta PKI (llaves de CSR y la de la CA de laboratorio) se guardan en un sobre con el mismo esquema que la DEK, sin pasar por la bóveda: `vault.Seal`/`vault.Unseal`.

| Tamaño | Campo |
|---|---|
| 4 | Mágico `MCK1` |
| 4 | Argon2id memoria en KiB |
| 4 | Argon2id iteraciones |
| 1 | Argon2id hilos |
| 16 | Sal |
| 12 | Nonce |
| … | PKCS#8 DER cifrado con AES-256-GCM + etiqueta |

- Datos asociados: los 29 bytes anteriores al nonce; cambiar un parámetro invalida el sobre.
- Antes de derivar se validan los parámetros con topes más estrictos que los de `vault.mcv`, porque el sobre llega pegado por el usuario: memoria entre el mínimo de la bóveda y 1 GiB, 1–10 iteraciones y 1–8 hilos. Un sobre fuera de rango se rechaza como dañado sin derivar nada.
- En disco viaja como PEM `MACUAHUITL SEALED PRIVATE KEY`. Para llevar la llave a otro equipo se exporta a PKCS#12 con contraseña (o PEM sin cifrar, solo si se pide de forma explícita).
