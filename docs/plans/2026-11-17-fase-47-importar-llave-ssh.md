# Fase 47: importar una llave SSH existente (plan)

Pedido del dueño del 2026-11-17, recibido por Release, con prioridad alta: lo necesita para su Raspberry Pi. Cambia su regla de la fase 44. Hasta ahora toda llave se generaba dentro del núcleo; ahora también puede **importar** una privada que ya tiene (por ejemplo `~/.ssh/id_ed25519`) y elegirla al registrar un host linux o windows. La enmienda está en el ADR 0013, §1b.

Depende de #236 (43d-4), que trae `internal/sshkey`, la frontera estricta de la bóveda, el tope de 64 KiB por campo y la validación de la llave al guardar.

## Contrato (este PR)

- **`VaultService.ImportKeyCredential(ImportKeyCredentialRequest) → ImportKeyCredentialResponse`.**
  - Pedido: `label`, `username`, `private_key` (bytes: el **contenido**, nunca una ruta) y `passphrase` (bytes, vacía si no hace falta).
  - Respuesta:
    - `id`;
    - `public_key`: la línea authorized_keys, con el mismo comentario `macuahuitl@<hostname>` que `GetCredentialPublicKey`;
    - `fingerprint` (`SHA256:…`);
    - `algorithm`;
    - `bits`: ed25519 = 256, ECDSA = tamaño de la curva, RSA = largo del módulo;
    - `weak`: RSA de menos de 3072 bits. Es un aviso, no un error.
- **`CredentialInfo.origin` (7):** `"generated"`, `"imported"` o `""`.
- **`GetCredentialPublicKeyResponse.fingerprint` (2).**
- **`RegenerateKeyCredentialResponse.previous_origin` (2):** si era `"imported"`, la UI y mctl avisan que se reemplaza por una generada.
- **Reasons:** el reason es el código i18n, como en el resto de vault.

  | Reason | Código | Cuándo |
  |---|---|---|
  | `vault.err.key_passphrase_required` | FailedPrecondition | la llave está cifrada y falta la frase |
  | `vault.err.key_passphrase_wrong` | InvalidArgument | la frase no la descifra. En PEM legado, cualquier fallo después de descifrar |
  | `vault.err.key_import_invalid` | InvalidArgument | no se puede parsear (metadata `format`, de una lista cerrada) |
  | `vault.err.key_import_unsupported` | InvalidArgument | DSA, `sk-*`, P-224, RSA fuera de 1024..16384, PKCS#8 cifrada o demasiadas rondas de bcrypt (metadata `type` o `format`). Con PKCS#8 cifrada sugiere `ssh-keygen -p -f <archivo>` |
  | `vault.err.field_too_long` | InvalidArgument | más de 64 KiB (metadata `max`) |

## Reglas

- **Formatos.** Se aceptan OpenSSH (con o sin frase, bcrypt-pbkdf), PKCS#1, PKCS#8 **sin cifrar**, SEC1 y PEM legado cifrado (DES, 3DES, AES-CBC). La PKCS#8 cifrada (`ENCRYPTED PRIVATE KEY`) se rechaza, porque `x/crypto/ssh` no la soporta.
- **Orden de clasificación.**
  1. Tamaño.
  2. Tipo de PEM.
  3. Tipo de la pública en la cabecera OpenSSH, que va en claro aun cifrada. Así DSA y `sk-*` se rechazan **antes** de pedir la frase.
  4. `ParseRawPrivateKey`; solo si da PassphraseMissing, la versión con frase.
  5. `NewSignerFromKey`.
  6. Bits.

  Si la llave no está cifrada y llega una frase, la frase se ignora y se borra. Nunca se propaga `err.Error()` de `x/crypto`, porque trae cadenas del archivo.
- **Política única `sshkey.Check`:** ed25519, P-256/384/521 y RSA de 1024 a 16384 bits. La usan la importación **y** la frontera estricta de #236 (Put e import de `.mcvault`).
- **Guardado.** Se usa `ssh.MarshalPrivateKey(key, "macuahuitl:imported")` (OpenSSH **sin frase**, siempre con ese comentario), en el mismo campo que las generadas. El comentario original no se conserva: `x/crypto` lo descarta. El formato del archivo de la bóveda no cambia.
- **Origin.** Se deriva en vault con el parseo manual de keygen.go:
  - `generated`: ed25519 OpenSSH sin frase **con el comentario vacío** (lo que escribe keygen.go);
  - `imported`: cualquier otra llave;
  - `""`: si no es `key`.

  Sobrevive al `.mcvault` y el rekey lo deja en `generated`. Es informativo, **no un control de seguridad**.
- **La pública de RSA y ECDSA.** `Vault.PublicKey`, `AuthorizedKey` y `GetCredentialPublicKey` funcionan con los tres tipos: la pública se deriva vía `internal/sshkey` y el tipo sale del formato de cable.
- **Memoria (mejor esfuerzo, dentro del límite 1 de THREAT_MODEL).**
  - Se hace `clear` del pedido, de la frase, del slice ed25519 y de `block.Bytes`.
  - El PEM final se arma con `armor()`.
  - Se ponen en cero `D` y `Primes`.
  - Quedan copias fuera de nuestro alcance: el búfer de gRPC, los intermedios de `x/crypto` y la caché de `rsa.PrivateKey`. En la importación la privada **sí** cruza el socket local.
  - El parseo (bcrypt puede tardar segundos) va fuera de `v.mu`.
- **Auditoría.** `credential.keyimport`, con objetivo = id y detalle `type=… bits=… fingerprint=…`, como `credential.keygen`. Sin la etiqueta y nunca con material de la llave.
- **mctl.** `mctl cred import-key --label L --user U --file PATH`.
  - Lee el archivo del lado del cliente, con el tope antes de leerlo entero.
  - Si el núcleo responde `key_passphrase_required`, pide la frase con `cli.Env.Secret` (la TTY sin eco o una línea de stdin, la convención del respaldo) y reintenta. No hay flag nuevo.
  - `rekey` avisa con `previous_origin=imported`.
- **UI (Front).** El selector de archivo: el puente lee la ruta en Go y la privada no pasa por JS. El texto pegado sí pasa por el estado de JS; es un límite declarado.
- **Alcance.** Igual que las generadas: `kind=key`, solo el terminal de hosts linux y windows.

## Bloques

- **47a:** este PR. Plan, enmienda del ADR 0013 y proto con gen; los servicios devuelven Unimplemented.
- **47b:** núcleo.
  - `sshkey.Import(pem, pass) (openssh []byte, pub PublicKey, info)` en `internal/sshkey`.
  - `vault.ImportKey(label, user, pem, pass)` por la frontera estricta.
  - El servicio con sus reasons, la auditoría, `origin` en ListCredentials, la huella en GetCredentialPublicKey y el aviso de rekey.
  - Pruebas en tabla: cada formato y tipo, con y sin frase; frase incorrecta; DSA; `sk-*`; RSA 1024 con `weak`; RSA 512 rechazada; basura; 64 KiB + 1. También que la privada no aparece en la auditoría, en los logs ni en el error, y que el round-trip por `.mcvault` conserva `origin`.
- **47c:** el subcomando `mctl cred import-key`, con la frase por terminal o stdin, su ayuda en es y en y sus golden.
- **47d (condición de Release):** prueba de punta a punta con el patrón de `internal/core/e2e44f_test.go`, contra `test/simulator` (`AuthorizedKeys`, `NoPassword`, `AuthLog`), con dos llaves importadas:
  - ed25519 **con** frase, armada con un helper de `test/simulator`;
  - RSA 2048 PKCS#1 **sin** frase (`weak`), armada con `crypto/x509`.

  Las dos autentican solo por publickey. Además, en `internal/sshkey/testdata` van llaves de interoperabilidad generadas con `ssh-keygen` real, y hay un fuzz de `sshkey.Import`.

## Review Focus

1. Que la privada o la frase no se filtren por errores (`%v` de x/crypto), por la auditoría, por los logs ni por el JSON de mctl.
2. Que una llave cifrada con frase incorrecta no se confunda con una llave inválida: la UI decide si pide la frase según el reason.
3. Que se rechacen las `sk-*` y DSA, y que `weak` aparezca solo en RSA.
4. Que `origin` se derive sin cambiar el formato de la bóveda y sobreviva al export e import.
5. Que rekey sobre una importada deje `origin=generated` y avise.
