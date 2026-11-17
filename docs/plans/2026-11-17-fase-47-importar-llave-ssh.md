# Fase 47: importar una llave SSH existente (plan)

Pedido del dueño del 2026-11-17, recibido por Release, con prioridad alta: lo necesita para su Raspberry Pi. Cambia su regla de la fase 44. Hasta ahora toda llave se generaba dentro del núcleo; ahora también puede **importar** una privada que ya tiene (por ejemplo `~/.ssh/id_ed25519`) y elegirla al registrar un host linux o windows. La enmienda está en el ADR 0013, §1b.

Depende de #236 (43d-4), que trae `internal/sshkey`, la frontera estricta de la bóveda, el tope de 64 KiB por campo y la validación de la llave al guardar.

## Contrato (este PR)

- `VaultService.ImportKeyCredential(ImportKeyCredentialRequest) → ImportKeyCredentialResponse`.
  - **Pedido:** `label`, `username`, `private_key` (bytes, el **contenido** de la llave, nunca una ruta) y `passphrase` (bytes; va vacía si la llave no está cifrada).
  - **Respuesta:** `id`, `public_key` (línea authorized_keys), `fingerprint` (`SHA256:…`), `algorithm` (`ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `ssh-rsa`), `bits` y `weak` (RSA de menos de 3072 bits: es un aviso, no un error).
- `CredentialInfo.origin` (7): `"generated"` o `"imported"` en una credencial `key`, y `""` en las demás. Las llaves que ya existían salen como `generated`.
- `GetCredentialPublicKeyResponse.fingerprint` (2).
- **Reasons** (ErrorInfo):

  | Reason | Código | Cuándo |
  |---|---|---|
  | `vault.key_passphrase_required` | FailedPrecondition | la llave está cifrada y no se mandó frase |
  | `vault.key_passphrase_wrong` | InvalidArgument | la frase no descifra la llave |
  | `vault.key_invalid` | InvalidArgument | no se puede parsear; la metadata `format` dice el formato que se intentó |
  | `vault.key_unsupported` | InvalidArgument | DSA, `sk-*` (FIDO) o una curva o un tamaño fuera de lo que acepta OpenSSH; la metadata `type` dice cuál |
  | `vault.field_too_long` | InvalidArgument | la llave pasa de 64 KiB |

## Reglas

- **Formatos:** OpenSSH (`BEGIN OPENSSH PRIVATE KEY`, con frase bcrypt-pbkdf/aes) y PEM PKCS#1, PKCS#8 y SEC1, con o sin cifrado PEM legado si `x/crypto/ssh` lo soporta (`ParseRawPrivateKeyWithPassphrase`).
- **Tipos aceptados:** ed25519, ecdsa P-256/384/521 y RSA de al menos 1024 bits (de 1024 a 3071 con `weak`).
- **Tipos rechazados:** DSA, `sk-*` y cualquier otro, con `vault.key_unsupported`.
- **Guardado:**
  - La frase se usa una sola vez para descifrar.
  - La privada se vuelve a codificar en OpenSSH **sin frase** (`ssh.MarshalPrivateKey`), con el comentario original si lo trae, y va en el mismo campo «llave SSH» que las generadas. Así `transport.OpenSSH` no cambia, y la validación de #236 (privada parseable y sin frase) vale igual sobre lo guardado.
  - **El formato del archivo de la bóveda no cambia.** `origin` se deriva de la llave guardada sin agregar campos a la entrada. Ejemplo: las generadas son siempre ed25519 con el comentario vacío que pone `keygen.go`, y las importadas llevan una marca en el comentario del contenedor OpenSSH. La forma exacta la decide el bloque 47b y la documenta en el ADR.
- **Comentario de la pública:** el original si el archivo lo trae. Si no lo trae, `imported@<hostname local>`.
- **Lo que no se hace:** nunca se devuelve ni se registra la privada; solo viaja dentro del `.mcvault` cifrado, como las generadas.
- **Memoria:** el buffer con la privada recibida y la frase se borran después de usarlos. La privada en claro solo vive en `secret.Secret`.
- **Alcance:** igual que las generadas, `kind=key`, solo el terminal de hosts linux y windows.
- **rekey sobre una importada:** la reemplaza por una ed25519 **generada** (`origin` pasa a `generated`). La respuesta y mctl lo avisan.
- **Auditoría:** `credential.keyimport` con label, algoritmo, bits y huella. Nunca material de la llave ni la frase.
- **mctl:** `mctl cred import-key --label L --user U --file PATH`.
  - El archivo lo lee mctl, del lado del cliente.
  - La frase se pide por terminal sin eco, o por stdin con `--passphrase-stdin`; nunca va como argumento.
  - Con `vault.key_passphrase_required`, mctl la pide en la terminal y reintenta una vez.
- **UI (Front):** «Importar llave existente», con un archivo o texto pegado, más la frase. El puente lee la ruta en Go con el tope antes de leer y manda los bytes; la privada no pasa por el estado de JS.

## Bloques

- **47a:** este PR. Plan, enmienda del ADR 0013 y proto con gen; los servicios devuelven Unimplemented.
- **47b:** núcleo.
  - `sshkey.Import(pem, pass) (openssh []byte, pub PublicKey, info)` en `internal/sshkey`.
  - `vault.ImportKey(label, user, pem, pass)` por la frontera estricta.
  - El servicio con sus reasons, la auditoría, `origin` en ListCredentials, la huella en GetCredentialPublicKey y el aviso de rekey.
  - Pruebas en tabla: cada formato y tipo, con y sin frase; frase incorrecta; DSA; `sk-*`; RSA 1024 con `weak`; RSA 512 rechazada; basura; 64 KiB + 1. También que la privada no aparece en la auditoría, en los logs ni en el error, y que el round-trip por `.mcvault` conserva `origin`.
- **47c:** el subcomando `mctl cred import-key`, con la frase por terminal o stdin, su ayuda en es y en y sus golden.
- **47d (condición de Release):** prueba de punta a punta contra el simulador SSH del repo con dos llaves importadas: ed25519 **con** frase y RSA 2048 **sin** frase (`weak`). Las dos autentican por publickey en el terminal de un host linux.

## Review Focus

1. Que la privada o la frase no se filtren por errores (`%v` de x/crypto), por la auditoría, por los logs ni por el JSON de mctl.
2. Que una llave cifrada con frase incorrecta no se confunda con una llave inválida: la UI decide si pide la frase según el reason.
3. Que se rechacen las `sk-*` y DSA, y que `weak` aparezca solo en RSA.
4. Que `origin` se derive sin cambiar el formato de la bóveda y sobreviva al export e import.
5. Que rekey sobre una importada deje `origin=generated` y avise.
