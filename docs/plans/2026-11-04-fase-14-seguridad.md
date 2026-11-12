# Fase 14 — Seguridad y acceso: Plan de implementación

**Goal:** Probadores RADIUS y TACACS+, PKI de laboratorio (llaves, CSR, CA, exportación, decodificador) y decodificador de debugs IKE/IPsec, expuestos por gRPC (`SecurityService`), `mctl` y la pestaña "Seguridad" de la UI.

**Licencias:** RADIUS (RFC 2865/2866/2869/3579/5080/5997) y TACACS+ (RFC 8907) implementados con la librería estándar; MS-CHAPv2 usa `golang.org/x/crypto/md4` (BSD-3, ya en go.mod). `layeh/radius` (MPL-2.0) descartada. Dependencia nueva: `software.sslmate.com/src/go-pkcs12` v0.7.4 (BSD-3-Clause, LICENSE revisado).

**Architecture:**
- `internal/diag/radiustest`: cliente RADIUS (PAP, CHAP, MS-CHAPv2), Message-Authenticator primero en la petición (RFC 5080, mitigación Blast-RADIUS) y verificado en la respuesta, Response Authenticator, Status-Server, Accounting Start/Stop, diccionario con Cisco-AVPair (9/1), MS-CHAP2-Success verificado (autenticación mutua), Tunnel-* con etiqueta, Filter-Id, Class, Session-Timeout. Servidor falso en loopback (`StartFake`) para las pruebas de este paquete, del núcleo y de mctl.
- `internal/diag/tacacstest`: cliente TACACS+ (autenticación ASCII y PAP, autorización de un comando con los AV pairs que manda IOS, accounting Start/Stop), ofuscación MD5 del RFC, límite de 64 KiB por respuesta, diagnóstico de secreto distinto. Servidor falso en loopback.
- `internal/pki`: llaves RSA 2048/3072/4096 y ECDSA P-256/P-384, CSR con Subject y SAN DNS/IP, CA raíz de laboratorio (pathlen 0), firma con perfiles server/client/server-client (usos y validez los pone el perfil, no el CSR), exportación PEM/DER/PKCS#12 (AES-256 o 3DES legado), resumen de certificados y CSR pegados (PEM o DER) con avisos.
- `internal/vault/seal.go`: sobre `MCK1` (Argon2id + AES-256-GCM, mismo esquema que la DEK) para sellar llaves sueltas; documentado en `docs/security/CRYPTO.md`.
- `internal/ikedec`: interpreta `debug crypto isakmp|ikev2|ipsec` y `show crypto isakmp sa|ikev2 sa detail|ipsec sa` de IOS/IOS-XE y ASA. Estado de fase 1/2, propuestas ofrecidas vs aceptadas (IKEv1 transform por transform; IKEv2 "Received/Expected Policies"), estados de SA, contadores de IPsec y causas con explicación y acción.
- `internal/core/services_security.go`: `SecurityService`; RADIUS y TACACS+ salen por EgressGuard con allowlist del servidor escrito (`Allow`/`DialerFor`/`defer Revoke`).

## Decisiones

- **Secretos:** el secreto compartido y la contraseña de prueba vienen de una credencial de la bóveda (`SecretSource.credential_id`: su contraseña; para el usuario de prueba también su usuario) o escritos sin eco. Se borran al terminar; la auditoría registra solo el origen (`bóveda:<id>` o `escrito`). Límite conocido: el puente Wails recibe strings (igual que la bóveda) y go-pkcs12 recibe la contraseña de exportación como string.
- **PKI sin estado en el núcleo:** el núcleo genera, firma y exporta; los archivos los escribe el cliente (`mctl` con 0600 y sin sobrescribir; la UI muestra PEM en cuadros de texto y la exportación binaria la escribe el puente en una ruta absoluta). Serie aleatoria de 127 bits, sin índice de emitidos ni CRL: es solo de laboratorio.
- **Llaves selladas:** formato propio `MACUAHUITL SEALED PRIVATE KEY` con la criptografía de la bóveda, en vez de PKCS#8 cifrado (la librería estándar no lo escribe). Para llevar una llave a ISE/WLC se exporta a PKCS#12. PEM en claro solo con `--plain-key` / `include_plain_key`.
- **Accounting RADIUS** se envía aunque el Access-Request sea rechazado (se pidió explícitamente); Status-Server va al puerto de autenticación.
- **TACACS+**: una conexión TCP por paso, sin single-connect; exige secreto (sin él el tráfico viaja en claro).
- **IKE**: las reglas son una tabla de expresiones regulares con contexto de fase; sin validar en laboratorio. Las fixtures (`internal/ikedec/testdata`) están reconstruidas de la documentación pública de Cisco y lo dicen en su README.
- `pki` no importa `net` (noegress): usa `net/netip` y convierte a `net.IP` por asignación de `[]byte`.

## Pruebas

- Vectores de RFC 2865 §7.1 (User-Password y re-codificación del Access-Request) y RFC 2759 §9.2 (ChallengeHash, PasswordHash, NT-Response, AuthenticatorResponse).
- Servidores RADIUS y TACACS+ falsos en loopback: Accept/Reject/Challenge, secreto distinto, respuesta sin Message-Authenticator, autenticador de respuesta inválido, accounting, Status-Server, comandos autorizados y denegados.
- Núcleo: secretos desde la bóveda sin fugas a auditoría ni reporte, bóveda cerrada → `FailedPrecondition`, flujo PKI completo y PKCS#12 decodificable.
- Comprobaciones de mutación a mano en crypto RADIUS, etiquetas Tunnel, ofuscación TACACS+, parseo de AV pairs, PKI (keyEncipherment) e IKE (umbral de retransmisiones, contexto de fase).

## Pendientes

- Validar las reglas IKE/IPsec y las fixtures con capturas reales de IOS-XE y ASA (incluido IKEv2 de ASA, que solo se cubre por los nombres de notify).
- Probar contra ISE real (RADIUS y TACACS+) y contra AireOS/9800 la importación de PKCS#12.
- EAP (PEAP/EAP-TLS) y RadSec no están: requieren una máquina de estados EAP y TLS.
- TACACS+ CHAP/MS-CHAP y TACACS+ sobre TLS no están.
- La CA no lleva índice de certificados emitidos ni CRL/OCSP.
