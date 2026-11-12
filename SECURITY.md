# Política de seguridad

## Promesas

MACUAHUITL promete, y cualquiera puede verificar (ver [Guía para auditores](docs/security/AUDIT_GUIDE.md)):

1. Ninguna credencial se escribe en claro a disco.
2. Ninguna credencial aparece en logs, auditoría, outputs, mensajes de error ni volcados de memoria.
3. La aplicación solo conecta a destinos que escribió el ingeniero.
4. La contraseña maestra nunca se guarda. Si se pierde, la bóveda es irrecuperable, y eso es intencional.

Los límites conocidos de estas promesas están declarados en el [modelo de amenazas](docs/security/THREAT_MODEL.md#límites-declarados).

## Reportar una vulnerabilidad

No abras un issue público. Usa el reporte privado de vulnerabilidades de GitHub en este repositorio (pestaña *Security → Report a vulnerability*).

Incluye versión, pasos para reproducir e impacto. Respondemos en un máximo de 7 días.
