# Backlog

Ideas aceptadas pero sin definir lo suficiente para planearlas.

## Vista de líder (flota y negocio)

Pendiente de definir alcance, audiencia y métricas antes de planearla.

- Salud de la flota: puntuación por equipo según hallazgos del analizador y cumplimiento.
- EoX y PSIRT: las APIs de Cisco son nube; opciones a decidir: importar CSV/JSON descargado aparte, o consulta opt-in explícita y auditada por ejecución (como el DNS profundo).
- Reporte RCA para cliente: línea de tiempo, evidencia enmascarada, causa raíz, acción y prevención; exportable a PDF o Markdown.
- Paquete para TAC: comprimido firmado con evidencia, hashes y cadena de auditoría; lo sube el ingeniero, la app nunca lo envía.

Preguntas abiertas: ¿quién la consume (ingeniero, jefe de turno, cliente)?, ¿qué decisiones debe habilitar?, ¿cómo se pondera la salud?, ¿qué datos externos son aceptables y con qué opt-in?
