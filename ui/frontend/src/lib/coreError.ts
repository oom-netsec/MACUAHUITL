// Código, motivo estable y argumentos de un error del núcleo (cause del puente y errorInfo de los eventos *:done).
export interface ErrInfo { code: string; reason: string; metadata: Record<string, string> }

/** El motivo del error del puente; undefined si no trae (error sin migrar o que no vino del núcleo). */
export function errInfo(e: unknown): ErrInfo | undefined {
  const c = (e as { cause?: Partial<ErrInfo> } | null)?.cause;
  return c?.reason ? { code: c.code ?? "", reason: c.reason, metadata: c.metadata ?? {} } : undefined;
}
