// Código, motivo estable y argumentos de un error del núcleo (cause del puente y errorInfo de los eventos *:done).
export interface ErrInfo { code: string; reason: string; metadata: Record<string, string> }

/** El motivo del error del puente; undefined si no trae (error sin migrar o que no vino del núcleo). */
export function errInfo(e: unknown): ErrInfo | undefined {
  const c = (e as { cause?: Partial<ErrInfo> } | null)?.cause;
  return c?.reason ? { code: c.code ?? "", reason: c.reason, metadata: c.metadata ?? {} } : undefined;
}

/** «El archivo ya existe»: por reason; el texto en español solo sirve de respaldo si el error no trae cause. */
export function fileExists(e: unknown): boolean {
  const i = errInfo(e);
  return i ? i.reason === "file.exists" : /ya existe/.test(String(e));
}
