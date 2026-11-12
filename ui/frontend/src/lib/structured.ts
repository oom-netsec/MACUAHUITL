/** Informe estructurado de la fase 30b: null si el núcleo no lo tiene, falla o viene sin texto, para caer al método de texto de siempre. */
export async function tryReport<T extends { text: string }>(call?: () => Promise<T>): Promise<T | null> {
  try {
    const d = await call?.();
    return d?.text ? d : null;
  } catch {
    return null;
  }
}
