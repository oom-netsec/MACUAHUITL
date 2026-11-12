import type { CoreAPI } from "./core";

// pickSavePath deja el archivo creado, vacío: si la exportación falla se borra (solo borra un archivo regular de 0 bytes) y el error sigue su camino.
export async function cleanOnFail<T>(core: Pick<CoreAPI, "removeEmptyFile">, path: string, work: Promise<T>): Promise<T> {
  try { return await work; } catch (e) { await core.removeEmptyFile(path).catch(() => {}); throw e; }
}
