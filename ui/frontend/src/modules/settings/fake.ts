// Doble del módulo para pruebas: guarda las preferencias en memoria y avisa al cambiar la carpeta, como el núcleo.
import { vi } from "vitest";
import type { CorePrefs, CorePrefsState } from "./api";

export const sampleOutputsDefault = "/home/u/MACUAHUITL/outputs";

export function fakeSettings() {
  let cur: CorePrefs = { outputsDir: "", rotateMb: 0, rotateMin: 0, maxFiles: 0, format: "" };
  const state = (note = ""): CorePrefsState => ({ ...cur, outputsDirEffective: cur.outputsDir || sampleOutputsDefault, outputsDirDefault: sampleOutputsDefault, note });
  return {
    getCorePrefs: vi.fn(async () => state()),
    setCorePrefs: vi.fn(async (p: CorePrefs) => {
      const moved = p.outputsDir !== cur.outputsDir;
      cur = { ...p };
      return state(moved ? "El cambio aplica a lo que empiece después: los trabajos y escuchas en curso conservan la carpeta con que arrancaron. Los datos de la carpeta anterior no se mueven." : "");
    }),
  };
}
