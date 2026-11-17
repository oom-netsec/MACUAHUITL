import { useCallback, useEffect, useState, type DependencyList } from "react";
import { errorText } from "../components/Field";
import { useVaultVersion } from "./vaultSignal";

/**
 * Carga de una vista contra el núcleo: corre al montar, cuando cambian `deps` y al reconectar el núcleo o cambiar la
 * bóveda (App avisa con vaultChanged). Devuelve su propio error, que se borra al reintentar, separado del de las acciones:
 * una vista abierta sin núcleo no se queda con «connection error» cuando el núcleo llega.
* Devuelve [error, clear, reload]: `reload` repite la carga a pedido (un botón «Buscar» de nuevo), con el mismo error.
 * `live()` es falso si la carga ya quedó vieja (otra la reemplazó o la vista se desmontó): no aplicar su resultado.
 */
export function useCoreLoad(load: (live: () => boolean) => Promise<unknown>, deps: DependencyList) {
  const vv = useVaultVersion();
  const [err, setErr] = useState("");
  const [n, setN] = useState(0);
  useEffect(() => {
    let on = true;
    setErr("");
    load(() => on).catch((e) => { if (on) setErr(errorText(e)); });
    return () => { on = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- deps las da quien llama, como en useEffect
  }, [...deps, vv, n]);
  const clear = useCallback(() => setErr(""), []);
  const reload = useCallback(() => setN((x) => x + 1), []);
  return [err, clear, reload] as const;
}
