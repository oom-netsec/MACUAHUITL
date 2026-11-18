import { useState, type ReactNode } from "react";

// Muestra solo el panel elegido. Cada uno se monta al visitarlo y después queda oculto, no desmontado: lo escrito se conserva al volver.
export function Panels<T extends string>({ value, panels }: { value: T; panels: Record<T, ReactNode> }) {
  const [seen, setSeen] = useState<ReadonlySet<T>>(new Set([value]));
  if (!seen.has(value)) setSeen(new Set([...seen, value])); // ajuste durante el render: lo permite React y evita un parpadeo
  return <>{(Object.keys(panels) as T[]).filter((k) => seen.has(k)).map((k) => <div key={k} hidden={k !== value}>{panels[k]}</div>)}</>;
}
