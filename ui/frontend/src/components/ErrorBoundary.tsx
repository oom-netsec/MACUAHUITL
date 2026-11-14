import { Component, type ReactNode } from "react";
import { ErrorState } from "./Page";
import { useT } from "../lib/i18n";

function Fallback({ error, onRetry }: { error: Error; onRetry: () => void }) {
  const t = useT();
  return (
    <ErrorState title={t("shell.moduleError")} action={<button className="sm" onClick={onRetry}>{t("common.retry")}</button>}>
      {error.message}
    </ErrorState>
  );
}

// Un fallo al renderizar un módulo no desmonta la raíz (la ventana es sin marco): se pinta el error y se puede reintentar.
// shortcut: si lo que falló fue descargar el código del módulo (React.lazy guarda el rechazo), «Reintentar» repite el
// error hasta reiniciar la app; con los assets embebidos en el binario no debería pasar. Cambiar si se sirven por red.
// shortcut: una tarea que el módulo tenía corriendo en el núcleo (un ping, una escucha) sigue allá, pero la vista
// rehecha no la conoce y no ofrece Detener; el núcleo la corta por su plazo. Revisar si un módulo empieza a fallar así.
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  render() {
    return this.state.error
      ? <Fallback error={this.state.error} onRetry={() => this.setState({ error: null })} />
      : this.props.children;
  }
}
