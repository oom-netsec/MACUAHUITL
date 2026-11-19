import { useEffect, useRef } from "react";
import { useT } from "../../lib/i18n";
import { showHidden } from "../../lib/safeText";
import type { AuthPrompt } from "./api";

// Preguntas del equipo (login as:, contraseña, MFA). Seguridad: los campos son NO controlados, así lo tecleado vive solo en
// el DOM de este panel (ni estado de React, ni almacenamiento, ni logs); al enviar se leen a una variable local, se mandan,
// se vacía el formulario y el padre desmonta el panel. Nada de esto se pinta en la terminal.
export function AuthPanel({ prompt, label, active, onAnswer }: { prompt: AuthPrompt; label: string; active: boolean; onAnswer: (seq: number, answers: string[]) => void }) {
  const t = useT();
  const first = useRef<HTMLInputElement>(null);
  const form = useRef<HTMLFormElement>(null);
  // Solo toma el foco si la pestaña está activa y la persona no está escribiendo en otra parte (body, este mismo panel o la pestaña que se acaba de pulsar).
  useEffect(() => {
    const a = document.activeElement;
    if (active && (!a || a === document.body || form.current?.contains(a) || a.closest("[role=tab]"))) first.current?.focus();
  }, [active]);
  // El texto es del equipo: se muestra como texto plano, con lo oculto (controles, bidi) a la vista.
  const plain = (s: string) => showHidden(s);
  return (
    <form ref={form} className="ssh-auth" aria-label={`${t("ssh.auth.title")} · ${label}`} autoComplete="off"
      onSubmit={(e) => {
        e.preventDefault();
        const form = e.currentTarget;
        const answers = [...form.querySelectorAll<HTMLInputElement>("input")].map((i) => i.value);
        form.reset();
        onAnswer(prompt.seq, answers);
      }}>
      <strong>{t("ssh.auth.title")} · {label}</strong>
      {(prompt.name || prompt.instruction) && (
        <div className="ssh-auth-said">
          <em>{t("ssh.auth.said")}</em>
          {prompt.name && <p>{plain(prompt.name)}</p>}
          {prompt.instruction && <p className="ssh-auth-instr" style={{ whiteSpace: "pre-wrap" }}>{plain(prompt.instruction)}</p>}
        </div>
      )}
      {prompt.prompts.map((q, i) => (
        <label key={i} className="field">
          <span>{plain(q.text)}</span>
          <input ref={i === 0 ? first : undefined} type={q.echo ? "text" : "password"} autoComplete={q.echo ? "off" : "one-time-code"} spellCheck={false} autoCapitalize="off" />
        </label>
      ))}
      <div className="actions"><button type="submit" className="primary">{t("ssh.auth.answer")}</button></div>
    </form>
  );
}
