import { useEffect, useRef } from "react";
import { useT } from "../../lib/i18n";
import { showHidden } from "../../lib/safeText";
import type { AuthPrompt } from "./api";

// Preguntas del equipo (login as:, contraseña, MFA). Seguridad: los campos son NO controlados, así lo tecleado vive solo en
// el DOM de este panel (ni estado de React, ni almacenamiento, ni logs); al enviar se leen a una variable local, se mandan,
// se vacía el formulario y el padre desmonta el panel. Nada de esto se pinta en la terminal.
export function AuthPanel({ prompt, onAnswer }: { prompt: AuthPrompt; onAnswer: (seq: number, answers: string[]) => void }) {
  const t = useT();
  const first = useRef<HTMLInputElement>(null);
  useEffect(() => { first.current?.focus(); }, []);
  // El texto es del equipo: se muestra como texto plano, con lo oculto (controles, bidi) a la vista.
  const plain = (s: string) => showHidden(s);
  return (
    <form className="ssh-auth" aria-label={plain(prompt.name) || t("ssh.auth.title")} autoComplete="off"
      onSubmit={(e) => {
        e.preventDefault();
        const form = e.currentTarget;
        const answers = [...form.querySelectorAll<HTMLInputElement>("input")].map((i) => i.value);
        form.reset();
        onAnswer(prompt.seq, answers);
      }}>
      {prompt.name && <strong>{plain(prompt.name)}</strong>}
      {prompt.instruction && <p className="ssh-auth-instr" style={{ whiteSpace: "pre-wrap" }}>{plain(prompt.instruction)}</p>}
      {prompt.prompts.map((q, i) => (
        <label key={i} className="field">
          <span>{plain(q.text)}</span>
          <input ref={i === 0 ? first : undefined} type={q.echo ? "text" : "password"} autoComplete="off" spellCheck={false} autoCapitalize="off" />
        </label>
      ))}
      <div className="actions"><button type="submit" className="primary">{t("ssh.auth.answer")}</button></div>
    </form>
  );
}
