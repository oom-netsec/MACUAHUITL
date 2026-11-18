import type { CoreAPI } from "../../lib/core";
import { useCredentials } from "../../components/CredentialSelect";
import { Field, Select } from "../../components/Field";
import { Section } from "../../components/Page";
import { useT } from "../../lib/i18n";
import { useForm } from "../../lib/useForm";

function useCreds(core: CoreAPI) {
  const t = useT();
  const { creds } = useCredentials(core); // bóveda cerrada: lista vacía, solo secretos escritos
  return [["", t("security.typeHere")] as [string, string], ...creds.map((c) => [c.id, t("security.credVault", { label: c.label, user: c.username })] as [string, string])];
}

interface SecretsForm { secretCredId: string; secret: string; credId: string; username: string; password: string }
const empty: SecretsForm = { secretCredId: "", secret: "", credId: "", username: "", password: "" };

// Secreto compartido y usuario de prueba: de la bóveda o escritos sin eco.
export function useSecrets(core: CoreAPI) {
  const t = useT();
  const options = useCreds(core);
  const [f, set] = useForm(empty);
  const { secretCredId, secret, credId, username, password } = f;
  const view = (needUser: boolean) => (
    <Section title={t("security.sec.creds")}>
      <div className="field-row">
        <Select label={t("security.secretFrom")} value={secretCredId} onChange={set("secretCredId")} options={options} w="lg" />
        {!secretCredId && <Field label={t("security.secret")} type="password" value={secret} onChange={set("secret")} autoComplete="new-password" w="lg" />}
      </div>
      {needUser && (
        <div className="field-row">
          <Select label={t("security.userFrom")} value={credId} onChange={set("credId")} options={options} w="lg" />
          {!credId && (
            <>
              <Field label={t("security.testUser")} value={username} onChange={set("username")} w="md" />
              <Field label={t("security.testPass")} type="password" value={password} onChange={set("password")} autoComplete="new-password" w="md" />
            </>
          )}
        </div>
      )}
    </Section>
  );
  const values = { secretCredId, secret: secretCredId ? "" : secret, credId, username: credId ? "" : username, password: credId ? "" : password };
  const ready = (needUser: boolean) => (!!secretCredId || !!secret) && (!needUser || !!credId || !!username);
  const clear = () => { set("secret")(""); set("password")(""); }; // se llama justo después de r.run: los valores ya se tomaron
  return { view, values, ready, clear };
}
