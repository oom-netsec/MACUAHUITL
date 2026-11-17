import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { VaultView, trimTrailingNewline } from "./VaultView";
import { fakeCore } from "../../lib/fake";
import { vaultChanged } from "../../lib/vaultSignal";

test("trimTrailingNewline solo quita el salto final", () => {
  expect(trimTrailingNewline("pw\n")).toBe("pw");
  expect(trimTrailingNewline("pw\r\n")).toBe("pw");
  expect(trimTrailingNewline("p w ")).toBe("p w ");
});

test("crear bóveda exige confirmación igual y no vacía, y limpia los campos", async () => {
  const core = fakeCore({ vaultStatus: vi.fn(async () => ({ state: "absent" as const, armedJobs: [] })) });
  render(<VaultView core={core} />);
  const pw = await screen.findByLabelText("Contraseña maestra nueva");
  const again = screen.getByLabelText("Confirmación de la contraseña");
  const btn = screen.getByRole("button", { name: "Crear bóveda" });
  await userEvent.click(btn);
  expect(await screen.findByRole("alert")).toHaveTextContent(/no puede estar vacía/);
  await userEvent.type(pw, "una");
  await userEvent.type(again, "otra");
  await userEvent.click(btn);
  expect(await screen.findByRole("alert")).toHaveTextContent(/no coinciden/);
  expect(core.vaultCreate).not.toHaveBeenCalled();
  await userEvent.clear(again);
  await userEvent.type(again, "una");
  await userEvent.click(btn);
  await waitFor(() => expect(core.vaultCreate).toHaveBeenCalledWith("una"));
  expect(pw).toHaveValue("");
  expect(again).toHaveValue("");
});

test("desbloquear envía la contraseña y vacía el campo", async () => {
  const core = fakeCore({ vaultStatus: vi.fn(async () => ({ state: "locked" as const, armedJobs: [] })) });
  render(<VaultView core={core} />);
  const pw = await screen.findByLabelText("Contraseña maestra");
  await userEvent.type(pw, "maestra");
  await userEvent.click(screen.getByRole("button", { name: "Abrir bóveda" }));
  await waitFor(() => expect(core.vaultUnlock).toHaveBeenCalledWith("maestra"));
  expect(pw).toHaveValue("");
});

test("alta de credencial y lista sin secretos", async () => {
  const core = fakeCore({
    listCredentials: vi.fn(async () => [{ id: "c1", label: "core", username: "admin", kind: "password" as const, hasEnable: true, hasSshKey: false }]),
  });
  render(<VaultView core={core} />);
  expect(await screen.findByText("core")).toBeInTheDocument();
  expect(screen.getByText("admin")).toBeInTheDocument();
  expect(screen.getByText("Con enable")).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("Etiqueta"), "lab");
  await userEvent.type(screen.getByLabelText("Usuario"), "netops");
  const pass = screen.getByLabelText("Contraseña del equipo");
  const en = screen.getByLabelText("Contraseña de enable (opcional)");
  await userEvent.type(pass, "s3cr3t");
  await userEvent.type(en, "en4ble");
  await userEvent.click(screen.getByRole("button", { name: "Guardar credencial" }));
  await waitFor(() => expect(core.putCredential).toHaveBeenCalledWith("lab", "netops", "s3cr3t", "en4ble"));
  expect(pass).toHaveValue("");
  expect(en).toHaveValue("");
  expect(document.body.textContent).not.toContain("s3cr3t");
});

test("una contraseña maestra incorrecta se anuncia como error", async () => {
  const core = fakeCore({
    vaultStatus: vi.fn(async () => ({ state: "locked" as const, armedJobs: [] })),
    vaultUnlock: vi.fn(async () => { throw new Error("rpc error: code = PermissionDenied desc = contraseña maestra incorrecta"); }),
  });
  render(<VaultView core={core} />);
  await userEvent.type(await screen.findByLabelText("Contraseña maestra"), "mala");
  await userEvent.click(screen.getByRole("button", { name: "Abrir bóveda" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/^contraseña maestra incorrecta$/);
});

test("eliminar una credencial pide confirmación", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [{ id: "c1", label: "core", username: "admin", kind: "password" as const, hasEnable: false, hasSshKey: false }]) });
  render(<VaultView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Eliminar core" }));
  expect(core.deleteCredential).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Confirmar eliminación de core" }));
  await waitFor(() => expect(core.deleteCredential).toHaveBeenCalledWith("c1"));
  expect(await screen.findByRole("status")).toHaveTextContent("Credencial eliminada.");
});

test("si cerrar la bóveda o eliminar falla, el error se muestra", async () => {
  const core = fakeCore({
    listCredentials: vi.fn(async () => [{ id: "c1", label: "core", username: "admin", kind: "password" as const, hasEnable: false, hasSshKey: false }]),
    vaultLock: vi.fn(async () => { throw new Error("rpc error: code = FailedPrecondition desc = hay trabajos armados"); }),
    deleteCredential: vi.fn(async () => { throw new Error("rpc error: code = FailedPrecondition desc = credencial en uso"); }),
  });
  render(<VaultView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Cerrar bóveda" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("hay trabajos armados");
  await userEvent.click(screen.getByRole("button", { name: "Eliminar core" }));
  await userEvent.click(screen.getByRole("button", { name: "Confirmar eliminación de core" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("credencial en uso");
});

test("las credenciales van en una tabla con búsqueda por etiqueta, usuario o detalle", async () => {
  const core = fakeCore({
    listCredentials: vi.fn(async () => [
      { id: "c1", label: "Core DC", username: "netops", kind: "password" as const, hasEnable: true, hasSshKey: false },
      { id: "c2", label: "Sucursales", username: "tac", kind: "password" as const, hasEnable: false, hasSshKey: true },
      { id: "c3", label: "Laboratorio", username: "lab", kind: "password" as const, hasEnable: false, hasSshKey: false },
    ]),
  });
  render(<VaultView core={core} />);
  const table = await screen.findByRole("table", { name: "Credenciales" });
  expect(within(table).getAllByRole("row")).toHaveLength(4);
  await userEvent.type(screen.getByRole("textbox", { name: "Buscar en la tabla" }), "tac");
  expect(within(table).getAllByRole("row")).toHaveLength(2);
  expect(within(table).getByRole("cell", { name: "Sucursales" })).toBeInTheDocument();
  expect(within(table).getByText("Llave SSH")).toBeInTheDocument();
  await userEvent.clear(screen.getByRole("textbox", { name: "Buscar en la tabla" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Buscar en la tabla" }), "enable");
  expect(within(table).getByRole("cell", { name: "Core DC" })).toBeInTheDocument();
  expect(within(table).queryByRole("cell", { name: "Laboratorio" })).not.toBeInTheDocument();
});

describe("respaldo cifrado", () => {
  const frase = "frase-del-respaldo-1";

  test("exportar pide frase de 12 o más caracteres repetida y la confirmación explícita, y limpia los campos", async () => {
    const core = fakeCore();
    render(<VaultView core={core} />);
    const f1 = await screen.findByLabelText("Frase del respaldo");
    const f2 = screen.getByLabelText("Repite la frase del respaldo");
    const ok = screen.getByRole("checkbox", { name: /contiene todas mis credenciales/ });
    const btn = screen.getByRole("button", { name: "Exportar respaldo…" });
    expect(btn).toBeDisabled(); // sin confirmar
    await userEvent.click(ok);
    await userEvent.type(f1, "corta");
    await userEvent.type(f2, "corta");
    await userEvent.click(btn);
    expect(await screen.findByRole("alert")).toHaveTextContent(/al menos 12 caracteres/);
    await userEvent.clear(f1); await userEvent.clear(f2);
    await userEvent.type(f1, frase);
    await userEvent.type(f2, "otra-frase-distinta");
    await userEvent.click(btn);
    expect(await screen.findByRole("alert")).toHaveTextContent(/no coinciden/);
    expect(core.exportVaultBackup).not.toHaveBeenCalled();
    await userEvent.clear(f2);
    await userEvent.type(f2, frase);
    await userEvent.click(btn);
    await waitFor(() => expect(core.exportVaultBackup).toHaveBeenCalledWith("/home/u/Descargas/respaldo-boveda.mcvault", frase, true, true));
    expect(core.removeEmptyFile).not.toHaveBeenCalled();
    expect(await screen.findByRole("status")).toHaveTextContent("Respaldo de 3 credenciales guardado");
    expect(f1).toHaveValue("");
    expect(f2).toHaveValue("");
    expect(document.body.textContent).not.toContain(frase);
  });

  test("si se cancela el diálogo de guardar no se exporta", async () => {
    const core = fakeCore({ pickSavePath: vi.fn(async () => "") });
    render(<VaultView core={core} />);
    await userEvent.type(await screen.findByLabelText("Frase del respaldo"), frase);
    await userEvent.type(screen.getByLabelText("Repite la frase del respaldo"), frase);
    await userEvent.click(screen.getByRole("checkbox", { name: /contiene todas mis credenciales/ }));
    await userEvent.click(screen.getByRole("button", { name: "Exportar respaldo…" }));
    await waitFor(() => expect(core.pickSavePath).toHaveBeenCalled());
    expect(core.exportVaultBackup).not.toHaveBeenCalled();
  });

  test("un error del núcleo al exportar se muestra sin repetir la frase", async () => {
    const core = fakeCore({ exportVaultBackup: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = la frase del respaldo debe ser distinta de la contraseña maestra"); }) });
    render(<VaultView core={core} />);
    await userEvent.type(await screen.findByLabelText("Frase del respaldo"), frase);
    await userEvent.type(screen.getByLabelText("Repite la frase del respaldo"), frase);
    await userEvent.click(screen.getByRole("checkbox", { name: /contiene todas mis credenciales/ }));
    await userEvent.click(screen.getByRole("button", { name: "Exportar respaldo…" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("distinta de la contraseña maestra");
    expect(alert).not.toHaveTextContent(frase);
    // El diálogo de guardar dejó un archivo vacío: se borra.
    expect(core.removeEmptyFile).toHaveBeenCalledWith("/home/u/Descargas/respaldo-boveda.mcvault");
  });

  test("si el sistema de archivos no admitió los permisos, se avisa aunque el export sirvió", async () => {
    const core = fakeCore({ exportVaultBackup: vi.fn(async () => ({ count: 2, noPermissions: true, sshKeysIncluded: 0 })) });
    render(<VaultView core={core} />);
    await userEvent.type(await screen.findByLabelText("Frase del respaldo"), frase);
    await userEvent.type(screen.getByLabelText("Repite la frase del respaldo"), frase);
    await userEvent.click(screen.getByRole("checkbox", { name: /contiene todas mis credenciales/ }));
    await userEvent.click(screen.getByRole("button", { name: "Exportar respaldo…" }));
    const st = await screen.findByRole("status");
    expect(st).toHaveTextContent("Respaldo de 2 credenciales guardado");
    expect(st).toHaveTextContent("no admitió los permisos 0600");
    expect(core.removeEmptyFile).not.toHaveBeenCalled();
  });

  test("Importar respaldo… sigue deshabilitado hasta que hay frase", async () => {
    render(<VaultView core={fakeCore()} />);
    const b = await screen.findByRole("button", { name: "Importar respaldo…" });
    expect(b).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Frase del respaldo a importar"), "x");
    expect(b).toBeEnabled();
  });

  async function abrirVistaPrevia(core: ReturnType<typeof fakeCore>) {
    render(<VaultView core={core} />);
    const f = await screen.findByLabelText("Frase del respaldo a importar");
    await userEvent.type(f, frase);
    await userEvent.click(screen.getByRole("button", { name: "Importar respaldo…" }));
    await screen.findByText("Vista previa de la importación");
    return f;
  }

  test("importar muestra la vista previa sin secretos, exige decidir cada conflicto y aplica", async () => {
    const core = fakeCore({ pickPath: vi.fn(async () => "/home/u/r.mcvault") });
    const f = await abrirVistaPrevia(core);
    expect(core.previewVaultBackupImport).toHaveBeenCalledWith("/home/u/r.mcvault", frase);
    expect(f).toHaveValue(""); // la frase no se queda en el campo
    expect(screen.getByText("Core DC")).toBeInTheDocument();
    expect(screen.getByText("Se omite (del sistema)")).toBeInTheDocument();
    const apply = screen.getByRole("button", { name: "Aplicar importación" });
    expect(apply).toBeDisabled();
    expect(screen.getByText(/Elige qué hacer con cada conflicto/)).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Qué hacer con Laboratorio"), "reemplazar");
    expect(apply).toBeEnabled();
    await userEvent.click(apply);
    await waitFor(() => expect(core.applyVaultBackupImport).toHaveBeenCalledWith("tok-vault-1", [{ id: "a3", action: "reemplazar" }]));
    expect(await screen.findByRole("status")).toHaveTextContent("Importación lista: 1 nuevas, 0 reemplazadas, 1 renombradas, 1 omitidas, 1 iguales.");
    expect(screen.queryByText("Vista previa de la importación")).not.toBeInTheDocument();
    await waitFor(() => expect(vi.mocked(core.listCredentials).mock.calls.length).toBeGreaterThan(1)); // recarga la lista
  });

  test("una frase incorrecta o un archivo ajeno se anuncian como error y no abren la vista previa", async () => {
    const core = fakeCore({
      pickPath: vi.fn(async () => "/home/u/r.mcvault"),
      previewVaultBackupImport: vi.fn(async () => { throw new Error("rpc error: code = PermissionDenied desc = la frase del respaldo es incorrecta (o el archivo está alterado)"); }),
    });
    render(<VaultView core={core} />);
    await userEvent.type(await screen.findByLabelText("Frase del respaldo a importar"), frase);
    await userEvent.click(screen.getByRole("button", { name: "Importar respaldo…" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("la frase del respaldo es incorrecta");
    expect(screen.queryByText("Vista previa de la importación")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Frase del respaldo a importar")).toHaveValue("");
  });

  test("si la vista previa venció o ya se usó, se pide abrir el respaldo de nuevo", async () => {
    const core = fakeCore({
      pickPath: vi.fn(async () => "/home/u/r.mcvault"),
      applyVaultBackupImport: vi.fn(async () => { throw new Error("rpc error: code = FailedPrecondition desc = la bóveda está cerrada"); }),
    });
    await abrirVistaPrevia(core);
    await userEvent.selectOptions(screen.getByLabelText("Qué hacer con Laboratorio"), "omitir");
    await userEvent.click(screen.getByRole("button", { name: "Aplicar importación" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("La vista previa venció o ya se usó");
    expect(screen.queryByText("Vista previa de la importación")).not.toBeInTheDocument();
  });

  const descartada = "La bóveda se cerró y, por seguridad, se descartó la vista previa del respaldo. Abre la bóveda y vuelve a abrir el archivo.";

  test("si al aplicar la bóveda ya está cerrada (por el estado, no por el texto del error) lo dice claro", async () => {
    let cerrada = false;
    const core = fakeCore({
      pickPath: vi.fn(async () => "/home/u/r.mcvault"),
      vaultStatus: vi.fn(async () => ({ state: cerrada ? ("locked" as const) : ("unlocked" as const), armedJobs: [] })),
      // El texto del error no dice nada de la bóveda: la UI mira el estado.
      applyVaultBackupImport: vi.fn(async () => { cerrada = true; throw new Error("rpc error: code = Internal desc = x"); }),
    });
    await abrirVistaPrevia(core);
    await userEvent.selectOptions(screen.getByLabelText("Qué hacer con Laboratorio"), "omitir");
    await userEvent.click(screen.getByRole("button", { name: "Aplicar importación" }));
    expect(await screen.findByText(descartada)).toBeInTheDocument();
    expect(screen.queryByText("Vista previa de la importación")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Contraseña maestra")).toBeInTheDocument(); // la vista pasó a la pantalla de bloqueo
  });

  test("si la bóveda se cierra con la vista previa abierta (por tiempo, paleta o botón) el aviso sale en la pantalla de bloqueo", async () => {
    let cerrada = false;
    const core = fakeCore({
      pickPath: vi.fn(async () => "/home/u/r.mcvault"),
      vaultStatus: vi.fn(async () => ({ state: cerrada ? ("locked" as const) : ("unlocked" as const), armedJobs: [] })),
    });
    await abrirVistaPrevia(core);
    cerrada = true;
    act(() => vaultChanged());
    expect(await screen.findByText(descartada)).toBeInTheDocument();
    expect(screen.getByLabelText("Contraseña maestra")).toBeInTheDocument();
  });

  test("al cerrar la bóveda sin vista previa no sale ese aviso", async () => {
    let cerrada = false;
    const core = fakeCore({ vaultStatus: vi.fn(async () => ({ state: cerrada ? ("locked" as const) : ("unlocked" as const), armedJobs: [] })) });
    render(<VaultView core={core} />);
    await screen.findByLabelText("Frase del respaldo");
    cerrada = true;
    act(() => vaultChanged());
    await screen.findByLabelText("Contraseña maestra");
    expect(screen.queryByText(descartada)).not.toBeInTheDocument();
  });

  test("una decisión mala deja corregir con la misma vista previa", async () => {
    const core = fakeCore({
      pickPath: vi.fn(async () => "/home/u/r.mcvault"),
      applyVaultBackupImport: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = falta decidir"); }),
    });
    await abrirVistaPrevia(core);
    await userEvent.selectOptions(screen.getByLabelText("Qué hacer con Laboratorio"), "omitir");
    await userEvent.click(screen.getByRole("button", { name: "Aplicar importación" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("falta decidir");
    expect(screen.getByText("Vista previa de la importación")).toBeInTheDocument();
  });
});

// Fase 44: credenciales con llave SSH (la privada nunca sale del núcleo).
const PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfake lab-key";
const keyCred = { id: "k1", label: "llave lab", username: "netops", kind: "key" as const, hasEnable: false, hasSshKey: true };
const pwCred = { id: "c1", label: "core", username: "admin", kind: "password" as const, hasEnable: false, hasSshKey: false };

test("crear credencial con llave pide solo etiqueta y usuario, y muestra la pública con Copiar e instrucciones Linux y Windows", async () => {
  const user = userEvent.setup();
  const core = fakeCore({ createKeyCredential: vi.fn(async () => ({ id: "k1", publicKey: PUB })) });
  render(<VaultView core={core} />);
  const form = (await screen.findByRole("button", { name: "Crear credencial con llave SSH" })).closest("form")!;
  expect(within(form).queryByLabelText(/Contraseña/)).not.toBeInTheDocument();
  await user.type(within(form).getByLabelText("Etiqueta de la llave"), "llave lab");
  await user.type(within(form).getByLabelText("Usuario de la llave"), "netops");
  await user.click(within(form).getByRole("button", { name: "Crear credencial con llave SSH" }));
  await waitFor(() => expect(core.createKeyCredential).toHaveBeenCalledWith("llave lab", "netops"));
  const shown = await screen.findByText(PUB);
  expect(shown).toHaveClass("mono");
  expect(screen.getByRole("region", { name: "Llave pública de llave lab" })).toHaveFocus();
  await user.click(screen.getByRole("button", { name: /Copiar/ }));
  expect(await navigator.clipboard.readText()).toBe(PUB);
  expect(screen.getByText(/~\/\.ssh\/authorized_keys/)).toBeInTheDocument();
  expect(screen.getByText(/si el usuario es administrador: C:\\ProgramData\\ssh\\administrators_authorized_keys/)).toBeInTheDocument();
  expect(screen.getByText(/icacls C:\\ProgramData\\ssh\\administrators_authorized_keys \/inheritance:r \/grant "\*S-1-5-32-544:F" \/grant "\*S-1-5-18:F"/)).toBeInTheDocument();
  expect(screen.getByText(/%USERPROFILE%\\\.ssh\\authorized_keys \(normalmente C:\\Users/)).toBeInTheDocument();
  expect(screen.getByText(/700.*600.*StrictModes/)).toBeInTheDocument();
  // El foco pasa a la pública recién creada y su título dice de qué credencial es.
  expect(screen.getByRole("heading", { name: "Llave pública de llave lab" })).toBeInTheDocument();
  expect(screen.getByText(/solo para Administradores y SYSTEM/)).toBeInTheDocument();
});

test("la lista distingue las de llave con una insignia y «Ver llave pública» la muestra con Copiar", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [pwCred, keyCred]), credentialPublicKey: vi.fn(async () => PUB) });
  render(<VaultView core={core} />);
  expect(await screen.findByText("llave lab")).toBeInTheDocument();
  expect(screen.getAllByText("Llave")).toHaveLength(1); // solo la de llave
  expect(screen.getAllByRole("button", { name: /Ver llave pública/ })).toHaveLength(1);
  await userEvent.click(screen.getByRole("button", { name: /Ver llave pública/ }));
  await waitFor(() => expect(core.credentialPublicKey).toHaveBeenCalledWith("k1"));
  expect(await screen.findByText(PUB)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Copiar/ })).toBeInTheDocument();
});

test("no hay forma de importar una llave privada", async () => {
  render(<VaultView core={fakeCore({ listCredentials: vi.fn(async () => [keyCred]) })} />);
  await screen.findByText("llave lab");
  expect(screen.queryByRole("button", { name: /importar.*(llave|privada)/i })).not.toBeInTheDocument();
  expect(document.querySelector("textarea")).toBeNull();
  expect(screen.queryByText(/importar llave|pegar llave/i)).not.toBeInTheDocument();
  expect(document.querySelector('input[type="file"]')).toBeNull();
});

test("la pública se muestra como texto inerte aunque traiga HTML", async () => {
  const evil = "<b>x</b><img src=x onerror=alert(1)>";
  const core = fakeCore({ listCredentials: vi.fn(async () => [keyCred]), credentialPublicKey: vi.fn(async () => evil) });
  render(<VaultView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: /Ver llave pública/ }));
  expect(await screen.findByText(evil)).toBeInTheDocument();
  expect(document.querySelector("img, .vault-pub b")).toBeNull();
});

test("ver la pública de A y luego la de B deja B aunque la respuesta de A llegue tarde", async () => {
  const a = { ...keyCred, id: "ka", label: "llave A" }, b = { ...keyCred, id: "kb", label: "llave B" };
  let resA!: (v: string) => void;
  const credentialPublicKey = vi.fn((id: string) => (id === "ka" ? new Promise<string>((r) => { resA = r; }) : Promise.resolve("ssh-ed25519 BBBB b")));
  render(<VaultView core={fakeCore({ listCredentials: vi.fn(async () => [a, b]), credentialPublicKey })} />);
  await userEvent.click(await screen.findByRole("button", { name: "Ver llave pública de llave A" }));
  await userEvent.click(screen.getByRole("button", { name: "Ver llave pública de llave B" }));
  expect(await screen.findByText("ssh-ed25519 BBBB b")).toBeInTheDocument();
  await act(async () => { resA("ssh-ed25519 AAAA a"); });
  expect(screen.queryByText("ssh-ed25519 AAAA a")).not.toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Llave pública de llave B" })).toBeInTheDocument();
});

test("borrar la credencial cuya pública está a la vista la quita de la pantalla", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [keyCred]), credentialPublicKey: vi.fn(async () => PUB) });
  render(<VaultView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: /Ver llave pública/ }));
  expect(await screen.findByText(PUB)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Eliminar llave lab" }));
  await userEvent.click(screen.getByRole("button", { name: "Confirmar eliminación de llave lab" }));
  await waitFor(() => expect(screen.queryByText(PUB)).not.toBeInTheDocument());
});

test("regenerar la llave pide confirmar, manda confirm=true y muestra la pública nueva con el aviso de autorizarla otra vez", async () => {
  const NEW = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInew lab-key";
  const core = fakeCore({ listCredentials: vi.fn(async () => [pwCred, keyCred]), regenerateKeyCredential: vi.fn(async () => NEW) });
  render(<VaultView core={core} />);
  await screen.findByText("llave lab");
  expect(screen.getAllByRole("button", { name: /Regenerar la llave de/ })).toHaveLength(1); // solo la de llave
  await userEvent.click(screen.getByRole("button", { name: "Regenerar la llave de llave lab" }));
  expect(core.regenerateKeyCredential).not.toHaveBeenCalled(); // primer clic: solo arma
  await userEvent.click(screen.getByRole("button", { name: "Confirmar: regenerar la llave de llave lab" }));
  await waitFor(() => expect(core.regenerateKeyCredential).toHaveBeenCalledWith("k1", true));
  expect(await screen.findByText(NEW)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Copiar/ })).toBeInTheDocument();
  expect(screen.getByText(/La pública anterior ya no sirve/)).toBeInTheDocument();
});

test("si mientras regenera se abre la pública de otra credencial, la respuesta tardía no la pisa y queda el aviso de éxito", async () => {
  const NEW = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInew lab-key";
  const key2 = { ...keyCred, id: "k2", label: "llave dos" };
  let done: (v: string) => void = () => {};
  const core = fakeCore({
    listCredentials: vi.fn(async () => [keyCred, key2]), credentialPublicKey: vi.fn(async () => PUB),
    regenerateKeyCredential: vi.fn(() => new Promise<string>((r) => { done = r; })),
  });
  render(<VaultView core={core} />);
  await screen.findByText("llave lab");
  await userEvent.click(screen.getByRole("button", { name: "Regenerar la llave de llave lab" }));
  await userEvent.click(screen.getByRole("button", { name: "Confirmar: regenerar la llave de llave lab" }));
  await userEvent.click(screen.getByRole("button", { name: /Ver llave pública.*llave dos/ }));
  expect(await screen.findByText(PUB)).toBeInTheDocument();
  await act(async () => { done(NEW); });
  expect(screen.getByText(PUB)).toBeInTheDocument();
  expect(screen.queryByText(NEW)).not.toBeInTheDocument();
  expect(screen.getByText(/La pública anterior ya no sirve/)).toBeInTheDocument();
});

test("regenerar la misma credencial con la pública a la vista remonta el cuadro y le devuelve el foco", async () => {
  const NEW = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInew lab-key";
  const core = fakeCore({ listCredentials: vi.fn(async () => [keyCred]), credentialPublicKey: vi.fn(async () => PUB), regenerateKeyCredential: vi.fn(async () => NEW) });
  render(<VaultView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: /Ver llave pública/ }));
  await screen.findByText(PUB);
  await userEvent.click(screen.getByRole("button", { name: "Regenerar la llave de llave lab" }));
  await userEvent.click(screen.getByRole("button", { name: "Confirmar: regenerar la llave de llave lab" }));
  await screen.findByText(NEW);
  expect(screen.getByRole("region", { name: "Llave pública de llave lab" })).toHaveFocus();
});

test("exportar avisa antes cuántas credenciales llevan llave privada y después cuántas entraron al archivo", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [pwCred, keyCred]), pickSavePath: vi.fn(async () => "/tmp/r.mcvault"), exportVaultBackup: vi.fn(async () => ({ count: 2, noPermissions: false, sshKeysIncluded: 1 })) });
  render(<VaultView core={core} />);
  expect(await screen.findByText(/el archivo llevará la llave privada de 1 credenciales/)).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("Frase del respaldo"), "una-frase-larga-1");
  await userEvent.type(screen.getByLabelText("Repite la frase del respaldo"), "una-frase-larga-1");
  await userEvent.click(screen.getByRole("checkbox", { name: /contiene todas mis credenciales/ }));
  await userEvent.click(screen.getByRole("button", { name: "Exportar respaldo…" }));
  expect(await screen.findByText(/El archivo lleva la llave privada de 1 credenciales\./)).toBeInTheDocument();
});

test("sin credenciales con llave no hay aviso de llaves privadas en el respaldo", async () => {
  render(<VaultView core={fakeCore({ listCredentials: vi.fn(async () => [pwCred]) })} />);
  await screen.findByText("core");
  expect(screen.queryByText(/llave privada/)).not.toBeInTheDocument();
});

// Bug de la v1.2.0: en una fila de llave (tres botones) «Confirmar eliminación de <etiqueta>» no cabía en la celda y se recortaba
// con «…»; el segundo clic no llegaba al botón. Armado, el texto visible es corto y el nombre accesible conserva la etiqueta.
test.each([
  ["llave", { id: "k1", label: "Raspberry", username: "pi", kind: "key" as const, hasEnable: false, hasSshKey: true }],
  ["contraseña", { id: "p1", label: "core", username: "admin", kind: "password" as const, hasEnable: false, hasSshKey: false }],
])("eliminar una credencial de %s: armado muestra un texto corto y el segundo clic la elimina", async (_k, c) => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [c]) });
  render(<VaultView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: `Eliminar ${c.label}` }));
  const armed = screen.getByRole("button", { name: `Confirmar eliminación de ${c.label}` });
  expect(armed).toHaveTextContent(/^Confirmar eliminación$/);
  await userEvent.click(armed);
  await waitFor(() => expect(core.deleteCredential).toHaveBeenCalledWith(c.id));
});

test("regenerar una llave: armado muestra un texto corto y conserva la etiqueta en el nombre accesible", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [{ id: "k1", label: "Raspberry", username: "pi", kind: "key" as const, hasEnable: false, hasSshKey: true }]) });
  render(<VaultView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: /^Regenerar la llave de Raspberry|^Regenerar llave/ }));
  expect(screen.getByRole("button", { name: "Confirmar: regenerar la llave de Raspberry" })).toHaveTextContent(/^Confirmar: regenerar$/);
});
