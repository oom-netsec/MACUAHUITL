import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SnippetsView } from "./SnippetsView";
import { fakeCore } from "../../lib/fake";
import { START, clickWhenReady, confirmStep } from "../../lib/assistTestkit";
import { samplePortSecurityPlan, sampleTemplates } from "./fake";
import type { SnippetTemplate } from "./api";
import { I18nProvider } from "../../lib/i18n";

const creds = [{ id: "c1", label: "lab", username: "admin", hasEnable: true, hasSshKey: false }];
const target = { name: "10.0.0.5", address: "10.0.0.5", credentialId: "c1" };

async function open(over: Partial<ReturnType<typeof fakeCore>> = {}) {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), ...over });
  render(<SnippetsView core={core} />);
  await userEvent.type(await screen.findByLabelText("Equipo (IP o nombre[:puerto])"), "10.0.0.5");
  return core;
}
const choose = async (name: string) => userEvent.click(await screen.findByRole("radio", { name }));
const planBtn = () => screen.getByRole("button", { name: "Planear (solo lectura)" });

// Una plantilla con un campo de cada tipo, para probar el renderer.
const all: SnippetTemplate = {
  id: "demo", tech: "gestion", name: "Demo de tipos", platforms: ["ios"],
  fields: [
    { name: "txt", label: "Texto", type: "text", required: true, max: 10, pattern: "^[a-z]+$" },
    { name: "n", label: "Entero", type: "int", min: 1, max: 100 },
    { name: "d", label: "Decimal", type: "decimal", max: 100 },
    { name: "b", label: "Casilla", type: "bool", help: "Ayuda de la casilla" },
    { name: "c", label: "Opción libre", type: "choice", choices: ["x", "y"] },
    { name: "cr", label: "Opción obligatoria", type: "choice", choices: ["add", "remove"], required: true },
    { name: "ip", label: "Dirección", type: "ipv4" },
    { name: "mk", label: "Máscara", type: "ipv4_mask" },
    { name: "if", label: "Puerto", type: "interface" },
    { name: "ifs", label: "Puertos", type: "interfaces" },
    { name: "v", label: "VLAN", type: "vlan_id" },
    { name: "pw", label: "Clave", type: "secret" },
    { name: "dflt", label: "Con sugerido", type: "int", defaultValue: "30" },
  ],
};
const withDemo = { listSnippetTemplates: vi.fn(async () => [...sampleTemplates, all]) };
const rpc = (code: string, desc: string) => new Error(`rpc error: code = ${code} desc = ${desc}`);

test("el selector agrupa por tecnología en el orden del catálogo, con su nombre en español", async () => {
  await open();
  const legends = (await screen.findAllByRole("group")).map((g) => within(g).queryByText(/^Capa/)?.textContent).filter(Boolean);
  expect(legends).toEqual(["Capa 2", "Capa 3"]);
  const l3 = screen.getByText("Capa 3").closest("fieldset")!;
  expect(within(l3).getAllByRole("radio").map((r) => r.id)).toEqual(["sn-svi"]);
  expect(within(screen.getByText("Capa 2").closest("fieldset")!).getAllByRole("radio")).toHaveLength(5);
});

test("la búsqueda filtra por nombre sin importar acentos ni mayúsculas, y avisa si nada coincide", async () => {
  await open();
  await screen.findByRole("radio", { name: "Port-security en puertos de acceso" });
  await userEvent.type(screen.getByLabelText("Buscar plantilla"), "VELOCIDAD");
  expect(screen.getAllByRole("radio").map((r) => r.id)).toEqual(["sn-speed-duplex"]);
  expect(screen.queryByText("Capa 3")).not.toBeInTheDocument();
  await userEvent.clear(screen.getByLabelText("Buscar plantilla"));
  await userEvent.type(screen.getByLabelText("Buscar plantilla"), "zzz");
  expect(screen.getByText("Ninguna plantilla coincide.")).toBeInTheDocument();
});

test("la plataforma filtra el catálogo desde el núcleo y suelta la plantilla que ya no aplica", async () => {
  const list = vi.fn(async (p?: string) => (p === "ios-xe" ? [sampleTemplates[0]] : sampleTemplates));
  await open({ listSnippetTemplates: list } as never);
  await choose("Port-security en puertos de acceso");
  expect(list).toHaveBeenCalledWith("");
  await userEvent.selectOptions(screen.getByLabelText("Plataforma"), "ios-xe");
  expect(list).toHaveBeenLastCalledWith("ios-xe");
  await screen.findByRole("radio", { name: "Velocidad y duplex de puertos" });
  expect(screen.getAllByRole("radio")).toHaveLength(1);
  expect(screen.queryByLabelText("Máximo de direcciones MAC")).not.toBeInTheDocument();
});

test("un control por tipo de campo, con obligatorios marcados y la ayuda del núcleo", async () => {
  await open(withDemo as never);
  await choose("Demo de tipos");
  expect(screen.getByLabelText("Texto *")).toHaveAttribute("type", "text");
  expect(screen.getByLabelText("Entero")).toHaveAttribute("inputmode", "numeric");
  expect(screen.getByLabelText("Decimal")).toHaveAttribute("inputmode", "decimal");
  expect(screen.getByLabelText("Casilla")).toHaveAttribute("type", "checkbox");
  expect(screen.getByText("Ayuda de la casilla")).toBeInTheDocument();
  const opts = (l: string) => within(screen.getByLabelText(l)).getAllByRole("option").map((o) => (o as HTMLOptionElement).value);
  expect(opts("Opción libre")).toEqual(["", "x", "y"]); // vacío = no tocar
  expect(opts("Opción obligatoria *")).toEqual(["", "add", "remove"]); // obligatoria sin sugerido: «— elige —» deshabilitada
  expect(screen.getByRole("option", { name: "— elige —" })).toBeDisabled();
  expect(screen.getByLabelText("Opción obligatoria *")).toHaveValue("");
  expect(screen.getByLabelText("Opción obligatoria *")).toHaveAttribute("aria-required", "true");
  expect(screen.getByLabelText("Texto *")).toHaveAttribute("aria-required", "true");
  expect(screen.getByLabelText("Entero")).not.toHaveAttribute("aria-required");
  const pw = screen.getByLabelText("Clave");
  expect(pw).toHaveAttribute("type", "password");
  expect(pw).toHaveAttribute("autocomplete", "off");
  expect(screen.getByLabelText("Puertos")).toHaveAccessibleDescription(/rangos sobre el último número/);
});

test("solo defaultValue prellena; lo demás queda vacío y viaja vacío", async () => {
  const core = await open(withDemo as never);
  await choose("Demo de tipos");
  expect(screen.getByLabelText("Con sugerido")).toHaveValue("30");
  for (const l of ["Entero", "Decimal", "Dirección", "Máscara", "Puerto", "Puertos", "VLAN", "Clave"]) expect(screen.getByLabelText(l)).toHaveValue("");
  expect(screen.getByLabelText("Opción libre")).toHaveValue("");
  await userEvent.type(screen.getByLabelText("Texto *"), "abc");
  expect(planBtn()).toBeDisabled(); // falta elegir la opción obligatoria
  await userEvent.selectOptions(screen.getByLabelText("Opción obligatoria *"), "add");
  await userEvent.click(planBtn());
  expect(core.planTemplateSnippet).toHaveBeenCalledWith({
    target, id: "demo",
    values: { txt: "abc", n: "", d: "", b: "", c: "", cr: "add", ip: "", mk: "", if: "", ifs: "", v: "", pw: "", dflt: "30" },
  });
});

test("el cliente solo ayuda: marca el campo y apaga el botón, sin mandar nada", async () => {
  const core = await open(withDemo as never);
  await choose("Demo de tipos");
  await userEvent.type(screen.getByLabelText("Texto *"), "abc");
  await userEvent.selectOptions(screen.getByLabelText("Opción obligatoria *"), "add");
  expect(planBtn()).toBeEnabled();
  const bad: [string, string, RegExp][] = [
    ["Entero", "101", /Entero entre 1 y 100/], ["Decimal", "5.555", /dos decimales/], ["Dirección", "10.0.0.300", /IPv4/], ["Máscara", "24", /Máscara decimal/],
    ["Puerto", "Gi1/0/1-4", /Un puerto/], ["VLAN", "4095", /1 a 4094/], ["Texto *", "ABC", /formato/],
  ];
  for (const [label, v, msg] of bad) {
    const el = screen.getByLabelText(label);
    const prev = (el as HTMLInputElement).value;
    await userEvent.clear(el);
    await userEvent.type(el, v);
    expect(await screen.findByText(msg)).toBeInTheDocument();
    expect(planBtn()).toBeDisabled();
    await userEvent.clear(el);
    if (prev) await userEvent.type(el, prev);
    expect(planBtn()).toBeEnabled();
  }
  expect(core.planTemplateSnippet).not.toHaveBeenCalled();
});

test("interfaces: más de 48 puertos se marca; 48 pasa", async () => {
  await open();
  await choose("Velocidad y duplex de puertos");
  await userEvent.type(screen.getByLabelText("Puertos *"), "Gi1/0/1-49");
  expect(screen.getByText("Son 49 puertos y el máximo es 48.")).toBeInTheDocument();
  expect(planBtn()).toBeDisabled();
  await userEvent.clear(screen.getByLabelText("Puertos *"));
  await userEvent.type(screen.getByLabelText("Puertos *"), "Gi1/0/1-48");
  expect(planBtn()).toBeEnabled();
});

test("falta un obligatorio: no se puede planear", async () => {
  await open();
  await choose("Interfaz VLAN (SVI) con dirección IP");
  await userEvent.type(screen.getByLabelText("VLAN *"), "99");
  await userEvent.type(screen.getByLabelText("Dirección IP *"), "10.9.9.1");
  expect(screen.getByLabelText("Máscara *")).toHaveValue("255.255.255.0"); // el núcleo la sugiere con defaultValue
  expect(planBtn()).toBeEnabled();
  await userEvent.clear(screen.getByLabelText("Máscara *"));
  expect(planBtn()).toBeDisabled();
});

test("vlan, trunk y svi quedan cubiertos por el formulario genérico", async () => {
  const core = await open();
  await choose("Crear, nombrar o borrar una VLAN");
  await userEvent.type(screen.getByLabelText("VLAN *"), "30");
  await userEvent.type(screen.getByLabelText("Nombre"), "Cuarentena");
  await userEvent.click(screen.getByLabelText("Borrar la VLAN"));
  await userEvent.click(screen.getByLabelText(/Aceptar que se propague por VTP/));
  await userEvent.click(screen.getByLabelText(/Aceptar borrar una VLAN que viaja/));
  await userEvent.click(planBtn());
  expect(core.planTemplateSnippet).toHaveBeenLastCalledWith({
    target, id: "vlan", values: { id: "30", name: "Cuarentena", remove: "true", accept_vtp: "true", accept_trunk: "true" },
  });
  await choose("Agregar o quitar una VLAN de un trunk");
  await userEvent.type(screen.getByLabelText("Trunk *"), "Gi1/0/48");
  await userEvent.type(screen.getByLabelText("VLAN *"), "30");
  await userEvent.selectOptions(screen.getByLabelText("Operación *"), "remove");
  await userEvent.click(planBtn());
  expect(core.planTemplateSnippet).toHaveBeenLastCalledWith({ target, id: "trunk", values: { interface: "Gi1/0/48", op: "remove", vlan: "30" } });
  expect(core.assistPlanSnippet).not.toHaveBeenCalled();
});

const withReason = (e: Error, reason: string, metadata: Record<string, string>) => Object.assign(e, { cause: { message: e.message, code: e.message.match(/code = (\w+)/)?.[1] ?? "", reason, metadata } });

test("assist.invalid_value: el primer problema se muestra por su motivo (i18n) y no por el texto del núcleo", async () => {
  const msg = "assist: invalid snippet values: Max MAC (maximum): 5000 out of range; zz unknown";
  await open({ planTemplateSnippet: vi.fn(async () => { throw withReason(rpc("InvalidArgument", msg), "assist.invalid_value", { template: "port-security", field: "maximum", why: "range" }); }) } as never);
  await choose("Port-security en puertos de acceso");
  await userEvent.type(screen.getByLabelText("Puertos *"), "Gi1/0/5");
  await userEvent.click(planBtn());
  expect(await screen.findByText("Fuera de rango.")).toBeInTheDocument();
  expect(screen.getByLabelText("Máximo de direcciones MAC")).toBeInvalid();
  expect(screen.queryByText(/out of range/)).not.toBeInTheDocument();
});

test("assist.refused: el aviso lleva el motivo sin el prefijo del núcleo, sea cual sea su idioma", async () => {
  await open({ planTemplateSnippet: vi.fn(async () => { throw withReason(rpc("FailedPrecondition", "assist: device does not support this snippet: sin SVI"), "assist.refused", { template: "svi", device: "x" }); }) } as never);
  await choose("Port-security en puertos de acceso");
  await userEvent.type(screen.getByLabelText("Puertos *"), "Gi1/0/5");
  await userEvent.click(planBtn());
  expect(await screen.findByText("El equipo no admite este snippet: sin SVI")).toBeInTheDocument();
});

test("InvalidArgument del núcleo: cada motivo queda junto al campo que nombra y el resto en un aviso", async () => {
  const msg = "assist: valores del snippet inválidos: falta Puertos (interfaces); Máximo de direcciones MAC (maximum): 5000 fuera de rango; Acción ante violación (violation): valor no permitido; campo desconocido \"zz\"";
  const core = await open({ planTemplateSnippet: vi.fn(async () => { throw rpc("InvalidArgument", msg); }) } as never);
  await choose("Port-security en puertos de acceso");
  await userEvent.type(screen.getByLabelText("Puertos *"), "Gi1/0/5");
  await userEvent.click(planBtn());
  expect(await screen.findByText("5000 fuera de rango")).toBeInTheDocument();
  expect(screen.getByLabelText("Máximo de direcciones MAC")).toHaveAccessibleDescription(/5000 fuera de rango/);
  expect(screen.getByLabelText("Máximo de direcciones MAC")).toBeInvalid();
  expect(screen.getByLabelText("Acción ante violación")).toHaveAccessibleDescription(/valor no permitido/);
  expect(screen.getByLabelText("Puertos *")).toHaveAccessibleDescription(/falta Puertos \(interfaces\)/); // el prefijo del núcleo no la separa de su campo
  expect(screen.getByText("falta Puertos (interfaces)")).toBeInTheDocument(); // sin el prefijo «assist: …»
  expect(screen.getByLabelText("Puertos *")).toBeInvalid();
  expect(screen.getByRole("alert")).toHaveTextContent('campo desconocido "zz"');
  // Corregir el campo limpia su error.
  await userEvent.clear(screen.getByLabelText("Máximo de direcciones MAC"));
  await userEvent.type(screen.getByLabelText("Máximo de direcciones MAC"), "2");
  expect(screen.queryByText("5000 fuera de rango")).not.toBeInTheDocument();
  expect(core.assistStart).not.toHaveBeenCalled();
});

test("FailedPrecondition se muestra tal cual como aviso y no deja iniciar nada", async () => {
  await open({ planTemplateSnippet: vi.fn(async () => { throw rpc("FailedPrecondition", "Gi1/0/5 es un puerto trunk: port-security no aplica"); }) } as never);
  await choose("Port-security en puertos de acceso");
  await userEvent.type(screen.getByLabelText("Puertos *"), "Gi1/0/5");
  await userEvent.click(planBtn());
  const note = await screen.findByText("Gi1/0/5 es un puerto trunk: port-security no aplica");
  expect(note.closest(".notice")).toHaveClass("warn");
  expect(screen.queryByRole("button", { name: START })).not.toBeInTheDocument();
});

test("otro fallo (red, bóveda) se muestra como error", async () => {
  await open({ planTemplateSnippet: vi.fn(async () => { throw rpc("Unavailable", "sin conexión con el equipo"); }) } as never);
  await choose("Velocidad y duplex de puertos");
  await userEvent.type(screen.getByLabelText("Puertos *"), "Gi1/0/5");
  await userEvent.click(planBtn());
  expect(await screen.findByRole("alert")).toHaveTextContent("sin conexión con el equipo");
});

test("los avisos del plan salen antes del botón de iniciar, que solo existe tras planear", async () => {
  const core = await open();
  await choose("Port-security en puertos de acceso");
  await userEvent.type(screen.getByLabelText("Puertos *"), "Gi1/0/5");
  expect(screen.queryByRole("button", { name: START })).not.toBeInTheDocument(); // antes del plan no hay nada que iniciar
  await userEvent.click(planBtn());
  const notes = await screen.findByText("Avisos del plan: léelos antes de iniciar");
  expect(screen.getByText(/La reversa no saca un puerto de err-disabled/)).toBeInTheDocument();
  expect(notes.closest(".notice")).toHaveClass("warn");
  const start = screen.getByRole("button", { name: START });
  expect(start).toBeDisabled();
  expect(notes.compareDocumentPosition(start) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(core.assistStart).not.toHaveBeenCalled();
  await userEvent.click(screen.getByLabelText("Activar el modo asistido para esta ejecución"));
  await userEvent.click(start);
  expect(core.assistStart).toHaveBeenCalledWith(samplePortSecurityPlan.planId, true);
});

test("un plan sin avisos no muestra el recuadro de avisos", async () => {
  await open();
  await choose("Agregar o quitar una VLAN de un trunk");
  await userEvent.type(screen.getByLabelText("Trunk *"), "Gi1/0/48");
  await userEvent.type(screen.getByLabelText("VLAN *"), "30");
  await userEvent.click(planBtn());
  await screen.findByRole("region", { name: "Reversa" });
  expect(screen.queryByText("Avisos del plan: léelos antes de iniciar")).not.toBeInTheDocument();
});

test("editar un dato después de planear descarta el plan (ya no corresponde al formulario)", async () => {
  await open();
  await choose("Port-security en puertos de acceso");
  await userEvent.type(screen.getByLabelText("Puertos *"), "Gi1/0/5");
  await userEvent.click(planBtn());
  await screen.findByRole("region", { name: "Reversa" });
  await userEvent.type(screen.getByLabelText("Máximo de direcciones MAC"), "2");
  expect(screen.queryByRole("region", { name: "Reversa" })).not.toBeInTheDocument();
});

test("el secreto va por password, viaja una vez y no se muestra en ningún texto de la vista", async () => {
  const core = await open({
    listSnippetTemplates: vi.fn(async () => [sampleTemplates[0], { id: "snmp", tech: "gestion", name: "Credencial de ejemplo", platforms: ["ios"], fields: [{ name: "key", label: "Clave", type: "secret", required: true }] }]),
    planTemplateSnippet: vi.fn(async () => { throw rpc("InvalidArgument", "Clave (key): demasiado corta"); }),
  } as never);
  await choose("Credencial de ejemplo");
  await userEvent.type(screen.getByLabelText("Clave *"), "S3cretoXYZ");
  await userEvent.click(planBtn());
  expect(core.planTemplateSnippet).toHaveBeenCalledWith(expect.objectContaining({ values: { key: "S3cretoXYZ" } }));
  expect(await screen.findByText("demasiado corta")).toBeInTheDocument();
  expect(document.body.textContent).not.toContain("S3cretoXYZ");
  expect(screen.getByLabelText("Clave *")).toHaveAttribute("type", "password");
  expect(screen.getByLabelText("Clave *")).toHaveAttribute("aria-required", "true"); // lo único que lo contiene es su propio campo enmascarado
  // Cambiar de plantilla no lo arrastra.
  await choose("Velocidad y duplex de puertos");
  await choose("Credencial de ejemplo");
  expect(screen.getByLabelText("Clave *")).toHaveValue("");
});

test("ejecución asistida: la casilla es por ejecución, el aviso rojo y la confirmación por paso", async () => {
  const core = await open();
  await choose("Agregar o quitar una VLAN de un trunk");
  await userEvent.type(screen.getByLabelText("Trunk *"), "Gi1/0/48");
  await userEvent.type(screen.getByLabelText("VLAN *"), "30");
  await userEvent.click(planBtn());
  await screen.findByRole("region", { name: "Reversa" });
  expect(core.assistStart).not.toHaveBeenCalled();
  await userEvent.click(screen.getByLabelText("Activar el modo asistido para esta ejecución"));
  await userEvent.click(screen.getByRole("button", { name: START }));
  expect(core.assistStart).toHaveBeenCalledWith("s1", true);
  expect(await screen.findByRole("alert")).toHaveTextContent("MODO ASISTIDO ACTIVO");
  act(() => core.emitAssist({ runId: "r1", kind: "pending", state: "waiting-confirm", step: { id: "apply-1", kind: "apply", device: "SW1", lines: ["interface Gi1/0/48", "switchport trunk allowed vlan add 30"] } }));
  const step = within(await screen.findByRole("region", { name: "Paso pendiente apply-1" }));
  expect(core.assistConfirm).not.toHaveBeenCalled();
  await clickWhenReady(step.getByRole("button", { name: confirmStep("apply-1") }));
  expect(core.assistConfirm).toHaveBeenCalledWith("r1", "apply-1");
  act(() => core.emitAssist({ runId: "r1", kind: "state", state: "done" }));
  act(() => core.emitAssistDone({ runId: "r1" }));
  expect(await screen.findByText(/Listo: el cambio/)).toBeInTheDocument();
});

test("write memory y huellas aceptadas siguen yendo en la petición", async () => {
  const core = await open();
  await choose("Velocidad y duplex de puertos");
  await userEvent.type(screen.getByLabelText("Puertos *"), "Gi1/0/1");
  await userEvent.click(screen.getByLabelText(/write memory/));
  await userEvent.type(screen.getByLabelText(/huellas|fingerprint/i), "SHA256:abc");
  await userEvent.click(planBtn());
  expect(core.planTemplateSnippet).toHaveBeenCalledWith({
    target, id: "speed-duplex", values: { interfaces: "Gi1/0/1", speed: "", duplex: "" }, writeMemory: true, acceptedHostKeyFingerprints: ["SHA256:abc"],
  });
});

// Una promesa que se resuelve o rechaza a mano, para editar mientras el plan sigue pendiente.
const deferred = <T,>() => {
  let resolve!: (v: T) => void, reject!: (e: unknown) => void;
  const promise = new Promise<T>((a, b) => { resolve = a; reject = b; });
  return { promise, resolve, reject };
};
const fillSpeed = async () => { await choose("Velocidad y duplex de puertos"); await userEvent.type(screen.getByLabelText("Puertos *"), "Gi1/0/1"); };

test("un plan que llega después de editar el formulario no se muestra ni se puede ejecutar", async () => {
  const d = deferred<typeof samplePortSecurityPlan>();
  const core = await open({ planTemplateSnippet: vi.fn(() => d.promise) } as never);
  await fillSpeed();
  await userEvent.click(planBtn());
  await userEvent.type(screen.getByLabelText("Puertos *"), "2"); // edita con el plan en vuelo
  await act(async () => { d.resolve(samplePortSecurityPlan); });
  expect(screen.queryByRole("region", { name: "Reversa" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: START })).not.toBeInTheDocument();
  expect(core.assistStart).not.toHaveBeenCalled();
});

test("un rechazo que llega después de editar tampoco se muestra", async () => {
  const d = deferred<never>();
  await open({ planTemplateSnippet: vi.fn(() => d.promise) } as never);
  await fillSpeed();
  await userEvent.click(planBtn());
  await userEvent.type(screen.getByLabelText("Puertos *"), "2");
  await act(async () => { d.reject(rpc("FailedPrecondition", "motivo viejo")); });
  expect(screen.queryByText("motivo viejo")).not.toBeInTheDocument();
});

test("cambiar write memory, equipo, credencial, huellas o plataforma después de planear descarta el plan", async () => {
  const plan = async () => {
    await userEvent.click(planBtn());
    await screen.findByRole("region", { name: "Reversa" });
  };
  const gone = () => expect(screen.queryByRole("region", { name: "Reversa" })).not.toBeInTheDocument();
  await open({ listCredentials: vi.fn(async () => [...creds, { ...creds[0], id: "c2", label: "otra" }]) } as never);
  await fillSpeed();
  await plan();
  await userEvent.click(screen.getByLabelText(/write memory/));
  gone();
  await plan();
  await userEvent.type(screen.getByLabelText(/Huellas SHA256/), "x");
  gone();
  await plan();
  await userEvent.type(screen.getByLabelText("Equipo (IP o nombre[:puerto])"), "1");
  gone();
  await plan();
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c2");
  gone();
  await plan();
  await userEvent.selectOptions(screen.getByLabelText("Plataforma"), "ios");
  gone();
});

test("write memory con el plan en vuelo: la respuesta del plan viejo se descarta", async () => {
  const d = deferred<typeof samplePortSecurityPlan>();
  await open({ planTemplateSnippet: vi.fn(() => d.promise) } as never);
  await fillSpeed();
  await userEvent.click(planBtn());
  await userEvent.click(screen.getByLabelText(/write memory/));
  await act(async () => { d.resolve(samplePortSecurityPlan); });
  expect(screen.queryByRole("region", { name: "Reversa" })).not.toBeInTheDocument();
});

test("una opción obligatoria con valor sugerido se queda con él y no ofrece «— elige —»", async () => {
  await open();
  await choose("Agregar o quitar una VLAN de un trunk");
  expect(screen.getByLabelText("Operación *")).toHaveValue("add");
  expect(within(screen.getByLabelText("Operación *")).queryByRole("option", { name: "— elige —" })).not.toBeInTheDocument();
});

test("un campo con min 2 explica su rango real y se valida recortado", async () => {
  const core = await open();
  await choose("Crear, nombrar o borrar una VLAN");
  await userEvent.type(screen.getByLabelText("VLAN *"), "1");
  expect(screen.getByText("VLAN de 2 a 4094.")).toBeInTheDocument();
  expect(planBtn()).toBeDisabled();
  await userEvent.clear(screen.getByLabelText("VLAN *"));
  await userEvent.type(screen.getByLabelText("VLAN *"), " 30 ");
  expect(screen.queryByText("VLAN de 2 a 4094.")).not.toBeInTheDocument(); // el espacio se recorta, igual que lo que viaja
  await userEvent.click(planBtn());
  expect(core.planTemplateSnippet).toHaveBeenCalledWith(expect.objectContaining({ values: expect.objectContaining({ id: "30" }) }));
});

test("la casilla liga su ayuda y su error con aria-describedby", async () => {
  await open({ planTemplateSnippet: vi.fn(async () => { throw rpc("InvalidArgument", "assist: valores del snippet inválidos: Borrar la VLAN (remove): no admite nombre"); }) } as never);
  await choose("Crear, nombrar o borrar una VLAN");
  await userEvent.type(screen.getByLabelText("VLAN *"), "30");
  expect(screen.getByLabelText("Borrar la VLAN")).toHaveAccessibleDescription(/Solo una VLAN activa/);
  await userEvent.click(planBtn());
  expect(await screen.findByText("no admite nombre")).toBeInTheDocument();
  expect(screen.getByLabelText("Borrar la VLAN")).toHaveAccessibleDescription(/no admite nombre/);
});

test("en inglés, la plantilla y sus campos salen de las claves snippet.<id>.*", async () => {
  localStorage.setItem("macuahuitl.idioma", "en");
  try {
    const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
    render(<I18nProvider><SnippetsView core={core} /></I18nProvider>);
    await userEvent.click(await screen.findByRole("radio", { name: "Port speed and duplex" }));
    expect(screen.getByLabelText("Ports *")).toBeInTheDocument();
    expect(screen.getByLabelText("Speed")).toHaveAccessibleDescription("Empty leaves it untouched. auto returns it to negotiation.");
    expect(screen.getByText("Layer 2")).toBeInTheDocument();
  } finally { localStorage.removeItem("macuahuitl.idioma"); }
});

test("cambiar de plantilla con el plan en vuelo descarta la respuesta", async () => {
  const d = deferred<typeof samplePortSecurityPlan>();
  await open({ planTemplateSnippet: vi.fn(() => d.promise) } as never);
  await fillSpeed();
  await userEvent.click(planBtn());
  await choose("Storm-control de puertos");
  await act(async () => { d.resolve(samplePortSecurityPlan); });
  expect(screen.queryByRole("region", { name: "Reversa" })).not.toBeInTheDocument();
});

test("un vlan_id con min y max propios los usa en la validación y en el mensaje", async () => {
  const lim: SnippetTemplate = { id: "lim", tech: "l2", name: "Con límites", platforms: ["ios"], fields: [{ name: "v", label: "VLAN acotada", type: "vlan_id", min: 10, max: 20 }] };
  await open({ listSnippetTemplates: vi.fn(async () => [lim]) } as never);
  await choose("Con límites");
  await userEvent.type(screen.getByLabelText("VLAN acotada"), "25");
  expect(screen.getByText("VLAN de 10 a 20.")).toBeInTheDocument();
  await userEvent.clear(screen.getByLabelText("VLAN acotada"));
  await userEvent.type(screen.getByLabelText("VLAN acotada"), "15");
  expect(screen.queryByText("VLAN de 10 a 20.")).not.toBeInTheDocument();
});
