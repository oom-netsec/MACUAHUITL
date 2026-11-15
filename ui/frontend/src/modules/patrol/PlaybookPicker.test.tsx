import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { PlaybookPicker } from "./PlaybookPicker";
import { samplePlaybooks } from "./fake";

function Harness({ initial = [] as string[] }) {
  const [sel, setSel] = useState<string[]>(initial);
  return <><PlaybookPicker playbooks={samplePlaybooks} selected={sel} onChange={setSel} /><output aria-label="elegidos">{sel.join(",")}</output></>;
}
const chosen = () => screen.getByLabelText("elegidos").textContent;

test("agrupa por el área antes del «·», cuenta comandos y permite elegir varios", async () => {
  render(<Harness />);
  for (const a of ["L2", "TAC"]) await userEvent.click(screen.getByRole("button", { name: new RegExp(`^${a}`) }));
  const l2 = screen.getByRole("group", { name: /^L2/ });
  expect(within(l2).getByRole("checkbox", { name: /STP/ })).toBeInTheDocument();
  expect(screen.getByRole("group", { name: /^TAC/ })).toBeInTheDocument();
  await userEvent.click(within(l2).getByRole("checkbox", { name: /STP/ }));
  await userEvent.click(screen.getByRole("checkbox", { name: /Usuario sin red/ }));
  expect(chosen()).toBe("ios-xe/l2-stp,ios-xe/tac-usuario-sin-red");
  expect(screen.getByText("2 playbooks seleccionados")).toBeInTheDocument();
  await userEvent.click(within(l2).getByRole("checkbox", { name: /STP/ }));
  expect(chosen()).toBe("ios-xe/tac-usuario-sin-red");
});

test("la búsqueda filtra por nombre, id o comando y sin coincidencias lo dice", async () => {
  render(<Harness />);
  const q = screen.getByRole("searchbox", { name: "Buscar playbook" });
  await userEvent.type(q, "spanning");
  expect(screen.getByRole("checkbox", { name: /STP/ })).toBeInTheDocument();
  expect(screen.queryByRole("checkbox", { name: /OSPF/ })).not.toBeInTheDocument();
  await userEvent.clear(q);
  await userEvent.type(q, "zzz");
  expect(screen.getByText("Ningún playbook coincide con la búsqueda.")).toBeInTheDocument();
});

test("un elegido que la búsqueda oculta sigue elegido y se ve el resumen", async () => {
  render(<Harness initial={["ios-xe/l3-ospf"]} />);
  await userEvent.type(screen.getByRole("searchbox", { name: "Buscar playbook" }), "stp");
  expect(chosen()).toBe("ios-xe/l3-ospf");
  expect(screen.getByText("1 playbook seleccionado")).toBeInTheDocument();
});

test("muestra los comandos de cada playbook antes de elegirlo", async () => {
  render(<Harness />);
  await userEvent.click(screen.getByRole("button", { name: /^L2/ }));
  const stp = screen.getByRole("checkbox", { name: "STP" }).closest(".pb-item")!;
  await userEvent.click(within(stp as HTMLElement).getByText("Comandos (4)"));
  expect(screen.getByText("show spanning-tree detail")).toBeInTheDocument();
});

test("el contrato de Wails tolera las listas vacías que omite protojson", async () => {
  const { patrolWails } = await import("./api");
  const api = (json: string) => patrolWails((async () => json) as never);
  expect(await api("{}").listPlaybooks()).toEqual([]);
  expect(await api('{"playbooks":[{"id":"ios-xe/l2-stp","platform":"ios-xe","name":"L2 · STP"}]}').listPlaybooks())
    .toEqual([{ id: "ios-xe/l2-stp", platform: "ios-xe", name: "L2 · STP", commands: [], params: [], pack: "" }]);
});

test("un playbook sin id no llega al selector", async () => {
  const { patrolWails } = await import("./api");
  expect(await patrolWails((async () => '{"playbooks":[{"name":"roto"},{"id":"ios-xe/x","name":"X"}]}') as never).listPlaybooks()).toHaveLength(1);
});

test("cada fila muestra su paquete de origen y la búsqueda lo encuentra", async () => {
  const pbs = [
    { id: "a/uno", platform: "ios-xe", name: "L2 · Uno", commands: ["show a"], params: [], pack: "oom/cat9k" },
    { id: "a/dos", platform: "ios-xe", name: "L2 · Dos", commands: ["show b"], params: [], pack: "usuario" },
    { id: "a/tres", platform: "ios-xe", name: "L2 · Tres", commands: ["show c"], params: [], pack: "" },
  ];
  render(<PlaybookPicker playbooks={pbs} selected={[]} onChange={() => {}} />);
  await userEvent.click(screen.getByRole("button", { name: /^L2/ }));
  expect(screen.getByText("oom/cat9k")).toBeInTheDocument();
  expect(screen.getByText("Propio")).toBeInTheDocument();
  expect(screen.getByText("Base")).toBeInTheDocument();
  await userEvent.type(screen.getByRole("searchbox", { name: "Buscar playbook" }), "cat9k");
  expect(screen.queryByRole("checkbox", { name: /Dos/ })).not.toBeInTheDocument();
  expect(screen.getByRole("checkbox", { name: /Uno/ })).toBeInTheDocument();
  await userEvent.clear(screen.getByRole("searchbox", { name: "Buscar playbook" }));
  await userEvent.type(screen.getByRole("searchbox", { name: "Buscar playbook" }), "propio"); // busca lo que la etiqueta muestra
  expect(screen.getByRole("checkbox", { name: /Dos/ })).toBeInTheDocument();
  expect(screen.queryByRole("checkbox", { name: /Uno/ })).not.toBeInTheDocument();
});

const hdr = (a: string) => screen.getByRole("button", { name: new RegExp(`^${a}`) });
const all = (a: string) => screen.getByRole("checkbox", { name: `Seleccionar todo ${a}` }) as HTMLInputElement;

test("los grupos arrancan plegados con su conteo y aria-expanded", async () => {
  render(<Harness />);
  expect(hdr("L2")).toHaveAttribute("aria-expanded", "false");
  expect(hdr("L2")).toHaveTextContent("(0 seleccionados / 2)");
  expect(hdr("L3")).toHaveTextContent("(0 seleccionados / 1)");
  expect(screen.queryByRole("checkbox", { name: "STP" })).not.toBeInTheDocument();
  await userEvent.click(hdr("L2"));
  expect(hdr("L2")).toHaveAttribute("aria-expanded", "true");
  expect(screen.getByRole("checkbox", { name: "STP" })).toBeInTheDocument();
  expect(document.getElementById(hdr("L2").getAttribute("aria-controls")!)).toContainElement(screen.getByRole("checkbox", { name: "STP" }));
});

test("el teclado pliega y despliega con Enter y Espacio", async () => {
  render(<Harness />);
  hdr("L3").focus();
  await userEvent.keyboard("{Enter}");
  expect(hdr("L3")).toHaveAttribute("aria-expanded", "true");
  await userEvent.keyboard(" ");
  expect(hdr("L3")).toHaveAttribute("aria-expanded", "false");
});

test("un grupo con algo elegido arranca desplegado y el conteo singular dice 1", () => {
  render(<Harness initial={["ios-xe/l3-ospf"]} />);
  expect(hdr("L3")).toHaveAttribute("aria-expanded", "true");
  expect(hdr("L3")).toHaveTextContent("(1 seleccionado / 1)");
  expect(hdr("L2")).toHaveAttribute("aria-expanded", "false");
});

test("la búsqueda despliega los grupos con resultados; vaciarla vuelve a la regla y respeta lo manual", async () => {
  render(<Harness />);
  const q = screen.getByRole("searchbox", { name: "Buscar playbook" });
  await userEvent.type(q, "stp");
  expect(hdr("L2")).toHaveAttribute("aria-expanded", "true");
  expect(screen.queryByRole("button", { name: /^TAC/ })).not.toBeInTheDocument();
  await userEvent.click(hdr("L2")); // la persona lo cierra a mano
  expect(hdr("L2")).toHaveAttribute("aria-expanded", "false");
  await userEvent.clear(q);
  expect(hdr("L2")).toHaveAttribute("aria-expanded", "false");
  expect(hdr("TAC")).toHaveAttribute("aria-expanded", "false");
});

test("la casilla del grupo elige y quita lo visible, queda indeterminada si es parcial y no pliega", async () => {
  render(<Harness />);
  await userEvent.click(all("L2"));
  expect(chosen()).toBe("ios-xe/l2-stp,ios-xe/l2-vlan-troncales");
  expect(hdr("L2")).toHaveAttribute("aria-expanded", "true"); // elegir abre; el clic no alterna
  expect(all("L2").checked).toBe(true);
  await userEvent.click(screen.getByRole("checkbox", { name: "STP" }));
  expect(all("L2").checked).toBe(false);
  expect(all("L2").indeterminate).toBe(true);
  await userEvent.click(all("L2"));
  expect(chosen()).toBe("ios-xe/l2-stp,ios-xe/l2-vlan-troncales");
  await userEvent.click(all("L2"));
  expect(chosen()).toBe("");
  expect(hdr("L2")).toHaveAttribute("aria-expanded", "true"); // quitar todo no lo cierra bajo los dedos
});

test("la casilla del grupo solo actúa sobre lo que el filtro deja ver", async () => {
  render(<Harness initial={["ios-xe/l2-vlan-troncales"]} />);
  await userEvent.type(screen.getByRole("searchbox", { name: "Buscar playbook" }), "stp");
  const box = screen.getByRole("checkbox", { name: "Seleccionar el visible de L2" }) as HTMLInputElement;
  expect(box.checked).toBe(false);
  await userEvent.click(box);
  expect(chosen()).toBe("ios-xe/l2-stp,ios-xe/l2-vlan-troncales");
});

test("una búsqueda nueva olvida lo cerrado a mano", async () => {
  render(<Harness />);
  const q = screen.getByRole("searchbox", { name: "Buscar playbook" });
  await userEvent.type(q, "stp");
  await userEvent.click(hdr("L2"));
  expect(hdr("L2")).toHaveAttribute("aria-expanded", "false");
  await userEvent.type(q, " s");
  expect(hdr("L2")).toHaveAttribute("aria-expanded", "true");
});

test("quitar el último elegido de un grupo no lo pliega bajo los dedos", async () => {
  render(<Harness initial={["ios-xe/l3-ospf"]} />);
  await userEvent.click(screen.getByRole("checkbox", { name: "OSPF" }));
  expect(chosen()).toBe("");
  expect(hdr("L3")).toHaveAttribute("aria-expanded", "true");
});

test("el conteo del encabezado cuenta el grupo entero aunque la búsqueda oculte lo elegido", async () => {
  render(<Harness initial={["ios-xe/l2-vlan-troncales"]} />);
  await userEvent.type(screen.getByRole("searchbox", { name: "Buscar playbook" }), "stp");
  expect(hdr("L2")).toHaveTextContent("(1 seleccionado / 2)");
});

test("con filtro la casilla del grupo dice cuántos visibles toca y no quita lo oculto", async () => {
  render(<Harness initial={["ios-xe/l2-vlan-troncales"]} />);
  const q = screen.getByRole("searchbox", { name: "Buscar playbook" });
  expect(screen.queryByRole("checkbox", { name: "Seleccionar todo L2" })).toBeInTheDocument();
  await userEvent.type(q, "stp");
  const box = screen.getByRole("checkbox", { name: "Seleccionar el visible de L2" });
  await userEvent.click(box);
  expect(chosen()).toBe("ios-xe/l2-stp,ios-xe/l2-vlan-troncales");
  await userEvent.click(box);
  expect(chosen()).toBe("ios-xe/l2-vlan-troncales");
  await userEvent.clear(q);
  await userEvent.type(q, "l2");
  expect(screen.getByRole("checkbox", { name: "Seleccionar los 2 visibles de L2" })).toBeInTheDocument();
});

test("el indeterminado sale de la selección inicial y el grupo se nombra sin el conteo", () => {
  render(<Harness initial={["ios-xe/l2-stp"]} />);
  expect(all("L2").indeterminate).toBe(true);
  expect(screen.getByRole("group", { name: "L2" })).toBeInTheDocument();
});

test("aria-controls solo existe con el grupo abierto", async () => {
  render(<Harness />);
  expect(hdr("L2")).not.toHaveAttribute("aria-controls");
  await userEvent.click(hdr("L2"));
  expect(hdr("L2")).toHaveAttribute("aria-controls");
});

test("lo cerrado a mano sobrevive mientras la búsqueda no cambie de verdad (espacios no cuentan)", async () => {
  render(<Harness />);
  const q = screen.getByRole("searchbox", { name: "Buscar playbook" });
  await userEvent.type(q, "stp");
  await userEvent.click(hdr("L2"));
  await userEvent.type(q, " ");
  expect(hdr("L2")).toHaveAttribute("aria-expanded", "false");
});
