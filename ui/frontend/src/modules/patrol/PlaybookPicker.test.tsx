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
  const l2 = screen.getByRole("group", { name: /^L2/ });
  expect(within(l2).getByRole("checkbox", { name: /STP/ })).toBeInTheDocument();
  expect(screen.getByRole("group", { name: /^TAC/ })).toBeInTheDocument();
  await userEvent.click(within(l2).getByRole("checkbox", { name: /STP/ }));
  await userEvent.click(screen.getByRole("checkbox", { name: /Usuario sin red/ }));
  expect(chosen()).toBe("ios-xe/l2-stp,ios-xe/tac-usuario-sin-red");
  expect(screen.getByText("2 playbooks elegidos")).toBeInTheDocument();
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
  expect(screen.getByText("1 playbook elegido")).toBeInTheDocument();
});

test("muestra los comandos de cada playbook antes de elegirlo", async () => {
  render(<Harness />);
  const stp = screen.getByRole("checkbox", { name: "STP" }).closest(".pb-item")!;
  await userEvent.click(within(stp as HTMLElement).getByText("Comandos (4)"));
  expect(screen.getByText("show spanning-tree detail")).toBeInTheDocument();
});

test("el contrato de Wails tolera las listas vacías que omite protojson", async () => {
  const { patrolWails } = await import("./api");
  const api = (json: string) => patrolWails((async () => json) as never);
  expect(await api("{}").listPlaybooks()).toEqual([]);
  expect(await api('{"playbooks":[{"id":"ios-xe/l2-stp","platform":"ios-xe","name":"L2 · STP"}]}').listPlaybooks())
    .toEqual([{ id: "ios-xe/l2-stp", platform: "ios-xe", name: "L2 · STP", commands: [], params: [] }]);
});

test("un playbook sin id no llega al selector", async () => {
  const { patrolWails } = await import("./api");
  expect(await patrolWails((async () => '{"playbooks":[{"name":"roto"},{"id":"ios-xe/x","name":"X"}]}') as never).listPlaybooks()).toHaveLength(1);
});
