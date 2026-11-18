import { useState } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TargetField, TargetsField } from "./TargetField";
import { fakeCore } from "../../lib/fake";
import { sampleHosts } from "./fake";

const hosts = sampleHosts; // LAB-CORE 10.9.0.1 (con credencial), LAB-AP ap1.lab:2222, OFI-SW 10.8.0.1
const pick = async (name: string) => {
  await userEvent.click(await screen.findByRole("button", { name: "Elegir de la libreta" }));
  await userEvent.selectOptions(await screen.findByLabelText("Host de la libreta"), hosts.find((h) => h.name === name)!.id);
};

function One({ onCred }: { onCred?: (id: string) => void }) {
  const [v, setV] = useState("");
  return <TargetField core={fakeCore()} value={v} onChange={setV} onPickCredential={onCred} />;
}
function Many({ start = "" }: { start?: string }) {
  const [v, setV] = useState(start);
  return <TargetsField core={fakeCore()} value={v} onChange={setV} />;
}

test("un equipo: etiqueta común, escribir a mano y elegir de la libreta (con puerto y credencial)", async () => {
  const onCred = vi.fn();
  render(<One onCred={onCred} />);
  const input = screen.getByLabelText("Equipo (IP o nombre, con :puerto opcional)");
  await userEvent.type(input, "1.1.1.1");
  expect(input).toHaveValue("1.1.1.1");
  await pick("LAB-CORE");
  expect(input).toHaveValue("10.9.0.1");
  expect(onCred).toHaveBeenLastCalledWith(hosts[0].credentialId);
  onCred.mockClear();
  await pick("LAB-AP"); // sin credencial: no se llama
  expect(input).toHaveValue("ap1.lab:2222");
  expect(onCred).not.toHaveBeenCalled();
});

test("varios equipos: etiqueta común, agrega sin duplicar y respeta lo escrito", async () => {
  render(<Many start="sw9" />);
  const area = screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)");
  await pick("LAB-CORE");
  await pick("LAB-AP");
  await pick("LAB-CORE"); // ya estaba
  expect(area).toHaveValue("sw9\n10.9.0.1\nap1.lab:2222");
});

test("libreta vacía: no hay botón", async () => {
  const listHosts = vi.fn(async () => []);
  render(<TargetField core={fakeCore({ listHosts })} value="" onChange={() => {}} />);
  await waitFor(() => expect(listHosts).toHaveBeenCalled());
  expect(screen.getByLabelText("Equipo (IP o nombre, con :puerto opcional)")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Elegir de la libreta" })).toBeNull();
});
