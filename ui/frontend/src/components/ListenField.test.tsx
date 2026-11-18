import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { ListenField, joinListen, splitHostPort } from "./ListenField";

const ips: [string, string][] = [["192.0.2.10", "eth0"], ["127.0.0.1", "lo"]];
function Host({ start = "192.0.2.10", port, spy }: { start?: string; port?: string; spy?: (s: { v: string; any: boolean; port: string }) => void }) {
  const [v, setV] = useState(start);
  const [any, setAny] = useState(false);
  const [p, setP] = useState(port ?? "");
  spy?.({ v, any, port: p });
  return <ListenField label="Escuchar en" value={v} onChange={setV} any={any} onAny={setAny} ips={ips} port={port === undefined ? undefined : p} onPort={setP} />;
}

test("lista las IP locales y al final «Todas las interfaces (0.0.0.0)»", () => {
  render(<Host />);
  const o = screen.getAllByRole("option").map((x) => x.textContent);
  expect(o).toEqual(["192.0.2.10 · eth0", "127.0.0.1 · lo", "Todas las interfaces (0.0.0.0)"]);
});

test("elegir «Todas» marca any y conserva la IP elegida antes; volver a una IP lo apaga", async () => {
  const seen: { v: string; any: boolean }[] = [];
  render(<Host spy={(s) => seen.push(s)} />);
  const sel = screen.getByLabelText("Escuchar en");
  await userEvent.selectOptions(sel, "Todas las interfaces (0.0.0.0)");
  expect(seen.at(-1)).toMatchObject({ any: true, v: "192.0.2.10" });
  expect(sel).toHaveValue("0.0.0.0");
  await userEvent.selectOptions(sel, "127.0.0.1");
  expect(seen.at(-1)).toMatchObject({ any: false, v: "127.0.0.1" });
});

test("un valor que no está en la lista se conserva como opción", () => {
  render(<Host start="10.9.9.9" />);
  expect(screen.getByLabelText("Escuchar en")).toHaveValue("10.9.9.9");
  expect(screen.getAllByRole("option").map((x) => x.textContent)).toEqual(["192.0.2.10 · eth0", "127.0.0.1 · lo", "10.9.9.9", "Todas las interfaces (0.0.0.0)"]);
});

test("con port muestra el campo de puerto y lo edita", async () => {
  const seen: { port: string }[] = [];
  render(<Host port="1162" spy={(s) => seen.push(s)} />);
  const p = screen.getByLabelText("Puerto");
  await userEvent.clear(p);
  await userEvent.type(p, "99");
  expect(seen.at(-1)?.port).toBe("99");
});

test("sin port no hay campo de puerto", () => {
  render(<Host />);
  expect(screen.queryByLabelText("Puerto")).toBeNull();
});

test("splitHostPort y joinListen son inversos, también con IPv6", () => {
  expect(splitHostPort("127.0.0.1:5514")).toEqual({ host: "127.0.0.1", port: "5514" });
  expect(splitHostPort("[::1]:5514")).toEqual({ host: "::1", port: "5514" });
  expect(splitHostPort("host")).toEqual({ host: "host", port: "" });
  expect(joinListen("127.0.0.1", "5514")).toBe("127.0.0.1:5514");
  expect(joinListen("::1", "5514")).toBe("[::1]:5514");
});
