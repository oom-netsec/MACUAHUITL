import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TransferView } from "./TransferView";
import { fakeCore } from "../../lib/fake";
import { CoreContext } from "../../app/activity";
import type { TransferReady } from "./api";
import { nftLeftoverCmd } from "./validate";

// Entradas hostiles: nombres de archivo y rechazos vienen del cliente remoto; las órdenes copiables, del núcleo.
const ifaces = [{ name: "eth0", up: true, loopback: false, addresses: ["192.0.2.10/24"], hardwareAddr: "" }];
const ready = (o: Partial<TransferReady> = {}): TransferReady => ({
  serverId: "s1", protocol: "tftp", listening: "192.0.2.10:6969", hint: "", user: "", password: "", fingerprints: null, recvDir: "/o/r", fromDir: "", files: [], ...o,
});
async function openServer(over = {}) {
  const core = fakeCore({ listInterfaces: vi.fn(async () => ifaces), ...over });
  render(<CoreContext.Provider value={core}><TransferView core={core} /></CoreContext.Provider>);
  await screen.findByRole("option", { name: /192.0.2.10/ });
  await userEvent.selectOptions(screen.getByLabelText("IP de escucha"), "192.0.2.10");
  await userEvent.type(screen.getByLabelText(/Carpeta de envío/, { selector: "input" }), "/srv/img");
  await userEvent.click(screen.getByRole("button", { name: "Abrir servidor" }));
  return core;
}
const line = (File: string, over = {}) => ({ Proto: "tftp", Client: "192.0.2.1", File, Bytes: 1, Duration: 1, Result: "ok", dirCode: "write" as const, ...over });

test("el nombre de archivo y el rechazo con HTML se ven como texto: no crean elementos", async () => {
  const core = await openServer();
  const evil = '<img src=x onerror="window.__pwn=1"><script>window.__pwn=2</script>';
  act(() => core.emitTransfer({ runId: "r1", ready: ready() }));
  act(() => core.emitTransfer({ runId: "r1", line: line(evil, { Result: "error", Rejected: true, Error: evil }) }));
  const card = await screen.findByRole("group", { name: /TFTP/ });
  await waitFor(() => expect(within(card).getAllByRole("row")).toHaveLength(2));
  expect(card.querySelector("img, script")).toBeNull();
  const row = within(card).getAllByRole("row")[1];
  expect(row.textContent!.split(evil).length - 1).toBe(2); // nombre y rechazo, literales
});

test("bidi y controles en el nombre de archivo se muestran como código visible", async () => {
  const core = await openServer();
  act(() => core.emitTransfer({ runId: "r1", ready: ready() }));
  act(() => core.emitTransfer({ runId: "r1", line: line("cfg‮txt.exe⁦⁩\u0007\u001b[2J\u0000") }));
  const row = (await screen.findAllByRole("row"))[1];
  expect(row.textContent).toContain("cfg⟦U+202E⟧txt.exe⟦U+2066⟧⟦U+2069⟧⟦U+0007⟧⟦U+001B⟧[2J⟦U+0000⟧");
  expect(row.textContent).not.toMatch(/[‮⁦⁩\u0007\u001b\u0000]/);
});

test("la orden de sysctl sale exactamente como la manda el núcleo, en el Console y al copiar", async () => {
  const cmd = "echo 'net.ipv4.ip_unprivileged_port_start=21' | sudo tee /etc/sysctl.d/60-x.conf && sudo sysctl --system # $(id) `id` <b>x</b> \"q\"  doble  espacio ";
  const denied = Object.assign(new Error("Linux no deja abrir el puerto 69"), { cause: { code: "FailedPrecondition", reason: "fileserve.err.port_denied", metadata: { port: "69", cmd } } });
  const core = await openServer({ transferServe: vi.fn(async () => { throw denied; }) });
  const log = (await screen.findByRole("log", { name: /^Orden para permitirlo/ }));
  expect(log.textContent).toBe(cmd);
  expect(log.querySelector("b")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Copiar" }));
  expect(core.copyText).toHaveBeenCalledWith(cmd);
});

test("nftLeftoverCmd: la orden sale solo con protocolo y puerto limpios; un nombre con «;» o espacios no entra", () => {
  expect(nftLeftoverCmd("tftp", "192.0.2.10", 69)).toBe("sudo nft delete table ip macuahuitl_tftp_6969");
  for (const p of ["x; rm -rf /", "x y", "a\nb", "$(id)", "", "a-b", "A"]) expect(nftLeftoverCmd(p, "192.0.2.10", 99), p).toBe("");
  expect(nftLeftoverCmd("raro", "192.0.2.10", Number.NaN)).toBe("");
  expect(nftLeftoverCmd("raro", "192.0.2.10", 1.5)).toBe("");
  // El host solo decide la familia: lo que traiga no se interpola.
  expect(nftLeftoverCmd("tftp", "::1; reboot", 69)).toBe("sudo nft delete table ip6 macuahuitl_tftp_6969");
});

test("serveProblem: las carpetas del servidor rechazan rutas de Windows peligrosas (solo en Windows)", async () => {
  const { serveProblem } = await import("./validate");
  const { setOSForTests } = await import("../../lib/platform");
  const form = { proto: "tftp" as const, any: false, listen: "192.0.2.10", port: "69", write: true, recvDir: "/r", fromDir: "/s", files: "", allow: "192.0.2.1", minutes: "30" };
  setOSForTests("windows");
  try {
    expect(serveProblem({ ...form, fromDir: "C:\\s", recvDir: "C:\\r" })).toBeNull();
    expect(serveProblem({ ...form, fromDir: "\\\\srv\\share\\s", recvDir: "C:\\r" })).toBe("paths.err.unc");
    expect(serveProblem({ ...form, fromDir: "C:\\s", recvDir: "C:\\r:ads" })).toBe("paths.err.ads");
    expect(serveProblem({ ...form, write: false, fromDir: "C:\\s", recvDir: "\\\\?\\C:\\r" })).toBeNull(); // sin escritura, recvDir no se usa
  } finally { setOSForTests(undefined); }
  expect(serveProblem({ ...form, fromDir: "\\\\srv\\share\\s", recvDir: "/r:x" })).toBeNull(); // Linux: nombres comunes
});

test("la tarjeta del servidor no arma orden de IOS para un archivo con salto de línea y avisa", async () => {
  const core = await openServer();
  act(() => core.emitTransfer({ runId: "r1", ready: ready({ files: ["ok.bin", "x\nreload"], recvDir: "" }) }));
  const log = await screen.findByRole("log", { name: /Órdenes de IOS|IOS/ });
  expect(log.textContent).toBe("copy tftp://192.0.2.10/ok.bin flash:");
  expect(screen.getByText(/1 archivo\(s\) tienen en su nombre/)).toBeVisible();
});
