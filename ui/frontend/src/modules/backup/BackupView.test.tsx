import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BackupView } from "./BackupView";
import { fakeCore } from "../../lib/fake";
import { CoreContext, NavContext } from "../../app/activity";
import { sampleEntry } from "./fake";

const a = sampleEntry();
const b = sampleEntry({ id: "SW1_192.0.2.1/20261106T110000Z-running", at: "2026-11-06T11:00:00Z", masked: false });

const cred = { id: "c1", label: "lab", username: "admin", hasEnable: false, hasSshKey: false };
const withCreds = (over = {}) => fakeCore({ listCredentials: vi.fn(async () => [cred]), ...over });

test("respalda una vez, espera el resultado, avisa y recarga la lista", async () => {
  const core = withCreds({
    backupCollect: vi.fn().mockResolvedValueOnce({ state: "running", done: false, saved: [], skipped: 0, pruned: 0, warnings: [] })
      .mockResolvedValueOnce({ state: "completed", done: true, saved: [a.id], skipped: 0, pruned: 0, warnings: ["SW1: el equipo no devolvió startup-config"] }),
    backupList: vi.fn().mockResolvedValueOnce({ backups: [], masked: false }).mockResolvedValue({ backups: [a], masked: true }),
  });
  render(<BackupView core={core} pollMs={1} />);
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1:2222");
  await userEvent.click(screen.getByLabelText("Incluir también el startup-config"));
  await userEvent.click(await screen.findByRole("button", { name: "Respaldar ahora" }));
  expect(core.backupStart).toHaveBeenCalledWith(expect.objectContaining({ targets: [{ address: "192.0.2.1", port: 2222 }], credentialId: "c1", startup: true, keep: 30, intervalSeconds: 0, rounds: 0, secrets: false }));
  expect(await screen.findByText(/1 respaldo\(s\) guardado\(s\)\. Avisos: SW1/)).toBeInTheDocument();
  expect(core.backupCollect).toHaveBeenCalledTimes(2);
  expect(await screen.findByText(a.device)).toBeInTheDocument();
  expect(screen.getByText(/Aviso: Los respaldos marcados «enmascarado»/)).toBeInTheDocument();
});

test("sin armar explica por qué y no espera", async () => {
  const core = withCreds({ backupStart: vi.fn(async () => ({ jobId: "j9", armed: false, detail: "Login Test falló" })) });
  render(<BackupView core={core} />);
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  await userEvent.click(await screen.findByRole("button", { name: "Respaldar ahora" }));
  expect(await screen.findByRole("status")).toHaveTextContent("Trabajo j9 creado sin armar: Login Test falló");
  expect(core.backupCollect).not.toHaveBeenCalled();
});

test("programar convierte minutos en segundos y no espera el resultado", async () => {
  const core = withCreds();
  render(<BackupView core={core} />);
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  await userEvent.clear(screen.getByLabelText(/Programar cada/));
  await userEvent.type(screen.getByLabelText(/Programar cada/), "60");
  await userEvent.clear(screen.getByLabelText(/Veces/));
  await userEvent.type(screen.getByLabelText(/Veces/), "4");
  await userEvent.click(await screen.findByRole("button", { name: "Programar" }));
  expect(core.backupStart).toHaveBeenCalledWith(expect.objectContaining({ intervalSeconds: 3600, rounds: 4 }));
  expect(await screen.findByRole("status")).toHaveTextContent("Programado (trabajo j1)");
  expect(core.backupCollect).not.toHaveBeenCalled();
});

test("avisa que sin enmascarar deja secretos en claro", async () => {
  render(<BackupView core={withCreds()} />);
  await userEvent.click(screen.getByLabelText("Guardar sin enmascarar secretos"));
  expect(screen.getByRole("status")).toHaveTextContent("contraseñas y llaves en claro");
});

test("la línea de tiempo agrupa por equipo y ordena del más nuevo al más viejo", async () => {
  const r1 = sampleEntry({ id: "R1_192.0.2.9/20261105T080000Z-running", device: "R1_192.0.2.9", at: "2026-11-05T08:00:00Z", bytes: 2048 });
  const core = withCreds({ backupList: vi.fn(async () => ({ backups: [a, r1, b], masked: false })) });
  render(<BackupView core={core} />);
  const sw1 = await screen.findByRole("region", { name: a.device });
  const boxes = within(sw1).getAllByRole("checkbox").map((c) => c.getAttribute("aria-label"));
  expect(boxes).toEqual([`Comparar ${b.id}`, `Comparar ${a.id}`]);
  expect(within(sw1).getAllByText("1.2 KiB")).toHaveLength(2);
  expect(within(screen.getByRole("region", { name: r1.device })).getByText("2 KiB")).toBeInTheDocument();
});

test("compara dos respaldos, el más viejo primero, en el visor de diferencias", async () => {
  const diff = { from: a, to: b, added: 1, removed: 1, ignored: ["ntp clock-period 1", "ntp clock-period 2"], masked: true, changes: [] };
  const texts: Record<string, string> = {
    [a.id]: "hostname SW1\ninterface Gi1/0/1\n description PC-01\nntp clock-period 1\n",
    [b.id]: "hostname SW1\ninterface Gi1/0/1\n description PC-02\nntp clock-period 2\n",
  };
  const core = withCreds({
    backupList: vi.fn(async () => ({ backups: [b, a], masked: true })), backupDiff: vi.fn(async () => diff),
    backupGet: vi.fn(async (id: string) => ({ meta: id === a.id ? a : b, text: texts[id] })),
  });
  render(<BackupView core={core} />);
  const cmp = screen.getByRole("button", { name: "Comparar" });
  await screen.findByLabelText(`Comparar ${b.id}`);
  expect(cmp).toBeDisabled();
  await userEvent.click(screen.getByLabelText(`Comparar ${b.id}`));
  await userEvent.click(screen.getByLabelText(`Comparar ${a.id}`));
  await userEvent.click(cmp);
  expect(core.backupDiff).toHaveBeenCalledWith(a.id, b.id);
  const reg = await screen.findByRole("region", { name: "Diferencias" });
  expect(within(reg).getByText("1 cambio", { exact: false })).toBeInTheDocument();
  expect(within(reg).getByText((_, el) => el?.tagName === "CODE" && el.textContent === " description PC-02" && el.closest("[data-op]")?.getAttribute("data-op") === "+")).toBeInTheDocument();
  // Las líneas volátiles que el núcleo ignora no se muestran como cambio.
  expect(within(reg).queryByText(/clock-period 2/)).not.toBeInTheDocument();
  expect(screen.getByText(/no son visibles porque alguno de los dos respaldos se tomó enmascarado/)).toBeInTheDocument();
  expect(screen.getByText(/Ignoradas por volátiles: ntp clock-period 1/)).toBeInTheDocument();
});

test("ver ofrece descargar el .cfg con el nombre del equipo y la fecha, y copiar el contenido", async () => {
  const core = withCreds({ backupList: vi.fn(async () => ({ backups: [a], masked: true })), backupGet: vi.fn(async () => ({ meta: a, text: "hostname SW1\n" })) });
  render(<CoreContext.Provider value={core}><BackupView core={core} /></CoreContext.Provider>);
  await userEvent.click(await screen.findByRole("button", { name: `Ver ${a.id}` }));
  const reg = await screen.findByRole("region", { name: "Contenido" });
  await userEvent.click(within(reg).getByRole("button", { name: "Descargar .cfg" }));
  expect(core.saveFile).toHaveBeenCalledWith("SW1_192.0.2.1-20261106T100000Z.cfg", "hostname SW1\n", "utf8");
  await userEvent.click(within(reg).getByRole("button", { name: "Copiar contenido" }));
  expect(core.copyText).toHaveBeenCalledWith("hostname SW1\n");
});

test("ver muestra el contenido y el error del núcleo sale como alerta", async () => {
  const core = withCreds({
    backupList: vi.fn(async () => ({ backups: [a], masked: true })),
    backupGet: vi.fn().mockResolvedValueOnce({ meta: a, text: "hostname SW1\n" }).mockRejectedValueOnce(new Error("rpc error: code = NotFound desc = no existe")),
  });
  render(<BackupView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: `Ver ${a.id}` }));
  expect(within(await screen.findByRole("region", { name: "Contenido" })).getByText((_, el) => el?.tagName === "PRE" && /hostname SW1/.test(el.textContent ?? ""))).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: `Ver ${a.id}` }));
  expect(await screen.findByRole("alert")).toHaveTextContent("no existe");
  expect(screen.queryByRole("region", { name: "Contenido" })).not.toBeInTheDocument();
});

test("el menú de equipo precarga la dirección en Equipos", () => {
  render(<NavContext.Provider value={{ go: () => {}, inbox: { backup: { data: "10.20.3.11", n: 1 } } }}><BackupView core={withCreds()} /></NavContext.Provider>);
  expect(screen.getByLabelText(/Equipos/)).toHaveValue("10.20.3.11");
});
