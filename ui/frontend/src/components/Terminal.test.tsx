import { act, render } from "@testing-library/react";
import { Terminal } from "./Terminal";
import { fakeCore } from "../lib/fake";
import { resetTermPrefs, setTermBackend, setTermPrefs } from "../lib/termPrefs";

beforeEach(() => { localStorage.clear(); resetTermPrefs(); });

test("colorea por categoría sin cambiar el texto", () => {
  const text = "Gi1/0/1 is up, 10.0.0.1 %LINK-3-UPDOWN\nRouter#show";
  const { container } = render(<Terminal text={text} />);
  const pre = container.querySelector("pre")!;
  expect(pre.textContent).toBe(text);
  expect(pre.querySelector(".t-iface")?.textContent).toBe("Gi1/0/1");
  expect(pre.querySelector(".t-ok")?.textContent).toBe("up");
  expect(pre.querySelector(".t-addr")?.textContent).toBe("10.0.0.1");
  expect(pre.querySelector(".t-bad")?.textContent).toBe("%LINK-3-UPDOWN");
  expect(pre.querySelector(".t-prompt")?.textContent).toBe("Router#");
});

test("nunca interpreta HTML de la red", () => {
  const evil = '<img src=x onerror="window.pwned=1"> up';
  const { container } = render(<Terminal text={evil} />);
  expect(container.querySelector("img")).toBeNull();
  expect(container.querySelector("pre")!.textContent).toBe(evil);
  expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
});

test("una salida de 20 000 líneas conserva todo el texto y resalta solo la cola", () => {
  const text = Array.from({ length: 20000 }, (_, i) => `Gi1/0/${i % 48} is up`).join("\n");
  const t0 = performance.now();
  const { container } = render(<Terminal text={text} />);
  expect(container.querySelector("pre")!.textContent).toBe(text);
  expect(container.querySelectorAll(".t-ok").length).toBe(2000);
  // Tarda ~4 s con la máquina cargada: el tope es holgado a propósito (busca un cuelgue, no un tiempo fino).
  expect(performance.now() - t0).toBeLessThan(12_000);
}, 15_000);

test("cambiar paleta y resaltado se refleja y se guarda en el núcleo", async () => {
  const core = fakeCore();
  await setTermBackend(core);
  const { container } = render(<Terminal text="up" />);
  const term = container.querySelector(".term")!;
  act(() => setTermPrefs({ palette: "p3" }));
  expect(term).toHaveAttribute("data-palette", "p3");
  act(() => setTermPrefs({ hl: false }));
  expect(core.setPreference).toHaveBeenLastCalledWith("terminal", '{"palette":"p3","hl":false,"srm":false}');
});

test("la preferencia sobrevive a un reinicio (se lee del núcleo, no del webview)", async () => {
  const core = fakeCore();
  await setTermBackend(core);
  const first = render(<Terminal text="up" />);
  act(() => setTermPrefs({ palette: "ibm" }));
  first.unmount();
  // Reinicio: localStorage vacío y estado de módulo reiniciado; solo el núcleo conserva el valor.
  localStorage.clear();
  resetTermPrefs();
  const { container } = render(<Terminal text="up" />);
  expect(container.querySelector(".term")).toHaveAttribute("data-palette", "classic");
  await act(async () => { await setTermBackend(core); });
  expect(container.querySelector(".term")).toHaveAttribute("data-palette", "ibm");
});

test("un valor guardado inválido cae a la paleta predeterminada", async () => {
  const core = fakeCore({ getPreference: vi.fn(async () => '{"palette":"<script>"}') });
  await act(async () => { await setTermBackend(core); });
  const { container } = render(<Terminal text="up" />);
  expect(container.querySelector(".term")).toHaveAttribute("data-palette", "classic");
});

test("si el usuario cambia la paleta antes de que llegue la preferencia guardada, gana lo del usuario", async () => {
  let llega!: (v: string) => void;
  const core = fakeCore({ getPreference: vi.fn(() => new Promise<string>((r) => { llega = r; })) });
  const pend = setTermBackend(core);
  const { container } = render(<Terminal text="up" />);
  act(() => setTermPrefs({ palette: "p3" }));
  await act(async () => { llega('{"palette":"ibm"}'); await pend; });
  expect(container.querySelector(".term")).toHaveAttribute("data-palette", "p3");
});
