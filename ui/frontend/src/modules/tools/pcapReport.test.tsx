import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PcapPanel } from "./ToolsView";
import { fakeCore } from "../../lib/fake";
import { pcapFromReport } from "./pcapParse";
import type { PcapReportData } from "./api";

// Fase 30b: la vista sale de toolsPcapReport (sin leer encabezados en español); si falla, del texto de siempre.
const base = { text: "Capture: x", summary: { file: "x", packets: 3, bytes: 30, durationMs: 1, start: "" }, neighbors: [],
  tcp: { handshakes: 0, rttMinMs: 0, rttAvgMs: 0, rttMaxMs: 0, retransmissions: 0, zeroWindow: 0, failedHandshakesTotal: 0, failedHandshakes: [], resets: [] },
  dns: { queries: 0, responses: 0, errors: [], slow: [], unanswered: [] }, tls: [], icmp: { unreachable: [], ttlExceeded: [] }, arpConflicts: [], fragments: 0, warnings: [], sections: [] };
const rep: PcapReportData = { ...base,
  conversations: [{ proto: "tcp", a: "10.0.0.5:1", b: "10.0.0.9:443", packets: 3, bytes: 30 }],
  topTalkers: [{ ip: "10.0.0.5", packets: 3, bytes: 30 }], protocols: [{ proto: "tcp", packets: 3, bytes: 30 }] };

test("pcapFromReport toma equipos, conversaciones y protocolos del informe", () => {
  expect(pcapFromReport(rep)).toEqual({ talkers: rep.topTalkers, conversations: rep.conversations, protocols: rep.protocols });
  expect(pcapFromReport({ ...rep, conversations: [], topTalkers: [] })).toBeNull();
});

async function analyze(core: ReturnType<typeof fakeCore>) {
  render(<PcapPanel core={core} />);
  await userEvent.type(screen.getByLabelText("Archivo de captura"), "/x.pcap");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
}

test("la vista usa el informe estructurado y no llama al método de texto", async () => {
  const core = fakeCore({ toolsPcapReport: vi.fn(async () => rep), toolsPcap: vi.fn(async () => "no debe llamarse") });
  await analyze(core);
  const talkers = await screen.findByRole("list", { name: "Equipos con más tráfico" });
  expect(within(talkers).getByText("10.0.0.5")).toBeInTheDocument();
  expect(core.toolsPcapReport).toHaveBeenCalledWith("/x.pcap", 20);
  expect(core.toolsPcap).not.toHaveBeenCalled();
});

test("si el informe falla se muestra el error, sin repetir con el método de texto", async () => {
  const core = fakeCore({ toolsPcapReport: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = no es una captura"); }),
    toolsPcap: vi.fn(async () => "no debe llamarse") });
  await analyze(core);
  expect(await screen.findByText(/no es una captura/)).toBeInTheDocument();
  expect(core.toolsPcap).not.toHaveBeenCalled();
});
