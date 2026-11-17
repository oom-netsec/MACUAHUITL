import { transferWails } from "./api";

test("transferSessions llama al puente por servidor y convierte null en listas vacías", async () => {
  const call = vi.fn(async () => null);
  const api = transferWails(call as never);
  expect(await api.transferSessions("s1")).toEqual({ sessions: [], rejections: [] });
  expect(call).toHaveBeenCalledWith("TransferSessions", "s1");
});

test("transferSessions conserva rechazos y completa la lista que falte", async () => {
  const rej = { serverId: "s1", ip: "192.0.2.5", protocol: "tftp", cause: "busy", name: "", count: 2, first: 1, last: 2, reason: "", reasonCode: "" };
  const api = transferWails((async () => ({ rejections: [rej] })) as never);
  expect(await api.transferSessions("s1")).toEqual({ sessions: [], rejections: [rej] });
});
