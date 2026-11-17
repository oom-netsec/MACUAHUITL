import { transferWails } from "./api";

test("listTransferSessions llama al puente por servidor y convierte null en lista vacía", async () => {
  const call = vi.fn(async () => null);
  const api = transferWails(call as never);
  expect(await api.listTransferSessions("s1")).toEqual([]);
  expect(call).toHaveBeenCalledWith("ListTransferSessions", "s1");
});
