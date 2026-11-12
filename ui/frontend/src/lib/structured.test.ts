import { tryReport } from "./structured";

test("tryReport devuelve el informe y cae a null si falta, falla o viene vacío", async () => {
  expect(await tryReport(async () => ({ text: "x" }))).toEqual({ text: "x" });
  expect(await tryReport()).toBeNull();
  expect(await tryReport(async () => { throw new Error("unknown method"); })).toBeNull();
  expect(await tryReport(async () => ({ text: "" }))).toBeNull();
});
