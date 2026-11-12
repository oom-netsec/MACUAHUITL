import { inGroup, perMinute, toMsg } from "./syslogStats";

const T0 = Date.UTC(2026, 10, 6, 18, 0, 0);
const m = (id: number, secs: number) => ({ id, at: T0 + secs * 1000, from: "", sev: 6, mnemonic: "", text: "" });

test("cuenta mensajes por minuto hasta el minuto del último, con ceros en los huecos", () => {
  const msgs = [m(1, 5), m(2, 20), m(3, 125), m(4, 130), m(5, 131)];
  expect(perMinute(msgs, 4)).toEqual([0, 2, 0, 3]);
});

test("descarta lo anterior a la ventana y sin mensajes devuelve vacío", () => {
  expect(perMinute([m(1, 0), m(2, 600)], 3)).toEqual([0, 0, 1]);
  expect(perMinute([], 5)).toEqual([]);
});

test("grupos de severidad: error o peor, aviso, notificación e informativo; sin PRI solo en todas", () => {
  expect(inGroup("all", -1)).toBe(true);
  expect(inGroup("err", 3)).toBe(true);
  expect(inGroup("err", 4)).toBe(false);
  expect(inGroup("warn", 4)).toBe(true);
  expect(inGroup("notice", 5)).toBe(true);
  expect(inGroup("info", 7)).toBe(true);
  expect(inGroup("info", -1)).toBe(false);
});

test("toMsg usa la hora del mensaje, el texto o el crudo, y -1 sin severidad", () => {
  const a = toMsg({ Time: "2026-11-06T18:00:09Z", From: "10.0.0.2:514", Severity: 3, Mnemonic: "LINK-3-UPDOWN", Text: "Gi1 down", Raw: "<187>x" }, 7, 123);
  expect(a).toEqual({ id: 7, at: Date.parse("2026-11-06T18:00:09Z"), from: "10.0.0.2:514", sev: 3, mnemonic: "LINK-3-UPDOWN", text: "Gi1 down" });
  const b = toMsg({ Raw: "solo crudo" }, 8, 123);
  expect(b).toMatchObject({ at: 123, sev: -1, text: "solo crudo", from: "", mnemonic: "" });
});
