import { targetOf } from "./HostPicker";

test("el destino conserva el puerto también en IPv6 (forma entre corchetes)", () => {
  expect(targetOf({ address: "10.0.0.1", port: 22 })).toBe("10.0.0.1");
  expect(targetOf({ address: "10.0.0.1", port: 2222 })).toBe("10.0.0.1:2222");
  expect(targetOf({ address: "fe80::1", port: 22 })).toBe("fe80::1");
  expect(targetOf({ address: "fe80::1", port: 2222 })).toBe("[fe80::1]:2222");
});
