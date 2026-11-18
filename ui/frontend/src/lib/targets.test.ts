import { addrPort, parseTarget, parseTargets, planTarget, targetOf, targetSpec } from "./targets";

test("parseTargets normaliza comas, espacios, saltos y CIDR sin duplicados", () => {
  expect(parseTargets("10.0.0.1, 10.0.0.2\n10.0.1.0/30  sw1\n10.0.0.1")).toEqual(["10.0.0.1", "10.0.0.2", "10.0.1.0/30", "sw1"]);
  expect(parseTargets("  \n , ")).toEqual([]);
});

test("el destino acepta host y host:puerto", () => {
  expect(parseTarget("192.0.2.1")).toEqual({ address: "192.0.2.1", port: 0 });
  expect(parseTarget("sw1:2222")).toEqual({ address: "sw1", port: 2222 });
  expect(parseTarget("2001:db8::1")).toEqual({ address: "2001:db8::1", port: 0 });
  // IPv6 con puerto: la forma entre corchetes.
  expect(parseTarget("[2001:db8::1]:2222")).toEqual({ address: "2001:db8::1", port: 2222 });
  expect(parseTarget("[2001:db8::1]")).toEqual({ address: "2001:db8::1", port: 0 });
});

test("el destino de una petición de plan conserva el nombre escrito y omite el puerto cero", () => {
  expect(planTarget(" sw1 ", "c1")).toEqual({ name: "sw1", address: "sw1", credentialId: "c1" });
  expect(planTarget("sw1:2222", "c1")).toEqual({ name: "sw1:2222", address: "sw1", port: 2222, credentialId: "c1" });
  // lo que escribe «Elegir de la libreta» para IPv6 con puerto se entiende de vuelta
  expect(planTarget("[fe80::1]:2222", "c1")).toEqual({ name: "[fe80::1]:2222", address: "fe80::1", port: 2222, credentialId: "c1" });
});

test("el destino conserva el puerto también en IPv6 (forma entre corchetes)", () => {
  expect(targetOf({ address: "10.0.0.1", port: 22 })).toBe("10.0.0.1");
  expect(targetOf({ address: "10.0.0.1", port: 2222 })).toBe("10.0.0.1:2222");
  expect(targetOf({ address: "fe80::1", port: 22 })).toBe("fe80::1");
  expect(targetOf({ address: "fe80::1", port: 2222 })).toBe("[fe80::1]:2222");
});

test("la dirección con puerto que se muestra pone IPv6 entre corchetes", () => {
  expect(addrPort({ address: "10.0.0.1", port: 22 })).toBe("10.0.0.1:22");
  expect(addrPort({ address: "fe80::1", port: 22 })).toBe("[fe80::1]:22");
});

test("targetSpec separa dirección y puerto; sin puerto no manda port", () => {
  expect(targetSpec("10.9.0.1")).toEqual({ address: "10.9.0.1" });
  expect(targetSpec("ap1.lab:2222")).toEqual({ address: "ap1.lab", port: 2222 });
  expect(targetSpec("[fe80::1]:2222")).toEqual({ address: "fe80::1", port: 2222 });
});
