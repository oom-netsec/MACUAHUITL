import { countInterfaces, decimalOk, interfaceOk, intOk, ipv4Ok, maskOk, vlanOk } from "./validate";

test("ipv4 y máscara decimal como el núcleo (netip): sin ceros a la izquierda, máscara contigua de /1 a /32", () => {
  expect(["10.0.0.1", "255.255.255.255", "0.0.0.0"].every(ipv4Ok)).toBe(true);
  expect(["10.0.0", "10.0.0.256", "a.b.c.d", "10.0.0.1.1", "", "10.01.0.1", "010.0.0.1", "10.0.0.00"].some(ipv4Ok)).toBe(false);
  expect(["255.255.255.0", "255.255.254.0", "255.255.255.255", "128.0.0.0"].every(maskOk)).toBe(true);
  expect(["0.0.0.0", "255.0.255.0", "24", "255.255.255.1", "0.0.0.255", "255.255.0.255", "255.255.255.01"].some(maskOk)).toBe(false);
});

test("enteros, decimales y VLAN respetan rango y forma", () => {
  expect(intOk("30", 1, 100)).toBe(true);
  expect(["0", "101", "030", "-1", "1.5", ""].some((v) => intOk(v, 1, 100))).toBe(false);
  expect(intOk("0", 0, 1440)).toBe(true);
  expect(["20", "5.5", "100.00", "999.99"].every((v) => decimalOk(v))).toBe(true);
  expect(["100.01", "5.555", "-1", "1,5", "1000"].some((v) => decimalOk(v, 0, 100))).toBe(false);
  expect(decimalOk("1000")).toBe(false); // el núcleo admite hasta 3 dígitos enteros
  expect(vlanOk("1") && vlanOk("4094")).toBe(true);
  expect(["0", "4095", "10,20", "10-20"].some((v) => vlanOk(v))).toBe(false);
  expect(vlanOk("5", 10)).toBe(false);
  expect(vlanOk("1", 2)).toBe(false);
  expect(vlanOk("100", 2, 99)).toBe(false); // el max del campo acota
  expect(vlanOk("99", 2, 99)).toBe(true);
  expect(vlanOk("4094", 1, 9999)).toBe(true);
  expect(vlanOk("4095", 1, 9999)).toBe(false); // nunca pasa de 4094
});

test("puerto: físico o Port-channel; lista: solo físicos, rangos después de «/» y sin repetidos", () => {
  expect(["Gi1/0/48", "Po1", "Fa0/1", "gigabitethernet1/0/1", "Port-channel10", "Te1/1/1"].every(interfaceOk)).toBe(true);
  expect(["Gi1/0/1-4", "1/0/1", "Gi", "Gi1/0/1,Gi1/0/2", "Vlan10", "Lo0", "Gi1/0/1.10", "Gi1/0/1/2/3"].some(interfaceOk)).toBe(false);
  expect(countInterfaces("Gi1/0/1-4, Gi1/0/9")).toBe(5);
  expect(countInterfaces("Gi1/0/1 Gi1/0/2,Gi1/0/3")).toBe(3);
  expect(countInterfaces("Gi1/0/1-48")).toBe(48);
  expect(countInterfaces("Gi1/0/1-4, Gi1/0/2")).toBe(4); // el repetido no cuenta
  expect(countInterfaces("Gi1/0/4-1")).toBeNull();
  expect(countInterfaces("hola mundo!")).toBeNull();
  expect(countInterfaces("Po1")).toBeNull(); // la lista solo admite puertos físicos
  expect(countInterfaces("Vlan10")).toBeNull();
  expect(countInterfaces("Gi1-4")).toBeNull(); // el rango va sobre el último número, después de «/»
});
