import { detectAclPlatform as d } from "./detect";

// Extractos de internal/acl/testdata.
test("reconoce los fixtures del núcleo", () => {
  expect(d("access-list EDGE-IN remark Gestion\naccess-list EDGE-IN extended permit tcp 10.10.0.0 255.255.255.0 host 192.0.2.1 eq 22 log")).toBe("asa");
  expect(d("ip access-list extended EDGE-IN\n remark Gestion\n permit tcp 10.10.0.0 0.0.0.255 host 192.0.2.1 eq 22 log")).toBe("ios-xe");
  expect(d("ip access-list EDGE-IN\n  10 remark Gestion\n  20 permit tcp 10.10.0.0/24 host 192.0.2.1 eq 22 log")).toBe("nx-os");
});

test("rasgos sueltos", () => {
  expect(d("access-list EDGE extended permit tcp any any")).toBe("asa");
  expect(d("access-list 101 permit ip any any")).toBe("ios-xe");
  expect(d("ip access-list extended X\n 10 permit ip any any")).toBe("ios-xe");
  expect(d("ip access-list X\n 10 permit ip any any")).toBe("nx-os");
  expect(d("permit tcp 10.0.0.0/24 any eq 22")).toBe("nx-os");
});

test("ambiguo o sin rasgos: no adivina", () => {
  expect(d("")).toBeNull();
  expect(d("permit ip any any")).toBeNull();
  expect(d("10 permit ip any any")).toBeNull();
  expect(d("ip access-list resequence X 10 10")).toBeNull();
  expect(d("access-list E extended permit ip any any\nip access-list extended Y")).toBeNull();
});

test("ASA con número de línea y prefijos IPv6 que no son de NX-OS", () => {
  expect(d("access-list EDGE line 1 extended permit ip any any")).toBe("asa");
  expect(d("ipv6 access-list V6\n permit ipv6 any 2001:db8::1/128")).toBeNull();
});
