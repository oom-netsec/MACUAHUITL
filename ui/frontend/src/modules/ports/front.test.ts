import { toFront } from "./front";
import { samplePorts } from "../metrics/fake";

test("toFront: acceso elegible; troncal, enrutado y miembro de port-channel fijos; estado desconocido sin color propio", () => {
  const base = samplePorts.ports[1];
  expect(toFront({ ...base, name: "Gi1/0/6", module: 1, stack: 0, number: 6, vlan: "20", trunk: false, channel: "", status: "err-disabled" }))
    .toMatchObject({ name: "Gi1/0/6", module: 1, slot: 0, port: 6, mode: "access", status: "err-disabled", vlan: "20" });
  expect(toFront({ ...base, vlan: "trunk", trunk: true, channel: "" }).mode).toBe("trunk");
  expect(toFront({ ...base, vlan: "routed", trunk: false, channel: "" }).mode).toBe("routed");
  expect(toFront({ ...base, vlan: "trunk", trunk: true, channel: "Po1" })).toMatchObject({ mode: "channel", channel: "Po1" });
  const odd = toFront({ ...base, status: "suspended", description: "uplink", channel: "" });
  expect(odd.status).toBe("notconnect");
  expect(odd.description).toBe("uplink · suspended");
});
