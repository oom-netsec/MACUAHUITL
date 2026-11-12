import { vi } from "vitest";
import type { PortsPlanResult } from "../ports/api";

export const sampleRotatePlan: PortsPlanResult = {
  planId: "c1",
  plan: {
    function: "credrotate",
    devices: [{
      device: "SW1",
      pre: ["show running-config | include ^username", "show version"],
      apply: ["username tech privilege 15 algorithm-type scrypt secret <oculto>"],
      rollback: ["username tech privilege 15 secret <oculto> <oculto>"],
      post: ["show running-config | include ^username"],
      expect: [{ command: "show running-config | include ^username", line: "tech 9", present: true }],
    }],
  },
};

export const fakeCredRotate = () => ({ assistPlanCredRotate: vi.fn(async () => sampleRotatePlan) });
