import { patrolWails } from "./api";

test("manda a Wails la forma exacta de ListJobs y RemoveJobs", async () => {
  const call = vi.fn(async (..._a: unknown[]) => undefined);
  const api = patrolWails(call as never);
  await api.listJobs({ includePast: true });
  await api.listJobs();
  await api.removeJobs({ jobIds: ["a", "b"] });
  expect(call.mock.calls).toEqual([["ListJobs", { includePast: true }], ["ListJobs", { includePast: false }], ["RemoveJobs", { jobIds: ["a", "b"] }]]);
});
