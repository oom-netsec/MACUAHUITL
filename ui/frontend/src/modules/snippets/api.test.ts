import { snippetsWails } from "./api";
import { fakeSnippets, sampleTemplates } from "./fake";

const target = { name: "SW1", address: "10.0.0.1", credentialId: "c1" };

test("listSnippetTemplates pide el catálogo por plataforma y devuelve la lista (vacía si el núcleo no manda ninguna)", async () => {
  const call = vi.fn(async (_m: string, ..._a: unknown[]) => JSON.stringify({ templates: sampleTemplates }));
  const api = snippetsWails(call as never);
  expect(await api.listSnippetTemplates("ios-xe")).toEqual(sampleTemplates);
  expect(call).toHaveBeenCalledWith("AssistListSnippetTemplates", "ios-xe");
  await api.listSnippetTemplates();
  expect(call).toHaveBeenLastCalledWith("AssistListSnippetTemplates", "");
  expect(await snippetsWails((async () => "{}") as never).listSnippetTemplates()).toEqual([]);
});

test("planTemplateSnippet manda la plantilla y sus valores por AssistPlanSnippet, sin planear nada más", async () => {
  const call = vi.fn(async (_m: string, ..._a: unknown[]) => JSON.stringify({ planId: "s1", plan: { function: "snippet-speed-duplex", devices: [] } }));
  const res = await snippetsWails(call as never).planTemplateSnippet({
    target, id: "speed-duplex", values: { interfaces: "Gi1/0/1-2", speed: "100" }, acceptedHostKeyFingerprints: ["SHA256:x"],
  });
  expect(res.planId).toBe("s1");
  expect(call).toHaveBeenCalledTimes(1);
  expect(call.mock.calls[0][0]).toBe("AssistPlanSnippet");
  expect(JSON.parse(call.mock.calls[0][1] as string)).toEqual({
    target, template: { id: "speed-duplex", values: { interfaces: "Gi1/0/1-2", speed: "100" } }, acceptedHostKeyFingerprints: ["SHA256:x"],
  });
});

test("el doble de pruebas trae plantillas de varias tecnologías con campos tipados", async () => {
  const fake = fakeSnippets();
  const list = await fake.listSnippetTemplates();
  expect(list.map((t) => t.id)).toEqual(["speed-duplex", "storm-control", "port-security", "svi", "trunk", "vlan"]);
  expect(list[1].fields.find((f) => f.name === "broadcast")?.type).toBe("decimal");
  expect((await fake.planTemplateSnippet({ id: "trunk" })).plan.devices).toHaveLength(1);
});
