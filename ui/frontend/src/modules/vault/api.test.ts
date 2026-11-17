import { passwordCreds, type Credential } from "./api";

const c = (id: string, kind?: "password" | "key"): Credential => ({ id, label: id, username: "u", kind, hasEnable: false, hasSshKey: kind === "key" });

test("passwordCreds quita las de llave y conserva las de contraseña y las sin tipo", () => {
  expect(passwordCreds([c("a", "password"), c("b", "key"), c("d")]).map((x) => x.id)).toEqual(["a", "d"]);
});
