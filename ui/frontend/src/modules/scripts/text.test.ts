import { fieldOfError } from "./text";

const coded = (reason: string, message = "x") => Object.assign(new Error(message), { cause: { code: "InvalidArgument", reason, metadata: {} } });

// Con la interfaz en inglés el texto no dice «llamado» ni «etiqueta»: el campo sale del reason del núcleo.
test("fieldOfError ubica el campo por el reason, en cualquier idioma", () => {
  expect(fieldOfError(coded("scripts.svc.name_taken", 'there is already a script named "a"'))).toBe("name");
  expect(fieldOfError(coded("scripts.err.name"))).toBe("name");
  expect(fieldOfError(coded("scripts.err.tag_bad"))).toBe("tags");
  expect(fieldOfError(coded("scripts.err.tags_max"))).toBe("tags");
  expect(fieldOfError(coded("scripts.err.description"))).toBe("desc");
  expect(fieldOfError(coded("scripts.err.command_ascii"))).toBe("commands");
  expect(fieldOfError(coded("scripts.svc.fav_max", "el comando de favoritos"))).toBe("");
});

test("fieldOfError sin reason usa el texto en español de siempre", () => {
  expect(fieldOfError(new Error('ya hay un script llamado "a"'))).toBe("name");
  expect(fieldOfError(new Error("etiqueta repetida"))).toBe("tags");
  expect(fieldOfError(new Error("otra cosa"))).toBe("");
});
