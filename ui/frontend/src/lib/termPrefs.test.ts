import { parsePrefs } from "./termPrefs";

test("por defecto: paleta clásica (oscura y con color) y resaltado encendido", () => {
  expect(parsePrefs(null)).toEqual({ palette: "classic", hl: true, srm: false });
  expect(parsePrefs("no es json")).toEqual({ palette: "classic", hl: true, srm: false });
});

test("una elección guardada se respeta, también la de un fósforo: el color del resaltado ya no depende de la paleta", () => {
  expect(parsePrefs('{"palette":"p1","hl":false,"srm":true}')).toEqual({ palette: "p1", hl: false, srm: true });
  expect(parsePrefs('{"palette":"inexistente"}').palette).toBe("classic");
});

test("quien tenía guardada una paleta con su nombre antiguo conserva su elección con el id nuevo", () => {
  expect(parsePrefs('{"palette":"securecrt-dark"}').palette).toBe("consola-oscura");
  expect(parsePrefs('{"palette":"securecrt-light"}')).toMatchObject({ palette: "consola-clara" });
});

test("una preferencia guardada con campos que ya no existen se lee sin romper y se descartan", () => {
  expect(parsePrefs('{"palette":"p1","crt":true,"hl":false}')).toEqual({ palette: "p1", hl: false, srm: false });
});
