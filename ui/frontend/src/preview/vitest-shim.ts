// En la vista previa, los dobles de pruebas (fake.ts) importan `vi` de vitest; aquí `vi.fn(impl)` es la propia impl.
type Fn = (...a: never[]) => unknown;
export const vi = { fn: <T extends Fn>(impl?: T) => impl ?? ((() => undefined) as unknown as T) };
