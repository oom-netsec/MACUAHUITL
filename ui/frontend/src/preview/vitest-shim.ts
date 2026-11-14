// In the preview, the test doubles (fake.ts) import `vi` from vitest; here `vi.fn(impl)` is the impl itself.
type Fn = (...a: never[]) => unknown;
export const vi = { fn: <T extends Fn>(impl?: T) => impl ?? ((() => undefined) as unknown as T) };
