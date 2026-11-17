import { useCallback, useReducer } from "react";

// Una acción por campo: el valor lleva el tipo de ese campo del formulario.
export type FormAction<S> = { [K in keyof S]: { field: K; value: S[K] } }[keyof S];

export function formReducer<S>(s: S, a: FormAction<S>): S {
  return { ...s, [a.field]: a.value };
}

// Estado del formulario y `set(campo)`, que devuelve el onChange de ese campo. `set` es estable entre renders.
export function useForm<S>(init: S) {
  const [form, dispatch] = useReducer<S, [FormAction<S>]>(formReducer, init);
  const set = useCallback(<K extends keyof S>(field: K) => (value: S[K]) => dispatch({ field, value } as FormAction<S>), []);
  return [form, set] as const;
}
