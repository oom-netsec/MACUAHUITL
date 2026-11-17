import { useReducer } from "react";

// Una acción por campo: el valor lleva el tipo de ese campo del formulario.
export type FormAction<S> = { [K in keyof S]: { field: K; value: S[K] } }[keyof S];

export function formReducer<S>(s: S, a: FormAction<S>): S {
  return { ...s, [a.field]: a.value };
}

// Estado del formulario y `set(campo)`, que devuelve el onChange de ese campo.
export function useForm<S>(init: S) {
  const [form, dispatch] = useReducer<S, [FormAction<S>]>(formReducer, init);
  const set = <K extends keyof S>(field: K) => (value: S[K]) => dispatch({ field, value });
  return [form, set] as const;
}
