import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// Los grupos del selector arrancan plegados: espera el catálogo, abre los plegados y devuelve la casilla del playbook.
export async function findPb(name: string | RegExp) {
  await waitFor(() => expect(document.querySelector(".pb-toggle")).not.toBeNull());
  for (const b of document.querySelectorAll<HTMLElement>('.pb-toggle[aria-expanded="false"]')) await userEvent.click(b);
  return screen.findByRole("checkbox", { name });
}
