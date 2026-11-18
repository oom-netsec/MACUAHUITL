import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { sampleHosts } from "../modules/inventory/fake";

// Credenciales para elegir de la libreta: dos, para que ninguna se preseleccione sola. LAB-CORE trae la primera (10.9.0.1); LAB-AP (ap1.lab:2222) no trae.
export const bookCreds = [
  { id: "c".repeat(32), label: "admin lab", username: "root", hasEnable: false, hasSshKey: false },
  { id: "c2", label: "otra", username: "x", hasEnable: false, hasSshKey: false },
];
export const BOOK_CRED = bookCreds[0].id;
export const LABEL_ONE = "Equipo (IP o nombre, con :puerto opcional)";
export const LABEL_MANY = "Equipos (IP o nombre, con :puerto opcional)";

// Abre «Elegir de la libreta» y elige el host por nombre.
export async function pickHost(name: "LAB-CORE" | "LAB-AP" | "OFI-SW", last = false) {
  const bs = await screen.findAllByRole("button", { name: "Elegir de la libreta" });
  await userEvent.click(last ? bs[bs.length - 1] : bs[0]); // last: el campo del panel, cuando la vista tiene otro antes
  await userEvent.selectOptions(await screen.findByLabelText("Host de la libreta"), sampleHosts.find((h) => h.name === name)!.id);
}
