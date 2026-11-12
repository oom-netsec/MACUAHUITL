// Duración legible para un ingeniero de guardia: "< 1 min", "5 min", "2 h 15 min", "1 d 2 h".
export function elapsed(ms: number): string {
  const min = Math.floor(ms / 60_000);
  if (min < 1) return "< 1 min";
  if (min < 60) return `${min} min`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h} h ${min % 60} min`;
  return `${Math.floor(h / 24)} d ${h % 24} h`;
}

// En el idioma activo de la app (I18nProvider fija <html lang>).
const lang = () => document.documentElement.lang || undefined;
export const when = (iso?: string) => (iso ? new Date(iso).toLocaleString(lang(), { dateStyle: "short", timeStyle: "short" }) : "");
export const clock = (iso: string) => new Date(iso).toLocaleTimeString(lang(), { hour: "2-digit", minute: "2-digit" });
