// Glifo de MACUAHUITL: macuahuitl con navajas de obsidiana dentro de un cartucho escalonado.
// Toma el color del texto (currentColor) para funcionar en claro y oscuro.
export function Glyph({ size = 24, title }: { size?: number; title?: string }) {
  return (
    <svg viewBox="0 0 64 64" width={size} height={size} fill="none" stroke="currentColor" strokeWidth={3.5}
      role={title ? "img" : undefined} aria-label={title} aria-hidden={title ? undefined : true}>
      <path d="M14 6H50V14H58V50H50V58H14V50H6V14H14Z" />
      <g transform="rotate(-45 32 32)" fill="currentColor" stroke="none">
        <rect x="28" y="14" width="8" height="26" rx="1.5" />
        <rect x="30" y="40" width="4" height="10" rx="1" />
        <path d="M29 16 23 19 29 22ZM29 24 23 27 29 30ZM29 32 23 35 29 38ZM35 16 41 19 35 22ZM35 24 41 27 35 30ZM35 32 41 35 35 38Z" />
      </g>
    </svg>
  );
}
