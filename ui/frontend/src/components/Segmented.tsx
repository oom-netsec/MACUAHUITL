import { useId } from "react";

// Control segmentado tipo iOS sobre radios nativos: las flechas del teclado funcionan sin código.
export function Segmented<T extends string>({ legend, value, onChange, options, disabled }: { legend: string; value: T; onChange: (v: T) => void; options: [T, string][]; disabled?: boolean }) {
  const name = useId();
  return (
    <fieldset className="segmented">
      <legend className="sr">{legend}</legend>
      {options.map(([v, l]) => (
        <label key={v}>
          <input type="radio" name={name} value={v} checked={value === v} disabled={disabled} onChange={() => onChange(v)} />
          <span>{l}</span>
        </label>
      ))}
    </fieldset>
  );
}
