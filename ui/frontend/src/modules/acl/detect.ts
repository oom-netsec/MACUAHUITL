// Adivina la plataforma de una ACL pegada por sus rasgos de sintaxis. Devuelve null si no hay rasgo claro o si
// hay rasgos de más de una plataforma: en ese caso no se adivina.
export function detectAclPlatform(text: string): "ios-xe" | "nx-os" | "asa" | null {
  const found = new Set<"ios-xe" | "nx-os" | "asa">();
  for (const raw of text.split("\n")) {
    const l = raw.trim();
    if (/^access-list\s+\S+\s+(line\s+\d+\s+)?(extended|standard|webtype|ethertype)\s/i.test(l) || /^access-list\s+[A-Za-z]\S*\s+remark\s/i.test(l)) found.add("asa");
    else if (/^ip access-list\s+(extended|standard)\s+\S+/i.test(l) || /^access-list\s+\d+\s+(permit|deny|remark)\s/i.test(l)) found.add("ios-xe");
    // Sin extended/standard (ni subcomandos de IOS) es el encabezado de NX-OS; también statistics y prefijos /n.
    else if (/^ip access-list\s+(?!(extended|standard|role-based|logging|log-update|resequence|persistent)\b)\S+\s*$/i.test(l) || /^statistics\s+per-entry/i.test(l) || /^(\d+\s+)?(permit|deny)\s+\S+\s+(any|\d+\.\d+\.\d+\.\d+\/\d+)\s/i.test(l) && /\d+\.\d+\.\d+\.\d+\/\d+/.test(l)) found.add("nx-os");
  }
  return found.size === 1 ? [...found][0] : null;
}
