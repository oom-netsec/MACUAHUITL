import type { TransferReady } from "./api";

// Comandos de IOS 15.x para usar el servidor recién abierto (sintaxis sin validar en laboratorio).
// IOS no deja elegir el puerto de tftp, ftp, scp ni sftp: llega al estándar y la redirección lo lleva al nuestro; http sí lleva puerto.
export function splitListen(addr: string): { host: string; port: number } {
  const i = addr.lastIndexOf(":");
  return { host: addr.slice(0, i).replace(/^\[|\]$/g, ""), port: Number(addr.slice(i + 1)) };
}

export function iosCommands(r: Pick<TransferReady, "protocol" | "listening" | "user" | "password" | "files">, write: boolean, ph: { ip: string; file: string }): string[] {
  const { host: h, port } = splitListen(r.listening);
  const ip = /^(0\.0\.0\.0|::)$/.test(h) ? ph.ip : h.includes(":") ? `[${h}]` : h;
  const names = r.files?.length ? r.files : [ph.file];
  const out: string[] = [];
  const url = (path: string) => {
    switch (r.protocol) {
      case "ftp": return `ftp://${r.user}:${r.password}@${ip}/${path}`;
      case "scp": case "sftp": return `${r.protocol}://${r.user}@${ip}/${path}`;
      case "http": return `http://${ip}:${port}/${path}`;
      default: return `tftp://${ip}/${path}`;
    }
  };
  for (const n of names) out.push(`copy ${url(n)} flash:`);
  if (write && r.protocol !== "http") out.push(`copy running-config ${url("r1-config.txt")}`);
  return out;
}
