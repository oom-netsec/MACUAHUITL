// Contrato del módulo con el puente (ui/bridge/metrics.go) y su implementación de Wails.
// Datos para gráficas y la vista de frente del switch. Toda lista llega como arreglo (nunca null).

export interface MetricsQuery {
  job: string; // ID del trabajo de Patrol o carpeta de salida absoluta
  device?: string; // dirección o nombre; vacío = todos
  maxPoints?: number; // por serie, las rondas más recientes (0 = 500; máximo 5000)
  maxInterfaces?: number; // las de mayor utilización pico (0 = 12; máximo 64)
  interfaces?: string[]; // interfaces concretas (Gi1/0/1 o GigabitEthernet1/0/1); anula maxInterfaces
}

export interface CpuPoint { round: number; atMs: number; fiveSec: number; oneMin: number; fiveMin: number }
export interface MemoryPoint { round: number; atMs: number; used: number; free: number; total: number } // bytes
export interface MemorySeries { pool: string; points: MemoryPoint[] } // «Processor», «I/O», «lsmpi_io»…

export interface InterfacePoint {
  round: number; atMs: number;
  inBps: number; outBps: number;
  // «counters»: diferencia de contadores entre rondas; «5min»: promedio del equipo (primera ronda, reinicio, vuelta dudosa); «»: sin dato.
  source: "counters" | "5min" | "";
  inUtilPct: number; outUtilPct: number; // 0 si bwKbit es 0
  deltaOk: boolean; // las diferencias de abajo valen; false = primera ronda, reinicio o contador que bajó
  inErrors: number; outErrors: number; crc: number; resets: number; inDrops: number; outDrops: number; // contra la ronda anterior
  reboot: boolean; // el equipo se reinició desde la ronda anterior
}
export interface InterfaceSeries { name: string; description: string; bwKbit: number; peakUtilPct: number; points: InterfacePoint[] }
export interface RebootEvent { round: number; bootMs: number }

export interface DeviceMetrics {
  address: string; hostname: string; rounds: number;
  cpu: CpuPoint[]; memory: MemorySeries[]; interfaces: InterfaceSeries[];
  interfaceTotal: number; // interfaces con datos, antes del tope
  reboots: RebootEvent[]; truncated: boolean;
  warnings: string[]; // p. ej. «falta el comando show interfaces…»: la serie viene vacía
}
export interface JobMetrics { devices: DeviceMetrics[]; warnings: string[] }

// ---- Estado de puertos para la vista de frente del switch ----

// Con `job` (ID de trabajo o carpeta absoluta) lee la evidencia; sin `job` consulta en vivo a `device` por SSH
// (solo lectura; llave de host estricta: una llave nueva falla mostrando su huella y se acepta con acceptedHostKeys).
export interface PortStatusQuery {
  job?: string;
  device?: string; // con trabajo: el equipo si tiene varios; en vivo: dirección o nombre del switch
  port?: number; // en vivo: puerto SSH (0 = 22)
  credentialId?: string; // en vivo
  acceptedHostKeys?: string[];
  legacySsh?: boolean;
}
export interface PortInfo {
  name: string; // abreviado: «Gi1/0/12»
  kind: string; // Gi, Fa, Te, Twe, Fo, Hu, Eth
  // Gi1/0/12 → module 1, stack 0, number 12. «module» es el primer número del nombre (el miembro del stack en un apilable)
  // y «stack» el segundo (la ranura; 0 si el nombre solo trae dos números). Son los nombres que pidió la vista de frente.
  module: number; stack: number; number: number;
  description: string;
  status: string; // «connected» | «notconnect» | «disabled» | «err-disabled» (también «inactive», «suspended»…)
  vlan: string; // «10», «trunk» o «routed», como lo imprime el equipo
  duplex: string; speed: string; // como los imprime: «a-full», «a-1000», «auto», «10G»
  duplexMode: string; // «full» | «half» | «auto» | «»
  speedMbps: number; // 0 si está en auto o no se sabe
  autoNegotiated: boolean;
  type: string; // «10/100/1000BaseTX», «1000BaseSX SFP»; vacío si el equipo no lo da
  trunk: boolean; trunkNative: string; // VLAN nativa; vacía si show interfaces trunk no se recolectó
  channel: string; channelFlags: string; // «Po1» y «P» (en el canal), «D» (caído)…; vacíos si no es miembro
}
export interface ChannelMember { port: string; flags: string }
export interface PortChannel { name: string; state: string; protocol: string; members: ChannelMember[] } // state: «SU», «SD»…
export interface PortStatus {
  source: "job" | "live"; address: string; hostname: string;
  atMs: number; // unix ms de show interfaces status
  ports: PortInfo[]; // solo puertos físicos, en el orden del equipo (Po, Vlan y Lo no entran)
  channels: PortChannel[];
  warnings: string[]; // comandos que faltan o no se entendieron; con ports vacío: «falta el comando show interfaces status»
}

export interface MetricsAPI {
  jobMetrics(q: MetricsQuery): Promise<JobMetrics>;
  portStatus(q: PortStatusQuery): Promise<PortStatus>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const metricsWails = (call: Call): MetricsAPI => ({
  jobMetrics: (q) => call("JobMetrics", { device: "", maxPoints: 0, maxInterfaces: 0, interfaces: [], ...q }),
  portStatus: (q) => call("PortStatus", { job: "", device: "", port: 0, credentialId: "", acceptedHostKeys: [], legacySsh: false, ...q }),
});
