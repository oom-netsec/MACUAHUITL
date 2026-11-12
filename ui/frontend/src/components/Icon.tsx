// Íconos de Lucide (ISC), importados uno por uno para que el bundle solo lleve los que se usan (ADR 0009).
// Los módulos piden el ícono por nombre; agregar uno es una línea aquí.
import {
  Activity, ChevronRight, Download, Upload, List, Plus, Play, CircleAlert, CircleCheck, Command, Copy, Eye, Info, Keyboard, Layers, ListTree, LoaderCircle, Lock, LockOpen,
  Minus, PanelLeft, RefreshCw, Search, ShieldCheck, Shield, SlidersHorizontal, Square, SquareTerminal, SunMoon, TriangleAlert, Wrench, X,
  Star, Settings, ArrowUp, ArrowDown, Pin, FolderPlus,
  type LucideIcon,
} from "lucide-react";

const icons = {
  patrol: RefreshCw,
  pulse: Activity,
  layers: Layers,
  syslog: ListTree,
  lock: Lock,
  unlock: LockOpen,
  audit: ShieldCheck,
  ops: SlidersHorizontal,
  shield: Shield,
  tools: Wrench,
  eye: Eye,
  terminal: SquareTerminal,
  chevron: ChevronRight,
  minimise: Minus,
  maximise: Square,
  close: X,
  search: Search,
  alert: TriangleAlert,
  error: CircleAlert,
  ok: CircleCheck,
  info: Info,
  loader: LoaderCircle,
  sidebar: PanelLeft,
  command: Command,
  keyboard: Keyboard,
  theme: SunMoon,
  copy: Copy,
  download: Download,
  upload: Upload,
  list: List,
  plus: Plus,
  play: Play,
  star: Star,
  settings: Settings,
  up: ArrowUp,
  down: ArrowDown,
  pin: Pin,
  folderPlus: FolderPlus,
} satisfies Record<string, LucideIcon>;

export type IconName = keyof typeof icons;

export function Icon({ name, size = 16 }: { name: IconName; size?: number }) {
  const C = icons[name];
  return <C size={size} strokeWidth={1.75} aria-hidden="true" />;
}
