import {
  LayoutDashboard,
  ShieldAlert,
  FolderGit2,
  Layers,
  ListTodo,
  Eye,
  Download,
  Settings,
} from "lucide-react";

export const journeys = [
  {
    label: "Visão geral",
    icon: LayoutDashboard,
    items: [{ path: "/", label: "Dashboard" }],
  },
  {
    label: "Inteligência de vulnerabilidades",
    icon: ShieldAlert,
    items: [
      { path: "/feed", label: "Feed de vulnerabilidades" },
      { path: "/search", label: "Busca de versões" },
      { path: "/technologies", label: "Tecnologias e produtos" },
      { path: "/exploration", label: "Exploração conhecida" },
    ],
  },
  {
    label: "Aplicações e repositórios",
    icon: FolderGit2,
    items: [{ path: "/projects", label: "Repositórios" }],
  },
  {
    label: "Análises e inventário",
    icon: Layers,
    items: [
      { path: "/inventory", label: "Inventário / SBOM" },
      { path: "/sca", label: "Análises SCA" },
      { path: "/sast", label: "Análises SAST" },
      { path: "/history", label: "Histórico e jobs" },
    ],
  },
  {
    label: "Investigação e remediação",
    icon: ListTodo,
    items: [
      { path: "/priorities", label: "Central de prioridades" },
      { path: "/triage", label: "Triagem e remediação" },
    ],
  },
  {
    label: "Monitoramento e alertas",
    icon: Eye,
    items: [
      { path: "/watchlist", label: "Watchlist" },
      { path: "/alerts", label: "Alertas" },
    ],
  },
  {
    label: "Relatórios",
    icon: Download,
    items: [{ path: "/reports", label: "Relatórios" }],
  },
  {
    label: "Configurações",
    icon: Settings,
    items: [
      { path: "/settings", label: "Configurações" },
      { path: "/sources", label: "Fontes de inteligência" },
    ],
  },
];
