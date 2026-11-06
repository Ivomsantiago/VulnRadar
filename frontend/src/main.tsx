import appPackage from "../package.json";
import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  BrowserRouter,
  Link,
  NavLink,
  Routes,
  Route,
  Navigate,
  useLocation,
} from "react-router-dom";
import {
  QueryClient,
  QueryClientProvider,
  useQueryClient,
} from "@tanstack/react-query";
import {
  Radar,
  LayoutDashboard,
  ListTodo,
  ShieldAlert,
  Search,
  FolderGit2,
  Eye,
  Bell,
  RefreshCw,
  Settings,
  History,
  Download,
  Activity,
  Menu,
  ChevronDown,
  Boxes,
  ScanLine,
  ShieldCheck,
  Layers,
  PanelLeftClose,
  Monitor,
  Command,
  X,
} from "lucide-react";
import { type Exposure, type Source } from "./api";
import { Empty, useData } from "./shared";
import { useStored, Skeleton } from "./ui";
import { CommandPalette } from "./CommandPalette";
import { Details, Feed } from "./Investigation";
import { SearchPage } from "./Search";
import { Projects } from "./Projects";
import { FindingsPage } from "./Findings";
import { Inventory } from "./Inventory";
import { Technologies } from "./Technologies";
import { Watchlist } from "./Watchlist";
import { Sources } from "./Sources";
import { HistoryPage } from "./History";
import { Reports } from "./Reports";
import { SettingsPage } from "./Settings";
import "./style.css";
const Overview = React.lazy(() =>
  import("./Overview").then((m) => ({ default: m.Overview })),
);
const client = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 5000, refetchInterval: 20000 },
  },
});
const groups = [
  {
    label: "OVERVIEW",
    items: [
      { path: "/", label: "Dashboard", icon: LayoutDashboard },
      { path: "/priorities", label: "Central de prioridades", icon: ListTodo },
    ],
  },
  {
    label: "VULNERABILITY INTELLIGENCE",
    items: [
      { path: "/feed", label: "Feed de vulnerabilidades", icon: ShieldAlert },
      { path: "/search", label: "Busca avançada", icon: Search },
      {
        path: "/technologies",
        label: "Tecnologias e bibliotecas",
        icon: Boxes,
      },
      { path: "/exploration", label: "Exploração conhecida", icon: Activity },
    ],
  },
  {
    label: "APPLICATION SECURITY",
    items: [
      { path: "/projects", label: "Repositórios", icon: FolderGit2 },
      { path: "/sca", label: "Análises SCA", icon: ScanLine },
      { path: "/sast", label: "Análises SAST", icon: ShieldCheck },
      { path: "/inventory", label: "Inventário / SBOM", icon: Layers },
    ],
  },
  {
    label: "GESTÃO",
    items: [
      { path: "/watchlist", label: "Watchlist", icon: Eye },
      { path: "/alerts", label: "Alertas", icon: Bell },
      { path: "/triage", label: "Triagem e remediação", icon: ListTodo },
      { path: "/reports", label: "Relatórios", icon: Download },
    ],
  },
  {
    label: "PLATAFORMA",
    items: [
      { path: "/sources", label: "Fontes de inteligência", icon: RefreshCw },
      { path: "/history", label: "Histórico e jobs", icon: History },
      { path: "/settings", label: "Configurações", icon: Settings },
    ],
  },
];
function App() {
  const location = useLocation();
  const qc = useQueryClient();
  const [collapsed, setCollapsed] = useStored("vr-sidebar-collapsed", false);
  const [closedGroups, setClosedGroups] = useStored<string[]>(
    "vr-sidebar-groups",
    [],
  );
  const [mobile, setMobile] = useState(false);
  const [palette, setPalette] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const exposure = useData<Exposure>("exposure", "/exposure");
  const sources = useData<Source[]>("sources", "/sources");
  const preferences = useData<{ theme: string }>("preferences", "/preferences");
  useEffect(() => {
    const events = new EventSource("/api/events");
    events.onopen = () => setConnected(true);
    events.onerror = () => setConnected(false);
    events.addEventListener("update", () => qc.invalidateQueries());
    return () => events.close();
  }, [qc]);
  useEffect(() => {
    const handle = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPalette((open) => !open);
      }
    };
    window.addEventListener("keydown", handle);
    return () => window.removeEventListener("keydown", handle);
  }, []);
  useEffect(() => {
    const theme = preferences.data?.theme || "dark";
    const media = matchMedia("(prefers-color-scheme: light)");
    const apply = () => {
      document.documentElement.dataset.theme =
        theme === "system" ? (media.matches ? "light" : "dark") : theme;
    };
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [preferences.data?.theme]);
  useEffect(() => setMobile(false), [location.pathname]);
  const active = groups
    .flatMap((g) => g.items.map((i) => ({ ...i, group: g.label })))
    .find((i) => i.path === location.pathname);
  const syncing = sources.data?.some((s) => s.status === "running");
  return (
    <div
      className={`app ${collapsed ? "collapsed" : ""} ${mobile ? "mobile-open" : ""}`}
    >
      <a className="skip-link" href="#main-content">
        Ir para o conteúdo
      </a>
      {mobile && (
        <button
          className="nav-backdrop"
          onClick={() => setMobile(false)}
          aria-label="Fechar navegação"
        />
      )}
      <aside>
        <Link to="/" className="brand">
          <span className="brand-icon">
            <Radar size={27} />
          </span>
          <span className="brand-name">
            Vuln<span className="accent">Radar</span>
            <small>APPLICATION SECURITY</small>
          </span>
        </Link>
        <Link
          to="/settings"
          className="workspace-selector"
          title="Configurações da instalação"
        >
          <span className="workspace-avatar">
            <Monitor size={16} />
          </span>
          <span className="nav-text">
            <b>Workspace local</b>
            <small>Ambiente privado</small>
          </span>
          <ChevronDown className="nav-text" size={14} />
        </Link>
        <nav aria-label="Navegação principal">
          {groups.map((group) => (
            <div className="nav-group" key={group.label}>
              <button
                className="nav-label"
                aria-expanded={!closedGroups.includes(group.label)}
                onClick={() =>
                  setClosedGroups(
                    closedGroups.includes(group.label)
                      ? closedGroups.filter((g) => g !== group.label)
                      : [...closedGroups, group.label],
                  )
                }
              >
                <span>{group.label}</span>
                <ChevronDown
                  size={12}
                  className={
                    closedGroups.includes(group.label) ? "rotated" : ""
                  }
                />
              </button>
              {(!closedGroups.includes(group.label) || collapsed) &&
                group.items.map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    end
                    title={item.label}
                  >
                    <item.icon size={17} />
                    <span className="nav-text">{item.label}</span>
                    {!collapsed &&
                    ((item.path === "/sca" && exposure.data?.open_sca) ||
                      (item.path === "/sast" && exposure.data?.open_sast)) ? (
                      <span className="nav-count">
                        {item.path === "/sca"
                          ? exposure.data?.open_sca
                          : exposure.data?.open_sast}
                      </span>
                    ) : null}
                  </NavLink>
                ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <ShieldCheck size={17} />
          <span className="nav-text">
            Instância local<small>Dados sob seu controle</small>
          </span>
          <button
            className="icon-button nav-text"
            aria-label="Recolher navegação"
            onClick={() => setCollapsed(!collapsed)}
          >
            <PanelLeftClose size={15} />
          </button>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <button
            className="icon-button menu-toggle"
            aria-label="Alternar navegação"
            aria-expanded={mobile}
            onClick={() => {
              if (window.innerWidth <= 900) setMobile(!mobile);
              else setCollapsed(!collapsed);
            }}
          >
            <Menu size={18} />
          </button>
          <div className="breadcrumb">
            <span>{active?.group || "VULNRADAR"}</span>
            <ChevronDown size={12} />
            <b>{active?.label || "Investigação"}</b>
          </div>
          <button
            className="global-search"
            onClick={() => setPalette(true)}
            aria-label="Abrir busca universal"
          >
            <Search size={17} />
            <span>Buscar no VulnRadar…</span>
            <kbd>Ctrl K</kbd>
          </button>
          <Link
            to="/sources"
            className="connection"
            title="Ver estado individual das fontes"
          >
            <i className={connected ? "online" : ""} />
            <span>
              {syncing
                ? "Sincronizando fontes"
                : connected
                  ? "Eventos conectados"
                  : "Reconectando"}
            </span>
          </Link>
          <Link className="icon-button" to="/alerts" aria-label="Abrir alertas">
            <Bell size={18} />
          </Link>
          <Link
            className="icon-button"
            to="/settings"
            aria-label="Abrir configurações"
          >
            <Settings size={18} />
          </Link>
        </header>
        <main id="main-content" tabIndex={-1}>
          <React.Suspense fallback={<Skeleton rows={7} />}>
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/priorities" element={<FindingsPage />} />
              <Route path="/feed" element={<Feed />} />
              <Route path="/exploration" element={<Feed kev />} />
              <Route path="/search" element={<SearchPage />} />
              <Route path="/technologies" element={<Technologies />} />
              <Route path="/projects" element={<Projects />} />
              <Route path="/sca" element={<FindingsPage kind="sca" />} />
              <Route path="/sast" element={<FindingsPage kind="sast" />} />
              <Route path="/inventory" element={<Inventory />} />
              <Route path="/watchlist" element={<Watchlist />} />
              <Route path="/alerts" element={<HistoryPage alerts />} />
              <Route path="/triage" element={<FindingsPage remediation />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/sources" element={<Sources />} />
              <Route path="/history" element={<HistoryPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route
                path="/vulnerabilities"
                element={<Navigate to="/feed" replace />}
              />
              <Route
                path="/repositories"
                element={<Navigate to="/projects" replace />}
              />
              <Route
                path="/findings"
                element={<Navigate to="/priorities" replace />}
              />
              <Route
                path="*"
                element={
                  <Empty title="Página não encontrada">
                    <Link to="/">Voltar ao dashboard</Link>
                  </Empty>
                }
              />
            </Routes>
          </React.Suspense>
          <footer>
            <span>VulnRadar</span> Inteligência com evidências. Decisões com
            contexto.<small>v{appPackage.version} · Local</small>
          </footer>
        </main>
      </div>
      {palette && (
        <CommandPalette
          close={() => setPalette(false)}
          onVulnerability={setSelected}
        />
      )}{" "}
      {selected && <Details id={selected} close={() => setSelected(null)} />}
    </div>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={client}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
