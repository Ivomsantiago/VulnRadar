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
  Search,
  Bell,
  Settings,
  Menu,
  ChevronDown,
  ShieldCheck,
  PanelLeftClose,
  Monitor,
  Command,
  X,
} from "lucide-react";
import { journeys } from "./navigation";
import { OCI } from "./OCI";
import { AccessBoundary } from "./Access";
import { type Source } from "./api";
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
import { SettingsPage } from "./Settings";
import "./style.css";
const Overview = React.lazy(() =>
  import("./Overview").then((m) => ({ default: m.Overview })),
);
const Reports = React.lazy(() =>
  import("./Reports").then((m) => ({ default: m.Reports })),
);
const client = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 5000, refetchInterval: 20000 },
  },
});
const groups = journeys;
function LegacyRoute({ to }: { to: string }) {
  const location = useLocation();
  return <Navigate to={to + location.search + location.hash} replace />;
}

function App() {
  const location = useLocation();
  const qc = useQueryClient();
  const [collapsed, setCollapsed] = useStored("vr-sidebar-collapsed", false);
  const [mobile, setMobile] = useState(false);
  const [palette, setPalette] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
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
  const journey = groups.find((group) =>
    group.items.some((item) => item.path === location.pathname),
  );
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
            <b>Workspace</b>
            <small>Acesso autenticado</small>
          </span>
          <ChevronDown className="nav-text" size={14} />
        </Link>
        <nav aria-label="Navegação principal">
          {groups.map((group) => (
            <Link
              key={group.label}
              to={group.items[0].path}
              title={group.label}
              className={
                group.items.some((item) => item.path === location.pathname)
                  ? "active"
                  : ""
              }
            >
              <group.icon size={18} />
              <span className="nav-text">{group.label}</span>
            </Link>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <ShieldCheck size={17} />
          <span className="nav-text">
            Instância privada<small>Workspace compartilhado</small>
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
          {journey && journey.items.length > 1 && (
            <nav className="journey-tabs" aria-label={journey.label}>
              {journey.items.map((item) => (
                <NavLink key={item.path} to={item.path} end>
                  {item.label}
                </NavLink>
              ))}
            </nav>
          )}
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
              <Route path="/oci" element={<OCI />} />
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
                element={<LegacyRoute to="/feed" />}
              />
              <Route
                path="/repositories"
                element={<LegacyRoute to="/projects" />}
              />
              <Route
                path="/findings"
                element={<LegacyRoute to="/priorities" />}
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
            <span>VulnRadar</span> Índice de vulnerabilidades e evidências de aplicações.<small>v{appPackage.version} · Autenticado</small>
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
        <AccessBoundary><App /></AccessBoundary>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
