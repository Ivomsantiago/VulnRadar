import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  BrowserRouter,
  NavLink,
  Routes,
  Route,
  useNavigate,
} from "react-router-dom";
import {
  QueryClient,
  QueryClientProvider,
  useQueryClient,
} from "@tanstack/react-query";
import {
  Radar,
  LayoutDashboard,
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
} from "lucide-react";
import { Empty } from "./shared";
import { Feed } from "./Investigation";
const Overview = React.lazy(() =>
  import("./Overview").then((m) => ({ default: m.Overview })),
);
import { SearchPage } from "./Search";
import { Watchlist } from "./Watchlist";
import { Projects } from "./Projects";
import { Sources } from "./Sources";
import { HistoryPage } from "./History";
import { Reports } from "./Reports";
import { SettingsPage } from "./Settings";
import "./style.css";

const client = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchInterval: 15000 } },
});

function App() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [collapsed, setCollapsed] = useState(false);
  const [global, setGlobal] = useState("");
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    const events = new EventSource("/api/events");
    events.onopen = () => setConnected(true);
    events.onerror = () => setConnected(false);
    events.addEventListener("update", () => qc.invalidateQueries());
    return () => events.close();
  }, [qc]);
  const groups = [
    {
      title: "MONITORAMENTO",
      items: [
        ["/", "Visão geral", LayoutDashboard],
        ["/feed", "Vulnerabilidades", ShieldAlert],
        ["/exploration", "Exploração conhecida", Activity],
      ],
    },
    {
      title: "INVESTIGAÇÃO",
      items: [
        ["/search", "Busca universal", Search],
        ["/projects", "Repositórios e análises", FolderGit2],
      ],
    },
    {
      title: "GESTÃO",
      items: [
        ["/watchlist", "Watchlist", Eye],
        ["/alerts", "Alertas", Bell],
        ["/reports", "Relatórios", Download],
      ],
    },
    {
      title: "SISTEMA",
      items: [
        ["/sources", "Fontes e sincronização", RefreshCw],
        ["/history", "Histórico", History],
        ["/settings", "Configurações", Settings],
      ],
    },
  ];
  return (
    <div className={`app ${collapsed ? "collapsed" : ""}`}>
      <aside>
        <NavLink to="/" className="brand">
          <span className="brand-icon">
            <Radar size={25} />
          </span>
          {!collapsed && (
            <span>
              Vuln<span className="accent">Radar</span>
              <small>APPLICATION SECURITY</small>
            </span>
          )}
        </NavLink>
        <nav>
          {groups.map((group) => (
            <div className="nav-group" key={group.title}>
              {!collapsed && <div className="nav-label">{group.title}</div>}
              {group.items.map(([path, label, Icon]) => {
                const I = Icon as typeof Radar;
                return (
                  <NavLink
                    key={String(path)}
                    to={String(path)}
                    end={path === "/"}
                    title={String(label)}
                  >
                    <I size={18} />
                    {!collapsed && String(label)}
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <ShieldAlert size={17} />
          {!collapsed && (
            <span>
              Instância local<small>Dados sob seu controle</small>
            </span>
          )}
        </div>
      </aside>
      <div className="workspace">
        <div className="topbar">
          <button
            aria-label="Recolher navegação"
            className="icon-button"
            onClick={() => setCollapsed(!collapsed)}
          >
            <Menu size={18} />
          </button>
          <form
            className="global-search"
            onSubmit={(e) => {
              e.preventDefault();
              navigate("/feed?q=" + encodeURIComponent(global));
            }}
          >
            <Search size={17} />
            <input
              aria-label="Busca global"
              placeholder="Buscar CVE, advisory ou tecnologia…"
              value={global}
              onChange={(e) => setGlobal(e.target.value)}
            />
            <kbd>↵</kbd>
          </form>
          <span className="connection">
            <i className={connected ? "online" : ""} />
            {connected ? "Eventos conectados" : "Reconectando"}
          </span>
          <NavLink className="icon-button" to="/alerts" aria-label="Alertas">
            <Bell size={18} />
          </NavLink>
          <span className="avatar">VR</span>
        </div>
        <main>
          <React.Suspense
            fallback={<div className="skeleton">Carregando painel…</div>}
          >
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/feed" element={<Feed />} />
              <Route path="/exploration" element={<Feed kev />} />
              <Route path="/search" element={<SearchPage />} />
              <Route path="/projects" element={<Projects />} />
              <Route path="/watchlist" element={<Watchlist />} />
              <Route path="/sources" element={<Sources />} />
              <Route path="/alerts" element={<HistoryPage alerts />} />
              <Route path="/history" element={<HistoryPage />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route
                path="*"
                element={<Empty title="Página não encontrada" />}
              />
            </Routes>
          </React.Suspense>
          <footer>
            VulnRadar <span>•</span> Inteligência com evidências. Decisões com
            contexto.
          </footer>
        </main>
      </div>
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
