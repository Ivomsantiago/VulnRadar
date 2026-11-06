import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  FolderGit2,
  FolderOpen,
  Plus,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  ScanLine,
  ShieldCheck,
  Clock,
  ChevronRight,
  ChevronUp,
  Square,
} from "lucide-react";
import {
  api,
  type Project,
  type Scan,
  type Page,
  type Finding,
  type ProjectInspection,
  type DirectoryListing,
} from "./api";
import {
  Header,
  Empty,
  ErrorBox,
  Badge,
  formatDate,
  statusLabels,
  useData,
} from "./shared";
import { Modal, Skeleton, Tabs } from "./ui";
import { FindingsTable, FindingDetails } from "./Findings";

export function DirectoryPicker({
  close,
  select,
}: {
  close: () => void;
  select: (path: string) => void;
}) {
  const [path, setPath] = useState("");
  const data = useData<DirectoryListing>(
    "directories",
    "/directories" + (path ? "?path=" + encodeURIComponent(path) : ""),
  );
  return (
    <Modal title="Selecionar pasta autorizada" onClose={close}>
      <p>
        Escolha uma pasta disponível no servidor que está executando o
        VulnRadar.
      </p>
      <ErrorBox error={data.error} />
      {data.isPending ? (
        <Skeleton />
      ) : data.data?.roots_configured ? (
        <>
          <div className="directory-current">
            <FolderOpen size={17} />
            <span className="mono">
              {data.data.path || "Raízes disponíveis"}
            </span>
            {data.data.parent && (
              <button
                onClick={() => setPath(data.data!.parent!)}
                aria-label="Pasta superior"
              >
                <ChevronUp size={16} />
              </button>
            )}
          </div>
          <div className="directory-list">
            {data.data.directories.map((d) => (
              <button key={d.path} onClick={() => setPath(d.path)}>
                <FolderOpen size={17} />
                <span>{d.name}</span>
                <ChevronRight size={14} />
              </button>
            ))}
          </div>
          {data.data.path && (
            <button
              className="primary"
              onClick={() => {
                select(data.data!.path!);
                close();
              }}
            >
              Selecionar esta pasta
            </button>
          )}
        </>
      ) : (
        <Empty title="Nenhuma pasta foi disponibilizada">
          Peça ao administrador da instalação para liberar uma pasta de projetos
          nas configurações do servidor. Em uma instalação local, consulte
          “Autorizar diretórios” no README. O navegador não recebe acesso
          irrestrito ao seu computador.
        </Empty>
      )}
    </Modal>
  );
}
function ScanWizard({
  project,
  close,
  onScan,
}: {
  project?: Project;
  close: () => void;
  onScan: (id: number) => void;
}) {
  const qc = useQueryClient();
  const [step, setStep] = useState(project ? 2 : 1);
  const [current, setCurrent] = useState(project);
  const [name, setName] = useState("");
  const [path, setPath] = useState("");
  const [picker, setPicker] = useState(false);
  const [kind, setKind] = useState("sca");
  const inspection = useQuery({
    queryKey: ["inspect", current?.id],
    queryFn: () => api<ProjectInspection>(`/projects/${current!.id}/inspect`),
    enabled: !!current,
    refetchInterval: false,
  });
  const engines = useQuery({
    queryKey: ["engines"],
    queryFn: () =>
      api<{ osv: string; semgrep: boolean; rules: number }>("/engines"),
    enabled: step === 3,
    refetchInterval: false,
    staleTime: 60000,
  });
  const create = useMutation({
    mutationFn: () => api<Project>("/projects", "POST", { name, path }),
    onSuccess: (p) => {
      setCurrent(p);
      setStep(2);
      qc.invalidateQueries();
    },
  });
  const run = useMutation({
    mutationFn: () =>
      api<Scan>(`/projects/${current!.id}/scans/${kind}`, "POST"),
    onSuccess: (s) => {
      qc.invalidateQueries();
      onScan(s.id);
      close();
    },
  });
  return (
    <>
      <Modal
        title={
          project ? "Preparar análise" : "Cadastrar e analisar repositório"
        }
        onClose={close}
        wide
      >
        <ol className="wizard-steps">
          {["Repositório", "Tipo de análise", "Pré-requisitos"].map(
            (label, index) => (
              <li
                key={label}
                className={
                  step === index + 1 ? "active" : step > index + 1 ? "done" : ""
                }
              >
                <span>
                  {step > index + 1 ? <CheckCircle2 size={14} /> : index + 1}
                </span>
                {label}
              </li>
            ),
          )}
        </ol>
        {step === 1 && (
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            <label>
              Nome do projeto
              <input
                autoFocus
                required
                maxLength={150}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Como sua aplicação é conhecida?"
              />
            </label>
            <label>
              Pasta do repositório
              <div className="input-action">
                <input
                  required
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  placeholder="Selecione uma pasta autorizada"
                />
                <button type="button" onClick={() => setPicker(true)}>
                  <FolderOpen size={16} />
                  Selecionar pasta
                </button>
              </div>
            </label>
            <p className="muted">
              Somente diretórios disponibilizados pela instalação são aceitos.
              Não executamos scripts ou instaladores do repositório.
            </p>
            <ErrorBox error={create.error} />
            <button className="primary" disabled={create.isPending}>
              Validar e continuar <ArrowRight size={15} />
            </button>
          </form>
        )}
        {step === 2 && (
          <>
            <div className="project-context">
              <FolderGit2 size={20} />
              <div>
                <b>{current?.name}</b>
                <small>{current?.path}</small>
              </div>
            </div>
            <ErrorBox error={inspection.error} />
            {inspection.isPending ? (
              <Skeleton rows={2} />
            ) : (
              inspection.data && (
                <div className="detection-summary">
                  <span>
                    Linguagens:{" "}
                    {inspection.data.languages.join(", ") ||
                      "Não identificadas"}
                  </span>
                  <span>
                    {inspection.data.lockfiles.length} manifestos suportados
                  </span>
                  {inspection.data.frameworks.length > 0 && (
                    <span>{inspection.data.frameworks.join(", ")}</span>
                  )}
                </div>
              )
            )}
            <div className="scan-choices">
              {[
                {
                  kind: "sca",
                  title: "SCA — Dependências",
                  description:
                    "Identifica componentes e versões, consulta advisories e informa correções.",
                  icon: ScanLine,
                },
                {
                  kind: "sast",
                  title: "SAST — Código",
                  description:
                    "Executa regras Semgrep localmente, com evidências por arquivo e linha.",
                  icon: ShieldCheck,
                },
                {
                  kind: "combined",
                  title: "Análise combinada",
                  description:
                    "Executa dependências e código; falhas de um motor ficam explícitas no resultado.",
                  icon: FolderGit2,
                },
              ].map((option) => (
                <label
                  key={option.kind}
                  className={kind === option.kind ? "selected" : ""}
                >
                  <input
                    type="radio"
                    name="scan-kind"
                    value={option.kind}
                    checked={kind === option.kind}
                    onChange={() => setKind(option.kind)}
                  />
                  <option.icon size={21} />
                  <span>
                    <b>{option.title}</b>
                    <small>{option.description}</small>
                  </span>
                </label>
              ))}
            </div>
            <div className="modal-actions">
              <button onClick={close}>Cancelar</button>
              <button
                className="primary"
                disabled={!inspection.data || !!inspection.error}
                onClick={() => setStep(3)}
              >
                Verificar pré-requisitos <ArrowRight size={15} />
              </button>
            </div>
          </>
        )}
        {step === 3 && (
          <>
            <h3>
              Verificação para{" "}
              {kind === "combined" ? "SCA + SAST" : kind.toUpperCase()}
            </h3>
            <p>
              Os estados abaixo refletem esta instalação. A cobertura final é
              registrada durante a execução.
            </p>
            {inspection.data?.checks.map((check) => (
              <div className="check-row" key={check.label}>
                {check.status === "ready" ? (
                  <CheckCircle2 size={18} />
                ) : (
                  <AlertTriangle size={18} />
                )}
                <div>
                  <b>{check.label}</b>
                  {check.message && check.status !== "ready" && (
                    <small>{check.message}</small>
                  )}
                </div>
                <Badge value={check.status} />
              </div>
            ))}
            {kind !== "sast" && (
              <div className="check-row">
                <ScanLine size={18} />
                <div>
                  <b>Conectividade com OSV</b>
                  <small>
                    A consulta dos pacotes será verificada durante a análise
                  </small>
                </div>
                <Badge
                  value={
                    engines.isPending
                      ? "running"
                      : engines.data?.osv === "reachable"
                        ? "ready"
                        : "unavailable"
                  }
                />
              </div>
            )}
            <ErrorBox error={run.error} />
            <div className="callout">
              <ShieldCheck size={18} />
              <p>
                {kind === "sast"
                  ? "O código será analisado localmente com regras disponibilizadas pela instalação."
                  : "A consulta OSV envia ecossistema, nomes e versões das dependências. Código-fonte não é enviado."}{" "}
                Limitações serão apresentadas no resultado.
              </p>
            </div>
            <div className="modal-actions">
              <button onClick={() => setStep(2)}>Voltar</button>
              <button
                className="primary"
                disabled={
                  run.isPending || (kind === "sast" && !engines.data?.semgrep)
                }
                onClick={() => run.mutate()}
              >
                Executar análise <ArrowRight size={15} />
              </button>
            </div>
          </>
        )}
      </Modal>
      {picker && (
        <DirectoryPicker
          close={() => setPicker(false)}
          select={(value) => {
            setPath(value);
            if (!name)
              setName(value.split(/[\\/]/).filter(Boolean).at(-1) || "");
          }}
        />
      )}
    </>
  );
}
export function ScanDetails({ id, close }: { id: number; close: () => void }) {
  const qc = useQueryClient();
  const scan = useData<Scan>("scan", "/scans/" + id);
  const [tab, setTab] = useState("summary");
  const [finding, setFinding] = useState<number | null>(null);
  const data = scan.data;
  const observations = useData<Page<Finding>>(
    "scan-findings",
    "/findings?status=&scan_id=" + id + "&page_size=100",
  );
  const cancel = useMutation({
    mutationFn: () => api("/scans/" + id + "/cancel", "POST"),
    onSuccess: () => qc.invalidateQueries(),
  });
  const active = data && ["pending", "running"].includes(data.status);
  const sca =
    data?.result.sca ||
    (["sca", "oci"].includes(data?.kind || "") ? data?.result : undefined);
  const sast =
    data?.result.sast || (data?.kind === "sast" ? data.result : undefined);
  const localFindings = observations.data?.items || [];
  return (
    <>
      <Modal title={"Análise #" + id} drawer wide onClose={close}>
        <ErrorBox error={scan.error || cancel.error} />
        {scan.isPending ? (
          <Skeleton />
        ) : (
          data && (
            <>
              <div className="scan-run-heading">
                <div>
                  <Badge value={data.kind.toUpperCase()} />
                  <Badge value={data.status} />
                  <h3>Projeto #{data.project_id}</h3>
                  <p>
                    <Clock size={13} />
                    Início: {formatDate(data.created_at)}
                    {data.completed_at &&
                      " · Conclusão: " + formatDate(data.completed_at)}
                  </p>
                </div>
                {active && (
                  <button
                    onClick={() => cancel.mutate()}
                    disabled={cancel.isPending}
                  >
                    <Square size={13} />
                    Cancelar
                  </button>
                )}
              </div>
              {active && (
                <div className="scan-progress">
                  <span className="pulse-dot" />
                  <b>{statusLabels[data.stage || "preparing"] || data.stage}</b>
                  <p>
                    Etapa informada pelo worker. Sem estimativa artificial de
                    porcentagem.
                  </p>
                </div>
              )}
              <Tabs
                value={tab}
                onChange={setTab}
                items={[
                  {
                    id: "summary",
                    label: "Resumo",
                    content: (
                      <>
                        {data.result.image && (
                          <div className="notice">
                            <b>{data.result.image}</b>
                            <p className="mono">
                              Digest:{" "}
                              {data.result.digest ||
                                "Não informado pelo mecanismo"}
                            </p>
                            <p>
                              Tipo do digest:{" "}
                              {data.result.digest_type === "repository"
                                ? "referência do repositório"
                                : data.result.digest_type === "manifest"
                                  ? "manifesto da plataforma"
                                  : "configuração da imagem"}
                            </p>
                            <p>Fonte: {data.result.engine}</p>
                          </div>
                        )}
                        <div className="result-kpis">
                          <div>
                            <small>Componentes</small>
                            <strong>
                              {data.result.inventory?.length ?? 0}
                            </strong>
                          </div>
                          <div>
                            <small>
                              Achados {data.kind === "oci" ? "OCI" : "SCA"}
                            </small>
                            <strong>{sca?.findings?.length ?? "—"}</strong>
                          </div>
                          <div>
                            <small>Achados SAST</small>
                            <strong>{sast?.findings?.length ?? "—"}</strong>
                          </div>
                          <div>
                            <small>Cobertura</small>
                            <strong className="coverage-value">
                              {data.result.coverage || "Em preparação"}
                            </strong>
                          </div>
                        </div>
                        {data.result.warnings?.length ? (
                          <div className="coverage-warning">
                            <h3>Limitações e ações necessárias</h3>
                            <ul>
                              {data.result.warnings.map((w, i) => (
                                <li key={i}>
                                  {typeof w === "string"
                                    ? w
                                    : JSON.stringify(w)}
                                </li>
                              ))}
                            </ul>
                          </div>
                        ) : (
                          !active && (
                            <div className="notice">
                              Execução concluída dentro do escopo registrado.
                              Isso não comprova ausência de vulnerabilidades.
                            </div>
                          )
                        )}
                        <div className="button-row">
                          <a
                            className="button"
                            href={`/api/scans/${id}/export?format=json`}
                            download
                          >
                            Relatório JSON
                          </a>
                          {sca && (
                            <a
                              className="button"
                              href={`/api/scans/${id}/export?format=cyclonedx`}
                              download
                            >
                              CycloneDX
                            </a>
                          )}
                          {sast && (
                            <a
                              className="button"
                              href={`/api/scans/${id}/export?format=sarif`}
                              download
                            >
                              SARIF
                            </a>
                          )}
                        </div>
                      </>
                    ),
                  },
                  {
                    id: "sca",
                    label: data.kind === "oci" ? "OCI" : "SCA",
                    count: localFindings.filter(
                      (f) => f.kind === (data.kind === "oci" ? "oci" : "sca"),
                    ).length,
                    content: localFindings.some(
                      (f) => f.kind === (data.kind === "oci" ? "oci" : "sca"),
                    ) ? (
                      <FindingsTable
                        items={localFindings.filter(
                          (f) =>
                            f.kind === (data.kind === "oci" ? "oci" : "sca"),
                        )}
                        open={setFinding}
                      />
                    ) : (
                      <Empty
                        title={
                          sca
                            ? "Nenhum achado SCA registrado"
                            : "SCA não executado nesta análise"
                        }
                      >
                        Verifique as limitações antes de interpretar a ausência
                        de correspondências.
                      </Empty>
                    ),
                  },
                  {
                    id: "sast",
                    label: "SAST",
                    count: localFindings.filter((f) => f.kind === "sast")
                      .length,
                    content: localFindings.some((f) => f.kind === "sast") ? (
                      <FindingsTable
                        items={localFindings.filter((f) => f.kind === "sast")}
                        open={setFinding}
                      />
                    ) : (
                      <Empty
                        title={
                          sast
                            ? "Nenhum padrão identificado pelas regras"
                            : "SAST não executado nesta análise"
                        }
                      >
                        A cobertura depende das linguagens, regras e arquivos
                        analisados.
                      </Empty>
                    ),
                  },
                  {
                    id: "inventory",
                    label: "Inventário",
                    count: data.result.inventory?.length || 0,
                    content: data.result.inventory?.length ? (
                      <div className="table-scroll">
                        <table>
                          <thead>
                            <tr>
                              <th>Componente</th>
                              <th>Versão</th>
                              <th>Ecossistema</th>
                              <th>Arquivo</th>
                            </tr>
                          </thead>
                          <tbody>
                            {data.result.inventory.map((c, index) => (
                              <tr key={index}>
                                <td>{c.package}</td>
                                <td className="mono">{c.version}</td>
                                <td>{c.ecosystem}</td>
                                <td className="mono">{c.file}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <Empty title="Nenhum inventário registrado" />
                    ),
                  },
                  {
                    id: "history",
                    label: "Comparação",
                    content: (
                      <>
                        <h3>Comparação com a análise anterior</h3>
                        {data.result.comparison ? (
                          <>
                            <div className="result-kpis">
                              <div>
                                <small>Novos</small>
                                <strong>{data.result.comparison.new}</strong>
                              </div>
                              <div>
                                <small>Persistentes</small>
                                <strong>
                                  {data.result.comparison.persistent}
                                </strong>
                              </div>
                              <div>
                                <small>Reabertos</small>
                                <strong>
                                  {data.result.comparison.reopened ?? 0}
                                </strong>
                              </div>
                              <div>
                                <small>Resolvidos</small>
                                <strong>
                                  {data.result.comparison.resolved}
                                </strong>
                              </div>
                            </div>
                            <div className="notice">
                              {data.result.comparison.comparable
                                ? "Resolução por ausência permitida somente para análise completa e escopo comparável."
                                : "Sem baseline completo e comparável; nenhum achado é resolvido apenas por não aparecer nesta execução."}
                            </div>
                          </>
                        ) : (
                          <p>
                            A comparação será registrada ao consolidar o
                            resultado.
                          </p>
                        )}
                        <Link
                          to={"/history?project_id=" + data.project_id}
                          onClick={close}
                        >
                          Abrir histórico de jobs <ArrowRight size={14} />
                        </Link>
                      </>
                    ),
                  },
                ]}
              />
            </>
          )
        )}
      </Modal>
      {finding && (
        <FindingDetails id={finding} close={() => setFinding(null)} />
      )}
    </>
  );
}
export function Projects() {
  const [params, setParams] = useSearchParams();
  const projects = useData<Project[]>("projects", "/projects");
  const scans = useData<Scan[]>("scans", "/scans");
  const [creating, setCreating] = useState(false);
  const [chosen, setChosen] = useState<Project | undefined>();
  const selected = Number(params.get("scan")) || null;
  const projectFilter = Number(params.get("project")) || null;
  const openScan = (id: number) => {
    const n = new URLSearchParams(params);
    n.set("scan", String(id));
    setParams(n);
  };
  return (
    <>
      <Header
        eyebrow="APPLICATION SECURITY"
        title="Repositórios e análises"
        description="Conheça seus componentes. Investigue seu código. Acompanhe a correção."
        action={
          <button className="primary" onClick={() => setCreating(true)}>
            <Plus size={16} />
            Cadastrar repositório
          </button>
        }
      />
      <ErrorBox error={projects.error || scans.error} />
      {projectFilter && (
        <div className="notice">
          Projeto selecionado #{projectFilter} ·{" "}
          <Link to="/projects">Ver todos os projetos</Link>
        </div>
      )}
      <div className="section-title">
        <div>
          <FolderGit2 size={17} />
          <h2>Projetos autorizados</h2>
          <span className="chip">{projects.data?.length || 0} projetos</span>
        </div>
        <Link to="/inventory">
          Inventário de componentes <ArrowRight size={14} />
        </Link>
      </div>
      {projects.isPending ? (
        <Skeleton />
      ) : projects.data?.length ? (
        <div className="project-grid">
          {projects.data
            .filter((project) => !projectFilter || project.id === projectFilter)
            .map((project) => (
              <section className="panel project-card" key={project.id}>
                <div className="project-card-top">
                  <span className="project-icon">
                    <FolderGit2 size={23} />
                  </span>
                  <Badge value="Local" />
                </div>
                <h2>{project.name}</h2>
                <p className="project-path mono">{project.path}</p>
                <div className="project-card-meta">
                  <Link to={"/priorities?project_id=" + project.id}>
                    Investigar achados <ArrowRight size={13} />
                  </Link>
                </div>
                <button
                  className="secondary"
                  onClick={() => setChosen(project)}
                >
                  Preparar análise <ArrowRight size={14} />
                </button>
              </section>
            ))}
        </div>
      ) : (
        <section className="panel getting-started">
          <span className="project-icon">
            <FolderGit2 size={30} />
          </span>
          <h2>Seu software merece contexto</h2>
          <p>
            Selecione um repositório autorizado para identificar linguagens,
            dependências e possibilidades de análise. O código do projeto não
            será executado.
          </p>
          <ol>
            <li>Cadastre a pasta</li>
            <li>Escolha SCA, SAST ou ambos</li>
            <li>Investigue as evidências</li>
          </ol>
          <button className="primary" onClick={() => setCreating(true)}>
            <Plus size={15} />
            Cadastrar primeiro repositório
          </button>
        </section>
      )}
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Execuções recentes</h2>
            <p>Estados persistidos · um scan em execução por vez</p>
          </div>
          <Link to="/history">
            Todos os jobs <ArrowRight size={13} />
          </Link>
        </div>
        {scans.isPending ? (
          <Skeleton />
        ) : scans.data?.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Execução</th>
                  <th>Projeto</th>
                  <th>Análise</th>
                  <th>Etapa</th>
                  <th>Estado</th>
                  <th>Início</th>
                  <th>Resultado</th>
                </tr>
              </thead>
              <tbody>
                {scans.data
                  .filter(
                    (scan) =>
                      !projectFilter || scan.project_id === projectFilter,
                  )
                  .map((scan) => (
                    <tr key={scan.id}>
                      <td className="mono">#{scan.id}</td>
                      <td>
                        {projects.data?.find((p) => p.id === scan.project_id)
                          ?.name || "#" + scan.project_id}
                      </td>
                      <td>
                        {scan.kind === "combined"
                          ? "SCA + SAST"
                          : scan.kind.toUpperCase()}
                      </td>
                      <td>
                        <span className="muted">
                          {statusLabels[scan.stage || ""] || scan.stage || "—"}
                        </span>
                      </td>
                      <td>
                        <Badge value={scan.status} />
                      </td>
                      <td>{formatDate(scan.created_at)}</td>
                      <td>
                        <button onClick={() => openScan(scan.id)}>
                          Investigar <ArrowRight size={13} />
                        </button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="Nenhuma análise executada">
            Inicie a primeira análise em um projeto para acompanhar suas etapas
            aqui.
          </Empty>
        )}
      </section>
      {(creating || chosen) && (
        <ScanWizard
          project={chosen}
          close={() => {
            setCreating(false);
            setChosen(undefined);
          }}
          onScan={openScan}
        />
      )}{" "}
      {selected && (
        <ScanDetails
          id={selected}
          close={() => {
            const n = new URLSearchParams(params);
            n.delete("scan");
            setParams(n);
          }}
        />
      )}
    </>
  );
}
