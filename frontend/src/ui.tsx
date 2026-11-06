import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { ChevronLeft, ChevronRight, X, ArrowUpRight } from "lucide-react";
import { Link } from "react-router-dom";

export function useDebounced<T>(value: T, delay = 300) {
  const [result, setResult] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setResult(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return result;
}
export function useStored<T>(key: string, initial: T) {
  const [value, setValue] = useState<T>(() => {
    try {
      return JSON.parse(localStorage.getItem(key) || "null") ?? initial;
    } catch {
      return initial;
    }
  });
  useEffect(() => {
    localStorage.setItem(key, JSON.stringify(value));
  }, [key, value]);
  return [value, setValue] as const;
}
export function Modal({
  title,
  children,
  onClose,
  drawer = false,
  wide = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  drawer?: boolean;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const id = useId();
  useEffect(() => {
    const element = ref.current;
    const active = document.activeElement as HTMLElement | null;
    if (element && !element.open) element.showModal();
    return () => {
      element?.close();
      active?.focus();
    };
  }, []);
  return createPortal(
    <dialog
      ref={ref}
      aria-labelledby={id}
      className={`${drawer ? "drawer" : "modal"} ${wide ? "wide" : ""}`}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        if (event.target === ref.current) {
          const rect = ref.current.getBoundingClientRect();
          if (
            event.clientX < rect.left ||
            event.clientX > rect.right ||
            event.clientY < rect.top ||
            event.clientY > rect.bottom
          )
            onClose();
        }
      }}
    >
      <div className="modal-head">
        <div>
          <span className="eyebrow">VULNRADAR / INVESTIGAÇÃO</span>
          <h2 id={id}>{title}</h2>
        </div>
        <button
          className="icon-button"
          onClick={onClose}
          aria-label={"Fechar " + title}
        >
          <X size={19} />
        </button>
      </div>
      <div className="modal-body">{children}</div>
    </dialog>,
    document.body,
  );
}
export function Tabs({
  items,
  value,
  onChange,
  label = "Seções",
}: {
  items: { id: string; label: string; content: ReactNode; count?: number }[];
  value: string;
  onChange: (id: string) => void;
  label?: string;
}) {
  const id = useId();
  return (
    <>
      <div role="tablist" aria-label={label} className="tabs">
        {items.map((item, index) => (
          <button
            type="button"
            key={item.id}
            role="tab"
            id={`${id}-${item.id}`}
            aria-controls={`${id}-panel`}
            aria-selected={value === item.id}
            tabIndex={value === item.id ? 0 : -1}
            onClick={() => onChange(item.id)}
            onKeyDown={(event) => {
              if (
                ["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)
              ) {
                event.preventDefault();
                const next =
                  event.key === "Home"
                    ? 0
                    : event.key === "End"
                      ? items.length - 1
                      : (index +
                          (event.key === "ArrowRight" ? 1 : -1) +
                          items.length) %
                        items.length;
                onChange(items[next].id);
                document.getElementById(`${id}-${items[next].id}`)?.focus();
              }
            }}
          >
            {item.label}
            {item.count !== undefined && (
              <span className="count">{item.count}</span>
            )}
          </button>
        ))}
      </div>
      <div
        role="tabpanel"
        id={`${id}-panel`}
        aria-labelledby={`${id}-${value}`}
        tabIndex={0}
        className="tab-content"
      >
        {items.find((item) => item.id === value)?.content}
      </div>
    </>
  );
}
export function Pagination({
  page,
  total,
  size,
  onChange,
}: {
  page: number;
  total: number;
  size: number;
  onChange: (n: number) => void;
}) {
  return (
    <div className="pagination">
      <span>
        {total
          ? `${(page - 1) * size + 1}–${Math.min(page * size, total)} de ${total.toLocaleString("pt-BR")}`
          : "Nenhum registro"}
      </span>
      <span>
        Página {page} de {Math.max(1, Math.ceil(total / size))}
      </span>
      <button
        aria-label="Página anterior"
        disabled={page <= 1}
        onClick={() => onChange(page - 1)}
      >
        <ChevronLeft size={16} />
      </button>
      <button
        aria-label="Próxima página"
        disabled={page * size >= total}
        onClick={() => onChange(page + 1)}
      >
        <ChevronRight size={16} />
      </button>
    </div>
  );
}
export function Skeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div
      role="status"
      aria-label="Carregando dados"
      className="loading-skeleton"
    >
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="skeleton-line" />
      ))}
    </div>
  );
}
export function Kpi({
  label,
  value,
  context,
  to,
  state = "observed",
  tone = "default",
}: {
  label: string;
  value: number | null;
  context: string;
  to: string;
  state?: string;
  tone?: string;
}) {
  return (
    <Link className={`metric ${tone}`} to={to}>
      <div>
        {label}
        <ArrowUpRight size={16} />
      </div>
      <strong>{value === null ? "—" : value.toLocaleString("pt-BR")}</strong>
      <small>{context}</small>
      <span className="kpi-state">
        {state === "observed"
          ? "Evidências dos scans"
          : state === "no_projects"
            ? "Sem projetos"
            : state === "partial"
              ? "Cobertura parcial"
              : state === "not_scanned"
                ? "Aguardando análise"
                : state}
      </span>
    </Link>
  );
}
export function Notice({
  children,
  tone = "info",
}: {
  children: ReactNode;
  tone?: string;
}) {
  return <div className={`notice ${tone}`}>{children}</div>;
}
