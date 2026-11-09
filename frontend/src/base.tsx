import {
  type ButtonHTMLAttributes,
  type ComponentProps,
  type HTMLAttributes,
  type ReactNode,
  type TableHTMLAttributes,
  useRef,
} from "react";
import { Modal } from "./ui";
export { Empty as EmptyState, Badge as SeverityBadge } from "./shared";
export function Drawer(props: Omit<ComponentProps<typeof Modal>, "drawer">) {
  return <Modal {...props} drawer />;
}

export function Button({
  type = "button",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button type={type} {...props} />;
}

export function Field({
  label,
  children,
  ...props
}: { label: string; children: ReactNode } & HTMLAttributes<HTMLLabelElement>) {
  return (
    <label {...props}>
      {label}
      {children}
    </label>
  );
}

export function Table({
  label,
  children,
  ...props
}: { label: string } & TableHTMLAttributes<HTMLTableElement>) {
  const current = useRef(-1);
  return (
    <table
      {...props}
      aria-label={label}
      tabIndex={0}
      onKeyDown={(event) => {
        props.onKeyDown?.(event);
        if (
          event.defaultPrevented ||
          (event.target instanceof HTMLElement &&
            event.target.closest("input, select, textarea"))
        )
          return;
        const rows = Array.from(
          event.currentTarget.querySelectorAll<HTMLButtonElement>(
            "tbody button[data-row-action]",
          ),
        );
        if ((event.key === "j" || event.key === "k") && rows.length) {
          event.preventDefault();
          const focused = rows.findIndex(
            (item) => item === document.activeElement,
          );
          current.current = Math.max(
            0,
            Math.min(
              rows.length - 1,
              (focused < 0 ? current.current : focused) +
                (event.key === "j" ? 1 : -1),
            ),
          );
          rows[current.current].focus();
        } else if (
          event.key === "Enter" &&
          event.target === event.currentTarget &&
          rows.length
        ) {
          event.preventDefault();
          rows[Math.max(0, current.current)]?.click();
        } else if (event.key === "Escape") {
          event.currentTarget.focus();
        }
      }}
    >
      {children}
    </table>
  );
}
