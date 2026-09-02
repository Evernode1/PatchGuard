import type { ButtonHTMLAttributes } from "react";

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "ghost";
};

export function Button({ variant = "primary", className = "", ...props }: Props) {
  const base =
    "px-4 py-2 text-sm font-medium rounded border transition-colors disabled:opacity-40 disabled:cursor-not-allowed";
  const styles =
    variant === "primary"
      ? "bg-clear text-base border-clear hover:brightness-110"
      : "bg-transparent text-ink border-line hover:border-clear hover:text-clear";
  return <button className={`${base} ${styles} ${className}`} {...props} />;
}
