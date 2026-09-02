import type { HTMLAttributes } from "react";

export function Card({ className = "", ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={`bg-panel border border-line rounded-lg p-5 shadow-glow ${className}`}
      {...props}
    />
  );
}
