import { slaTone } from "../../lib/format";

const TONE_CLASSES: Record<string, string> = {
  clear: "text-clear border-clear/40 bg-clear/10",
  watch: "text-watch border-watch/40 bg-watch/10",
  breach: "text-breach border-breach/40 bg-breach/10",
  muted: "text-dim border-line bg-transparent",
};

export function StatusBadge({ status }: { status: string }) {
  const { label, tone } = slaTone(status);
  return (
    <span
      className={`inline-block px-2 py-0.5 text-xs font-semibold tracking-wide rounded border ${TONE_CLASSES[tone]}`}
    >
      {label}
    </span>
  );
}
