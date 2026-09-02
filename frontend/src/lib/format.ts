// GEN <-> wei helpers. 1 GEN = 10^18 wei. Done with BigInt/strings to avoid
// floating-point precision loss on token amounts.
const DECIMALS = 18n;
const ONE = 10n ** DECIMALS;

/** Parse a human GEN string (e.g. "10.5") into wei as a bigint. */
export function parseGen(input: string): bigint {
  const s = (input ?? "").trim();
  if (!s) return 0n;
  if (!/^\d*\.?\d*$/.test(s)) throw new Error("Enter a valid number");
  const [whole, frac = ""] = s.split(".");
  const fracPadded = (frac + "0".repeat(18)).slice(0, 18);
  const wholePart = BigInt(whole || "0") * ONE;
  const fracPart = BigInt(fracPadded || "0");
  return wholePart + fracPart;
}

/** Format a wei value (bigint | string | number) as a trimmed GEN string. */
export function formatGen(wei: bigint | string | number, maxFrac = 4): string {
  let v: bigint;
  try {
    v = typeof wei === "bigint" ? wei : BigInt(String(wei ?? "0").split(".")[0] || "0");
  } catch {
    return "0";
  }
  const neg = v < 0n;
  if (neg) v = -v;
  const whole = v / ONE;
  const frac = v % ONE;
  let fracStr = frac.toString().padStart(18, "0").slice(0, maxFrac).replace(/0+$/, "");
  const out = fracStr ? `${whole}.${fracStr}` : `${whole}`;
  return neg ? `-${out}` : out;
}

/** Short 0x…addr display. */
export function shortAddr(a?: string): string {
  if (!a) return "";
  return a.length > 12 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a;
}

/** Human-friendly SLA-status label + tone. */
export function slaTone(status: string): { label: string; tone: "clear" | "watch" | "breach" | "muted" } {
  switch (status) {
    case "breach":
      return { label: "SLA BREACH", tone: "breach" };
    case "watch":
      return { label: "WATCHING", tone: "watch" };
    case "clear":
      return { label: "CLEAR", tone: "clear" };
    case "excluded":
      return { label: "EXCLUDED (PRE-EXISTING)", tone: "watch" };
    case "unverified":
      return { label: "UNVERIFIED", tone: "muted" };
    default:
      return { label: "NOT YET CHECKED", tone: "muted" };
  }
}
