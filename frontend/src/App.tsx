import { useState } from "react";
import { usePrivy } from "@privy-io/react-auth";
import { ShieldCheck, LogOut, RefreshCw, Loader2 } from "lucide-react";
import { Card } from "./components/ui/Card";
import { Button } from "./components/ui/Button";
import { StatusBadge } from "./components/ui/StatusBadge";
import { useActiveWallet, useProtocol, useTx } from "./hooks/usePatchGuard";
import { api } from "./lib/genlayer";
import { formatGen, parseGen, shortAddr } from "./lib/format";
import type { Policy } from "./lib/genlayer";

function Header() {
  const { ready, authenticated, login, logout, user } = usePrivy();
  const { address } = useActiveWallet();
  return (
    <header className="border-b border-line">
      <div className="max-w-5xl mx-auto px-5 py-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="text-clear" size={22} />
          <span className="font-bold text-lg tracking-tight">PatchGuard</span>
          <span className="hidden sm:inline text-xs text-dim ml-2 border border-line rounded px-2 py-0.5">
            GenLayer Studio
          </span>
        </div>
        {ready && authenticated ? (
          <div className="flex items-center gap-3">
            <span className="text-xs text-dim">{shortAddr(address ?? user?.wallet?.address)}</span>
            <Button variant="ghost" onClick={logout}>
              <LogOut size={14} className="inline mr-1" /> Disconnect
            </Button>
          </div>
        ) : (
          <Button onClick={login}>Connect wallet</Button>
        )}
      </div>
    </header>
  );
}

function Hero() {
  return (
    <section className="max-w-5xl mx-auto px-5 pt-12 pb-8">
      <h1 className="text-3xl sm:text-4xl font-bold leading-tight max-w-2xl">
        Insurance against the CVE your maintainer never patches.
      </h1>
      <p className="text-dim mt-4 max-w-2xl leading-relaxed">
        Underwrite a pool. Insure a public package against an unpatched CRITICAL or HIGH
        severity vulnerability blowing past its disclosure-to-patch SLA. Claims are settled
        on-chain by GenLayer validators reading the public GitHub Advisory Database
        independently and voting to consensus. No insurer, no oracle.
      </p>
    </section>
  );
}

function HowItWorks() {
  const steps = [
    ["Underwrite", "Stake GEN into a per-package pool (e.g. PyPI/django). Mint proportional shares."],
    ["Insure", "Pay a premium to cover a payout amount for N days on that package."],
    ["File a claim", "Validators each fetch api.github.com/advisories for the package, independently."],
    ["Settle", "Code derives the worst unpatched advisory + its age. An LLM grounded with those facts assigns clear / watch / breach. Validators must agree. \"breach\" pays out from the pool automatically."],
  ];
  return (
    <section className="max-w-5xl mx-auto px-5 py-8">
      <h2 className="text-sm uppercase tracking-widest text-dim mb-4">How it works</h2>
      <div className="grid sm:grid-cols-4 gap-4">
        {steps.map(([title, body], i) => (
          <Card key={title}>
            <div className="text-clear text-xs mb-2">0{i + 1}</div>
            <div className="font-semibold mb-1">{title}</div>
            <div className="text-xs text-dim leading-relaxed">{body}</div>
          </Card>
        ))}
      </div>
    </section>
  );
}

function StatsBar({ stats }: { stats: ReturnType<typeof useProtocol>["stats"] }) {
  const items = [
    ["Pools", stats?.pools ?? "—"],
    ["Policies", stats?.policies ?? "—"],
    ["Active policies", stats?.active_policies ?? "—"],
    ["Breaches paid", stats?.paid_claims ?? "—"],
    ["GEN staked", stats ? formatGen(stats.total_staked_wei) : "—"],
    ["GEN locked", stats ? formatGen(stats.total_locked_wei) : "—"],
  ] as const;
  return (
    <section className="max-w-5xl mx-auto px-5">
      <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
        {items.map(([label, value]) => (
          <div key={label} className="border border-line rounded-lg p-3 bg-panel">
            <div className="text-[10px] uppercase tracking-wide text-dim">{label}</div>
            <div className="text-lg font-bold mt-1">{String(value)}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

function NewPackageForm({ onDone }: { onDone: () => void }) {
  const [pkg, setPkg] = useState("");
  const [stake, setStake] = useState("1");
  const { run, state } = useTx();

  async function submit() {
    const hash = await run(`Underwrite ${pkg}`, "underwrite", {
      args: [pkg],
      value: parseGen(stake),
    });
    if (hash) {
      setPkg("");
      onDone();
    }
  }

  return (
    <Card>
      <div className="font-semibold mb-3">Underwrite a new package</div>
      <div className="flex flex-col sm:flex-row gap-2">
        <input
          className="flex-1 bg-base border border-line rounded px-3 py-2 text-sm outline-none focus:border-clear"
          placeholder="ecosystem/package  (e.g. PyPI/django)"
          value={pkg}
          onChange={(e) => setPkg(e.target.value)}
        />
        <input
          className="w-full sm:w-28 bg-base border border-line rounded px-3 py-2 text-sm outline-none focus:border-clear"
          placeholder="GEN stake"
          value={stake}
          onChange={(e) => setStake(e.target.value)}
        />
        <Button onClick={submit} disabled={!pkg || state.status === "pending"}>
          {state.status === "pending" ? <Loader2 className="animate-spin" size={14} /> : "Stake"}
        </Button>
      </div>
      {state.message && <div className="text-xs text-dim mt-2">{state.message}</div>}
    </Card>
  );
}

function PoolCard({
  pool,
  onDone,
}: {
  pool: { package: string; available_wei: string; locked_wei: string; total_stake_wei: string };
  onDone: () => void;
}) {
  const { address } = useActiveWallet();
  const [coverage, setCoverage] = useState("0.5");
  const [premium, setPremium] = useState("0.1");
  const [duration, setDuration] = useState("90");
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [checked, setChecked] = useState(false);
  const [myShares, setMyShares] = useState<string | null>(null);
  const [withdrawAmt, setWithdrawAmt] = useState("");
  const [showWithdraw, setShowWithdraw] = useState(false);
  const buy = useTx();
  const claim = useTx();
  const withdraw = useTx();
  const expire = useTx();

  async function loadPolicy() {
    if (!address) return;
    try {
      const p = await api.getPolicy(pool.package, address);
      setPolicy(p);
    } catch {
      setPolicy(null);
    } finally {
      setChecked(true);
    }
  }

  async function loadShares() {
    if (!address) return;
    try {
      const s = await api.getShares(pool.package, address);
      setMyShares(s);
    } catch {
      setMyShares("0");
    }
  }

  async function submitWithdraw() {
    const hash = await withdraw.run(`Withdraw from ${pool.package}`, "withdraw_stake", {
      args: [pool.package, parseGen(withdrawAmt)],
    });
    if (hash) {
      onDone();
      loadShares();
      setWithdrawAmt("");
    }
  }

  async function submitExpire() {
    if (!address) return;
    const hash = await expire.run(`Expire policy on ${pool.package}`, "expire_policy", {
      args: [pool.package, address],
    });
    if (hash) {
      onDone();
      loadPolicy();
    }
  }

  async function submitBuy() {
    const hash = await buy.run(`Insure ${pool.package}`, "buy_policy", {
      args: [pool.package, parseGen(coverage), Number(duration)],
      value: parseGen(premium),
    });
    if (hash) {
      onDone();
      loadPolicy();
    }
  }

  async function submitClaim() {
    const hash = await claim.run(`File claim on ${pool.package}`, "file_claim", {
      args: [pool.package],
    });
    if (hash) {
      onDone();
      loadPolicy();
    }
  }

  return (
    <Card>
      <div className="flex items-start justify-between">
        <div>
          <div className="font-semibold">{pool.package}</div>
          <div className="text-xs text-dim mt-1">
            Available {formatGen(pool.available_wei)} GEN · Locked {formatGen(pool.locked_wei)} GEN
          </div>
        </div>
        <Button variant="ghost" className="!px-2 !py-1" onClick={loadPolicy}>
          {checked ? "Refresh policy" : "My policy"}
        </Button>
      </div>

      {policy && policy.status !== "" && (
        <div className="mt-3 text-xs border border-line rounded p-3 bg-base/40 flex items-center justify-between">
          <div>
            <div className="text-dim">Your policy · {policy.status}</div>
            <div className="mt-1">
              Coverage {formatGen(policy.coverage_wei)} GEN
            </div>
            {policy.status === "ACTIVE" && (
              <button
                className="text-dim underline mt-1"
                onClick={submitExpire}
                disabled={expire.state.status === "pending"}
              >
                {expire.state.status === "pending" ? "Expiring…" : "Expire (after term ends)"}
              </button>
            )}
          </div>
          <StatusBadge status={policy.verdict} />
        </div>
      )}
      {expire.state.message && <div className="text-xs text-dim mt-1">{expire.state.message}</div>}

      <div className="mt-3 flex items-center justify-between text-xs">
        <button className="text-dim underline" onClick={loadShares}>
          {myShares !== null ? `My shares: ${formatGen(myShares)}` : "Check my shares"}
        </button>
        <button className="text-dim underline" onClick={() => setShowWithdraw((s) => !s)}>
          {showWithdraw ? "Close withdraw" : "Withdraw stake"}
        </button>
      </div>

      {showWithdraw && (
        <div className="mt-2 flex gap-2">
          <input
            className="flex-1 bg-base border border-line rounded px-2 py-1.5 text-xs outline-none focus:border-clear"
            placeholder="Shares to burn (GEN units)"
            value={withdrawAmt}
            onChange={(e) => setWithdrawAmt(e.target.value)}
          />
          <Button
            variant="ghost"
            onClick={submitWithdraw}
            disabled={!withdrawAmt || withdraw.state.status === "pending"}
          >
            {withdraw.state.status === "pending" ? <Loader2 className="animate-spin" size={14} /> : "Withdraw"}
          </Button>
        </div>
      )}
      {withdraw.state.message && <div className="text-xs text-dim mt-1">{withdraw.state.message}</div>}

      <div className="mt-4 grid grid-cols-3 gap-2">
        <input
          className="bg-base border border-line rounded px-2 py-1.5 text-xs outline-none focus:border-clear"
          placeholder="Coverage GEN"
          value={coverage}
          onChange={(e) => setCoverage(e.target.value)}
        />
        <input
          className="bg-base border border-line rounded px-2 py-1.5 text-xs outline-none focus:border-clear"
          placeholder="Premium GEN"
          value={premium}
          onChange={(e) => setPremium(e.target.value)}
        />
        <input
          className="bg-base border border-line rounded px-2 py-1.5 text-xs outline-none focus:border-clear"
          placeholder="Days"
          value={duration}
          onChange={(e) => setDuration(e.target.value)}
        />
      </div>
      <div className="mt-2 flex gap-2">
        <Button className="flex-1" onClick={submitBuy} disabled={buy.state.status === "pending"}>
          {buy.state.status === "pending" ? <Loader2 className="animate-spin mx-auto" size={14} /> : "Buy policy"}
        </Button>
        <Button
          variant="ghost"
          className="flex-1"
          onClick={submitClaim}
          disabled={claim.state.status === "pending"}
        >
          {claim.state.status === "pending" ? <Loader2 className="animate-spin mx-auto" size={14} /> : "File claim"}
        </Button>
      </div>
      {(buy.state.message || claim.state.message) && (
        <div className="text-xs text-dim mt-2">{buy.state.message || claim.state.message}</div>
      )}
    </Card>
  );
}

function PoolsGrid() {
  const { pools, stats, loading, refresh } = useProtocol();
  const [showNew, setShowNew] = useState(false);

  return (
    <section className="max-w-5xl mx-auto px-5 py-10">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm uppercase tracking-widest text-dim">Insured packages</h2>
        <div className="flex gap-2">
          <Button variant="ghost" onClick={refresh}>
            <RefreshCw size={14} className={loading ? "animate-spin inline mr-1" : "inline mr-1"} />
            Refresh
          </Button>
          <Button onClick={() => setShowNew((s) => !s)}>
            {showNew ? "Close" : "+ New pool"}
          </Button>
        </div>
      </div>

      {showNew && (
        <div className="mb-4">
          <NewPackageForm onDone={refresh} />
        </div>
      )}

      {pools.length === 0 && !loading && (
        <Card className="text-center text-dim text-sm py-8">
          No pools yet. Be the first to underwrite a package.
        </Card>
      )}

      <div className="grid sm:grid-cols-2 gap-4">
        {pools.map((p) => (
          <PoolCard key={p.package} pool={p} onDone={refresh} />
        ))}
      </div>

      {stats && stats.pools > 0 && <div className="h-2" />}
    </section>
  );
}

function Footer() {
  return (
    <footer className="border-t border-line mt-10">
      <div className="max-w-5xl mx-auto px-5 py-6 text-xs text-dim flex flex-col sm:flex-row justify-between gap-2">
        <span>PatchGuard — public GitHub Advisory evidence only. Nothing here is financial advice.</span>
        <span>Built on GenLayer Studio</span>
      </div>
    </footer>
  );
}

export default function App() {
  const { stats } = useProtocol();
  return (
    <div className="min-h-screen">
      <Header />
      <Hero />
      <StatsBar stats={stats} />
      <HowItWorks />
      <PoolsGrid />
      <Footer />
    </div>
  );
}
