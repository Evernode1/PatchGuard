// GenLayer client wiring for PatchGuard.
// Reads use a chain-only client (no wallet). Writes are signed by the user's
// Privy wallet via its EIP-1193 provider, following the documented browser flow.
import { createClient } from "genlayer-js";
import { studionet } from "genlayer-js/chains";
import { TransactionStatus } from "genlayer-js/types";

export const CONTRACT_ADDRESS = (import.meta.env.VITE_CONTRACT_ADDRESS ?? "") as `0x${string}`;

export type Stats = {
  pools: number;
  policies: number;
  active_policies: number;
  paid_claims: number;
  total_staked_wei: string;
  total_locked_wei: string;
};

export type Pool = {
  package: string;
  total_stake_wei: string;
  total_shares: string;
  locked_wei: string;
  available_wei: string;
  premium_income_wei: string;
};

export type Policy = {
  holder: string;
  package: string;
  coverage_wei: string;
  premium_wei: string;
  start: number;
  expiry: number;
  status: string;
  verdict: string;
  last_checked: number;
  baseline_ghsa_ids: string;
};

// Read-only client -- talks directly to the Studio RPC, no account needed.
const readClient = createClient({ chain: studionet });

function read<T>(functionName: string, args: any[] = []): Promise<T> {
  return readClient.readContract({
    address: CONTRACT_ADDRESS,
    functionName,
    args,
  }) as Promise<T>;
}

export const api = {
  getStats: () => read<Stats>("get_stats"),
  getPools: () => read<Pool[]>("get_pools"),
  getPool: (pkg: string) => read<Pool>("get_pool", [pkg]),
  getPolicy: (pkg: string, holder: string) => read<Policy>("get_policy", [pkg, holder]),
  getShares: (pkg: string, underwriter: string) =>
    read<string>("get_shares", [pkg, underwriter]),
};

// Some wallet-detection code paths probe MetaMask-only Snaps methods
// (wallet_getSnaps, etc.). Non-MetaMask wallets like Rabby reject these with
// "method doesn't has corresponding handler", which can bubble up and abort an
// otherwise-fine transaction. We wrap the provider and answer those probes with
// "no snaps installed" (the truth), while passing every other call through.
const SNAP_PROBE_METHODS = new Set([
  "wallet_getSnaps",
  "wallet_requestSnaps",
  "wallet_invokeSnap",
  "wallet_snap",
]);

function hardenProvider(provider: any): any {
  if (!provider || typeof provider.request !== "function") return provider;
  const originalRequest = provider.request.bind(provider);
  return new Proxy(provider, {
    get(target, prop, receiver) {
      if (prop === "request") {
        return async (args: any) => {
          if (args && SNAP_PROBE_METHODS.has(args.method)) return {};
          return originalRequest(args);
        };
      }
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

/** Build a wallet-bound write client from a Privy EIP-1193 provider. */
async function getWriteClient(provider: unknown, address: string) {
  const client = createClient({
    chain: studionet,
    account: address as `0x${string}`,
    // genlayer-js accepts a standard EIP-1193 provider here.
    provider: hardenProvider(provider) as never,
  });
  // Ensure the wallet is on the Studio chain before signing.
  await client.connect("studionet");
  return client;
}

export type TxArgs = {
  provider: unknown;
  address: string;
  functionName: string;
  args?: any[];
  value?: bigint;
  onHash?: (hash: string) => void;
};

/** Send a write transaction and wait until it is accepted by consensus. */
export async function sendTx({ provider, address, functionName, args = [], value = 0n, onHash }: TxArgs) {
  const client = await getWriteClient(provider, address);
  const hash = await client.writeContract({
    address: CONTRACT_ADDRESS,
    functionName,
    args,
    value,
  });
  if (onHash) onHash(hash as string);
  const receipt = await client.waitForTransactionReceipt({
    hash,
    status: TransactionStatus.ACCEPTED,
    interval: 5000,
    retries: 120,
  });
  return { hash, receipt };
}
