// Deploy PatchGuard to GenLayer Studio network.
//   cd deploy && npm install && node deploy.mjs
// Reads ACCOUNT_PRIVATE_KEY (funded) and optional FEE_WALLET / FEE_BPS from the
// root .env. Prints only the deployed contract address to stdout.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import dotenv from "dotenv";
import { createClient, createAccount } from "genlayer-js";
import { studionet } from "genlayer-js/chains";
import { TransactionStatus } from "genlayer-js/types";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");
dotenv.config({ path: resolve(root, ".env") });

const pk = process.env.ACCOUNT_PRIVATE_KEY;
if (!pk) {
  console.error("ACCOUNT_PRIVATE_KEY is not set in .env");
  process.exit(1);
}

const account = createAccount(pk.startsWith("0x") ? pk : `0x${pk}`);
const feeWallet = (process.env.FEE_WALLET || account.address).trim();
const feeBps = Number(process.env.FEE_BPS || 500);

const code = readFileSync(resolve(root, "contracts/patch_guard.py"), "utf8");
const client = createClient({ chain: studionet, account });

console.error(
  `Deploying PatchGuard from ${account.address} (fee_wallet=${feeWallet}, fee_bps=${feeBps})…`,
);

const hash = await client.deployContract({ code, args: [feeWallet, feeBps] });
console.error(`deploy tx: ${hash}`);

const receipt = await client.waitForTransactionReceipt({
  hash,
  status: TransactionStatus.ACCEPTED,
  interval: 5000,
  retries: 60,
});

const address =
  receipt?.txDataDecoded?.contractAddress ??
  receipt?.data?.contract_address ??
  receipt?.contractAddress;

if (!address) {
  console.error("Could not read contract address from receipt:");
  console.error(JSON.stringify(receipt, null, 2).slice(0, 2000));
  process.exit(1);
}

// Only the address goes to stdout so it can be captured cleanly.
console.log(address);
