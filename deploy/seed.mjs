// Seed PatchGuard with real transactions on GenLayer Studio for 5 real packages.
//   cd deploy && node seed.mjs
// Uses ACCOUNT_PRIVATE_KEY + CONTRACT_ADDRESS from the root .env.
// Budget-conscious: 1 GEN stake per pool (5 GEN total), 0.5 GEN coverage, 0.1 GEN premium.
//
// NOTE on anti-adverse-selection rules (contracts/patch_guard.py):
//   - buy_policy itself now re-fetches live GitHub Advisory Database evidence and
//     REJECTS the purchase if the package already has an open, unpatched
//     CRITICAL/HIGH advisory -- you can no longer buy cheap coverage against a
//     breach that's already public knowledge. Pick packages that are currently
//     clean (or only have lower-severity open advisories) before seeding:
//       curl "https://api.github.com/advisories?ecosystem=<eco>&affects=<name>"
//   - file_claim additionally enforces a waiting period (WAITING_PERIOD_DAYS,
//     currently 7) after purchase before any claim can be filed at all, and
//     excludes payout for the exact advisory (by ghsa_id) that was already open
//     at purchase time even if its severity later escalates.
// Because of both of those, this script can no longer buy-then-instantly-claim
// in one run -- that immediate round-trip was exactly the exploit being closed.
// It seeds the 5 pools/policies and prints how to file a real claim later.
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import dotenv from "dotenv";
import { createClient, createAccount } from "genlayer-js";
import { studionet } from "genlayer-js/chains";
import { TransactionStatus } from "genlayer-js/types";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
dotenv.config({ path: resolve(root, ".env") });

const pk = process.env.ACCOUNT_PRIVATE_KEY;
const CONTRACT = process.env.CONTRACT_ADDRESS;
if (!pk || !CONTRACT) {
  console.error("Need ACCOUNT_PRIVATE_KEY and CONTRACT_ADDRESS in .env");
  process.exit(1);
}

const GEN = 10n ** 18n;
const STAKE = 1n * GEN;            // 1 GEN per pool  -> 5 GEN total
const COVERAGE = GEN / 2n;         // 0.5 GEN coverage
const PREMIUM = GEN / 10n;         // 0.1 GEN premium
const DURATION = 90n;              // days

// Real, widely-used packages across ecosystems the GitHub Advisory Database covers.
// If any of these currently has an open unpatched CRITICAL/HIGH advisory,
// buy_policy will (correctly) reject the purchase for that one -- swap it out
// or just let this script report the failure and move on to the rest.
const PACKAGES = [
  "PyPI/django",
  "npm/lodash",
  "npm/express",
  "PyPI/pyyaml",
  "Maven/log4j-core",
];

const account = createAccount(pk.startsWith("0x") ? pk : `0x${pk}`);
const client = createClient({ chain: studionet, account });

async function tx(label, functionName, args, value = 0n) {
  process.stderr.write(`→ ${label} … `);
  try {
    const hash = await client.writeContract({ address: CONTRACT, functionName, args, value });
    await client.waitForTransactionReceipt({
      hash, status: TransactionStatus.ACCEPTED, interval: 5000, retries: 90,
    });
    console.error(`ok  tx: ${hash}`);
    return hash;
  } catch (e) {
    console.error(`FAIL: ${e?.message || e}`);
    return null;
  }
}

async function read(functionName, args = []) {
  return client.readContract({ address: CONTRACT, functionName, args });
}

console.error(`Seeding PatchGuard ${CONTRACT} from ${account.address}\n`);

// 1) Underwrite + insure each real package. A purchase can legitimately fail
// here if the package currently has an open unpatched CRITICAL/HIGH advisory
// (the purchase-time risk check) -- that's by design, not a bug.
const config = await read("get_config");
for (const pkg of PACKAGES) {
  await tx(`underwrite ${pkg} (1 GEN)`, "underwrite", [pkg], STAKE);
  await tx(`buy_policy  ${pkg} (cov 0.5, prem 0.1)`, "buy_policy", [pkg, COVERAGE, DURATION], PREMIUM);
}

const stats = await read("get_stats");
console.error("\n================ SEEDED STATE (on-chain) ================");
console.error("stats:", JSON.stringify(stats));
console.error("============================================================");

console.error(
  `\nEach policy above has a ${config.waiting_period_days}-day waiting period from ` +
  `its purchase time before file_claim can be called on it at all, and any advisory ` +
  `that was already open at purchase is excluded from that policy's payout even if ` +
  `it later escalates in severity. To demo a real payout: wait for the waiting ` +
  `period to elapse, confirm a package now has a genuinely NEW unpatched CRITICAL/HIGH ` +
  `advisory (published after purchase) older than its SLA window, then call ` +
  `file_claim(package) for it -- from the frontend once connected, or via ` +
  `client.writeContract({ address, functionName: "file_claim", args: [package] }) ` +
  `the same way this script calls buy_policy above.`
);
