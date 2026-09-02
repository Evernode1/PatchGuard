# PatchGuard

### Trustless vulnerability-SLA insurance for open source packages

Underwrite a pool. Insure a public package against an unpatched CRITICAL or HIGH
severity vulnerability blowing past its disclosure-to-patch SLA. Settle claims
on-chain via GenLayer validator consensus, from real public evidence. No insurer,
no oracle.

---

## What makes this different from "abandonment insurance"

A package can be extremely active — frequent commits, frequent releases — and
still leave a critical CVE unpatched for months. Conversely, an otherwise quiet
package can patch a critical CVE within days. **Abandonment and security risk are
not the same signal.** PatchGuard insures the second one directly:

> If a CRITICAL or HIGH severity advisory is publicly disclosed for the insured
> package and the maintainers do **not** ship a patched version within the SLA
> window (30 days for CRITICAL, 60 for HIGH), the policy pays out.

Evidence comes from the public **GitHub Advisory Database**
(`GET https://api.github.com/advisories?ecosystem=...&affects=...`) instead of the
repo's archived/pushed-at fields — a different public, unauthenticated, per-package
API surface that every GenLayer validator can fetch independently.

## Anti-adverse-selection controls

A buyer could otherwise watch a package's SLA quietly run out in public, then
buy cheap coverage the moment before (or right after) it breaches and claim
immediately. `buy_policy` and `file_claim` close that off from three angles:

- **Purchase-time risk check.** `buy_policy` runs the same public-evidence
  consensus fetch used at claim time (deterministic fields only, no LLM
  needed since there's no judgement call) and **refuses to sell coverage** if
  the package already has an open, unpatched CRITICAL/HIGH advisory. That
  isn't future risk to underwrite -- it's a loss that's already happened or
  is already in progress. It records the `ghsa_id` of whatever advisory *is*
  open (even a lower-severity one that doesn't block the sale) as the
  policy's baseline.
- **Inception + waiting period.** A claim can't be filed on a policy until
  `WAITING_PERIOD_DAYS` (7) have passed since it was bought, so a policy can't
  be purchased and cashed out in a single round trip even on a clean package.
- **Enforceable pricing floor.** `MIN_PREMIUM_BPS_PER_30D` sets a minimum
  premium-to-coverage rate (3% per 30 days by default) so coverage can't be
  bought for a token premium regardless of the package's risk state.
- **Package-specific settlement verification.** A GitHub Security Advisory's
  `vulnerabilities[]` array can list several affected packages (sibling
  packages, unrelated packages that share a name across ecosystems, etc.).
  Both the purchase-time check and claim adjudication only consider
  `vulnerabilities[]` entries whose own `package.ecosystem`/`package.name`
  are an *exact* match for the insured package -- an advisory that doesn't
  actually name that exact package (even if GitHub's `affects` filter
  returned it) is skipped entirely, and can neither block a purchase nor
  trigger a payout. Settlement additionally refuses to pay out a "breach"
  verdict that carries no such package-matched advisory id.
- **Full pre-existing-advisory baseline.** The purchase-time check records
  *every* currently-open advisory id for the exact package (any severity),
  not only the single worst one. If a lower-severity advisory that was open
  at purchase later escalates -- even one that wasn't the "worst" open
  advisory at the time -- settlement still recognizes and excludes it as
  pre-existing.

## How it works

```
1. Underwriter   → stakes GEN into a per-package pool (mints proportional shares).
2. Policyholder  → pays a premium to insure a coverage amount for N days on
                   a specific package (e.g. "PyPI/django"), subject to the
                   purchase-time risk check and pricing floor above.
3. Claim filed   → after the waiting period, GenLayer validators each fetch:
                       • https://api.github.com/advisories?ecosystem=<eco>&affects=<pkg>
                   Code deterministically reduces the raw advisory list to ONE
                   fact set: the highest-severity advisory with NO patched version
                   yet, and how many days it's been open. Withdrawn advisories are
                   ignored; patched ones don't count.
                   An LLM is grounded with those facts and assigns an SLA status.
                   Validators must agree on the status (the bounded decision field).
4. Settlement    → if status == "breach" AND the advisory isn't the one already
                   open at purchase: coverage paid from pool to holder.
                   If "watch" or "clear" or the advisory is pre-existing: claim
                   denied, policy stays in force until expiry so the holder can
                   re-file later.
```

What needs GenLayer is the **judgement** ("has the SLA actually been breached, once
you look at the real advisory record?") — a single deterministic API field isn't
enough once you have to reduce a list of advisories (mixed severities, some
patched, some withdrawn, some overlapping) to one fact set, and a centralized
insurer adjudicating its own payouts is a conflict of interest. Validators
independently re-fetch the public evidence and vote on a single bounded field;
payouts are deterministic code that runs only after consensus.

Underwriter economics use a share model (mirroring GenLayer's own staking):
premiums increase the stake-per-share, payouts decrease it. Underwriters carry the
risk and earn the yield.

---

## Tech stack

**Intelligent Contract** (Python on GenLayer GenVM)
- Pinned runner: `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`
- `gl.vm.run_nondet_unsafe(leader_fn, validator_fn)` for adjudication
- `gl.nondet.web.get` for public GitHub Advisory Database evidence
- `gl.nondet.exec_prompt(..., response_format="json")` grounded with code-verified facts
- `gl.get_contract_at(holder).emit_transfer(value=u256(amount), on="finalized")` for payouts

**Deployment + scripting** (Node)
- [`genlayer-js`](https://github.com/genlayerlabs/genlayer-js) `1.1.8` — `createClient`, `createAccount`, `deployContract`, `writeContract`, `readContract`
- `studionet` chain config (GenLayer Studio)

**Frontend**
- Vite + React 18 + TypeScript (strict)
- Tailwind v3, dark "security terminal" theme (distinct from a hand-drawn look)
- [Privy](https://privy.io) wallet connect (email + injected wallet)
- `genlayer-js` for reads (chain-only client) and writes (Privy EIP-1193 provider)

**Testing**
- `genvm-linter` for static contract validation
- `genlayer-test` direct-mode unit tests with `mock_web` / `mock_llm`

---

## Repository

```
contracts/         Intelligent Contract (patch_guard.py)
deploy/             genlayer-js deploy + seed scripts (GenLayer Studio)
tests/direct/       Fast in-memory tests (genlayer-test, no server needed)
frontend/           Vite + React + Tailwind dapp
gltest.config.yaml  gltest configuration (default: studionet)
```

---

## Develop

### Contract

```bash
# Python toolchain (3.12)
python -m venv .venv && . .venv/bin/activate
pip install genlayer-test genvm-linter   # or whatever your GenLayer SDK install provides
genvm-lint check contracts/patch_guard.py     # static validation
python -m pytest tests/direct/ -q              # in-memory tests
```

### Deploy / seed

```bash
genlayer up              # starts GenLayer Studio locally (Docker)
cp .env.example .env      # fill in ACCOUNT_PRIVATE_KEY (a Studio account -- `genlayer accounts`)
cd deploy
npm install
node deploy.mjs    # prints the deployed contract address -> paste into root .env as CONTRACT_ADDRESS
node seed.mjs      # underwrite + insure 5 real packages
```

**Currently deployed on GenLayer Studio at:**
`0x1862909bdff2bC0667eF9B799Af5f0b5A25744F8`
(already filled into `.env.example` / `frontend/.env.example` as `CONTRACT_ADDRESS` /
`VITE_CONTRACT_ADDRESS` -- copy to `.env` to use it directly instead of redeploying.)

> **Before running `seed.mjs`**, check that each package is currently clean (no
> open CRITICAL/HIGH advisory), since `buy_policy` now rejects the purchase
> otherwise -- that check is the point, not an obstacle to work around:
> ```bash
> curl "https://api.github.com/advisories?ecosystem=PyPI&affects=django&per_page=10"
> ```
> `seed.mjs` no longer files a claim immediately after buying: a policy has a
> 7-day waiting period from purchase before `file_claim` can be called on it at
> all, and any advisory that was already open at purchase is excluded from that
> policy's payout even if it later escalates in severity. To demo a real
> payout, wait for the waiting period to elapse, confirm a *new* unpatched
> CRITICAL/HIGH advisory has appeared for one of the seeded packages, then call
> `file_claim` for it from the frontend (or via `client.writeContract`, the
> same way `seed.mjs` calls `buy_policy`).

### Frontend

```bash
cd frontend
cp .env.example .env    # VITE_PRIVY_APP_ID + VITE_CONTRACT_ADDRESS
npm install
npm run dev        # local dev server
npm run build       # production build into dist/
```

---

## Cloudflare Pages deploy

| Setting          | Value              |
|------------------|--------------------|
| Root directory   | `frontend`         |
| Build command    | `npm run build`    |
| Output directory | `dist`             |
| `NODE_VERSION`   | `20`               |
| Env vars         | `VITE_PRIVY_APP_ID`, `VITE_CONTRACT_ADDRESS` |

---

## Security & honesty notes

- Secrets live only in `.env` files (git-ignored). Never commit private keys.
- Public GitHub Advisory Database evidence only — private advisories can't be
  validated trustlessly because each validator must independently fetch the same
  evidence.
- Payouts are emitted on `finalized` only, so consensus appeals can't strand or
  double-spend funds.
- Underwriter stake can never be withdrawn below the pool's locked coverage
  (`available_wei` invariant enforced in the contract).
- **This codebase has not been deployed or run against a live GenLayer network
  from this environment** (no network access here to test it end-to-end). The
  contract logic and direct-mode tests follow GenLayer's documented patterns
  closely, but before trusting it with real funds: run `genvm-lint`, run the test
  suite, deploy to GenLayer Studio yourself, and sanity-check the exact JSON shape
  returned by `https://api.github.com/advisories` against what `_worst_open_advisory`
  expects (GitHub's advisory API fields have changed shape before — verify
  `severity`, `published_at`, `withdrawn_at`, and `vulnerabilities[].patched_versions`
  / `first_patched_version` against current docs).

---

## Ideas to make it even more your own

- Swap the flat coverage payout for a **severity-scaled payout** (e.g. 100% for
  CRITICAL breach, 50% for HIGH breach).
- Add a **grace-period extension** underwriters can vote to grant a specific
  package before a claim can be filed.
- Track **CVSS score** instead of/alongside GitHub's severity bucket for finer
  tiers.
- Multi-package "bundle" policies (insure your whole `requirements.txt` in one
  policy).
