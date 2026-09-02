# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""PatchGuard -- trustless parametric insurance against unpatched critical
vulnerabilities in open-source packages.

Engineering teams insure a critical dependency (identified as `ecosystem/package`,
e.g. `PyPI/django`) against the risk that a CRITICAL or HIGH severity vulnerability
is publicly disclosed for it and the maintainers fail to ship a fix within the
disclosure-to-patch SLA. Underwriters stake native GEN into a per-package pool and
earn premiums. When a policyholder files a claim, GenLayer validators independently
fetch the package's public GitHub Security Advisory record, ground an LLM with
deterministic facts (severity, days since disclosure, whether a patched version has
shipped), and reach consensus on a single bounded decision field: an SLA status of
"clear", "watch", or "breach". If the consensus verdict is "breach", the contract
pays the coverage amount from the pool to the policyholder.

This is a different risk than dependency abandonment: a package can be extremely
active and still leave a critical CVE unpatched for months (or a maintainer can
patch quickly and the policy simply pays nothing). The subjective, evidence-based
judgement ("has the SLA been breached?") is the part that genuinely needs GenLayer:
it cannot be reduced to a single deterministic API field once real advisory data
(multiple vulnerabilities, mixed patch status, withdrawn records) is involved, and a
centralized insurer adjudicating its own payouts is a conflict of interest.
Everything that moves money is deterministic and runs only after consensus.

Underwriter economics use a share model (mirroring GenLayer's own staking): premiums
increase the stake-per-share, payouts decrease it. Underwriters carry the risk and
earn the yield.
"""

from genlayer import *

import json
import re
import typing
from dataclasses import dataclass
from datetime import datetime, timezone

# --- Error classification (compared by validators to decide agreement) --------
ERROR_EXPECTED = "[EXPECTED]"    # business-logic error, deterministic, must match
ERROR_EXTERNAL = "[EXTERNAL]"    # external 4xx, deterministic, must match
ERROR_TRANSIENT = "[TRANSIENT]"  # network/5xx, non-deterministic, both => agree
ERROR_LLM = "[LLM_ERROR]"        # malformed model output, disagree to force rotation

# --- Policy lifecycle states (stored as plain strings, never enums) -----------
STATUS_ACTIVE = "ACTIVE"    # coverage in force
STATUS_PAID = "PAID"        # SLA breach adjudicated, coverage paid out
STATUS_DENIED = "DENIED"    # claim filed, SLA not breached (re-fileable)
STATUS_EXPIRED = "EXPIRED"  # coverage lapsed without payout

# --- SLA statuses (the bounded consensus decision field) -----------------------
TIER_CLEAR = "clear"    # no unpatched critical/high advisory
TIER_WATCH = "watch"    # unpatched critical/high advisory, still inside SLA window
TIER_BREACH = "breach"  # unpatched critical/high advisory, SLA window elapsed
VALID_TIERS = (TIER_CLEAR, TIER_WATCH, TIER_BREACH)

# --- SLA windows, in days since public disclosure, encoded so the judgement is
# bounded rather than open-ended. A CRITICAL advisory gets a shorter grace period
# than a HIGH one before an unpatched state counts as a breach. ------------------
SLA_DAYS_CRITICAL = 30
SLA_DAYS_HIGH = 60

MAX_FEE_BPS = 2000    # protocol fee on premiums capped at 20%
SECONDS_PER_DAY = 86400
MAX_ADVISORIES_CONSIDERED = 25

# --- Anti-adverse-selection controls -------------------------------------
# A buyer must not be able to see a package already breaching (or about to
# breach) its SLA and buy cheap, immediately-claimable coverage against it.
# These three knobs close that off from different angles:
#   1. Purchase-time risk check (see _purchase_risk_check / buy_policy) --
#      refuses to sell coverage at all while a CRITICAL/HIGH advisory is
#      already open and unpatched for the package.
#   2. WAITING_PERIOD_DAYS -- even on a clean package, a claim can't be filed
#      until this many days after purchase, so a policy can't be bought and
#      cashed out inside a single block/transaction pair.
#   3. MIN_PREMIUM_BPS_PER_30D -- a risk-based pricing floor so coverage can't
#      be bought for a token premium regardless of the state of the package.
WAITING_PERIOD_DAYS = 7
MIN_PREMIUM_BPS_PER_30D = 300  # >= 3% of coverage per 30 days of duration


@allow_storage
@dataclass
class Pool:
    package: str
    total_stake: u256    # GEN backing this package, in wei (1 GEN = 1e18 wei)
    total_shares: u256   # underwriter shares outstanding
    locked: u256         # wei reserved against active coverage
    premium_income: u256  # cumulative premiums received (informational)


@allow_storage
@dataclass
class Policy:
    holder: Address
    package: str
    coverage: u256       # payout amount if SLA breached, in wei
    premium: u256        # premium paid, in wei
    start: u256          # unix seconds
    expiry: u256         # unix seconds
    status: str
    verdict: str         # last adjudicated SLA status ("" until first claim)
    last_checked: u256   # unix seconds of last adjudication
    baseline_ghsa_ids: str  # ALL open advisory ghsa_ids (comma-joined) for the
                             # exact package at purchase time; "" if none open


def _now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _skey(package: str, addr: Address) -> str:
    """Composite key for per-(package, address) records."""
    return package + "|" + addr.as_hex


def _parse_json(text: typing.Any) -> dict:
    """Best-effort extraction of a JSON object from an LLM text response."""
    if isinstance(text, dict):
        return text
    if not isinstance(text, str):
        raise gl.vm.UserError(f"{ERROR_LLM} model returned non-text: {type(text)}")
    first = text.find("{")
    last = text.rfind("}")
    if first == -1 or last == -1 or last <= first:
        raise gl.vm.UserError(f"{ERROR_LLM} no JSON object in model output")
    blob = text[first : last + 1]
    blob = re.sub(r",(?!\s*?[\{\[\"'\w])", "", blob)  # strip trailing commas
    try:
        return json.loads(blob)
    except Exception:
        raise gl.vm.UserError(f"{ERROR_LLM} unparseable JSON from model")


def _tier_of(data: dict) -> str:
    """Reduce a model response to the single stable consensus field."""
    if not isinstance(data, dict):
        raise gl.vm.UserError(f"{ERROR_LLM} expected JSON object, got {type(data)}")
    raw = data.get("sla_status")
    if raw is None:
        for alt in ("tier", "classification", "status", "label", "result"):
            if alt in data:
                raw = data[alt]
                break
    tier = str(raw).strip().lower() if raw is not None else ""
    if tier not in VALID_TIERS:
        raise gl.vm.UserError(f"{ERROR_LLM} invalid sla_status: {raw}")
    return tier


def _days_since(iso: str, now_unix: int) -> int:
    """Whole days between an ISO-8601 timestamp and now. Missing => very large."""
    if not iso:
        return 99999
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return max(0, (now_unix - int(dt.timestamp())) // SECONDS_PER_DAY)
    except Exception:
        return 99999


# GitHub's Advisory Database only accepts a fixed enum for `ecosystem` --
# https://docs.github.com/en/rest/security-advisories/global-advisories
# User-facing package identifiers use conventional package-manager names
# (e.g. "PyPI/django"); this maps those to GitHub's exact enum value so the
# API call doesn't 422. Unrecognized ecosystems fall through as lowercase.
_GITHUB_ECOSYSTEM_MAP = {
    "pypi": "pip",
    "pip": "pip",
    "python": "pip",
    "npm": "npm",
    "node": "npm",
    "maven": "maven",
    "gradle": "maven",
    "nuget": "nuget",
    "dotnet": "nuget",
    "composer": "composer",
    "packagist": "composer",
    "php": "composer",
    "go": "go",
    "golang": "go",
    "rust": "rust",
    "cargo": "rust",
    "rubygems": "rubygems",
    "gem": "rubygems",
    "ruby": "rubygems",
    "erlang": "erlang",
    "hex": "erlang",
    "actions": "actions",
    "pub": "pub",
    "dart": "pub",
    "flutter": "pub",
    "swift": "swift",
}


def _github_ecosystem(ecosystem: str) -> str:
    return _GITHUB_ECOSYSTEM_MAP.get(ecosystem.strip().lower(), ecosystem.strip().lower())


def _is_patched(vuln: dict) -> bool:
    """A single vulnerability entry counts as patched if any fixed version is named."""
    fpv = vuln.get("first_patched_version")
    if isinstance(fpv, dict) and str(fpv.get("identifier", "")).strip():
        return True
    if isinstance(fpv, str) and fpv.strip():
        return True
    pv = vuln.get("patched_versions")
    if isinstance(pv, str) and pv.strip():
        return True
    return False


def _vuln_matches_package(vuln: dict, gh_ecosystem: str, name: str) -> bool:
    """True only if this vulnerability entry's `package` field is an EXACT match
    (ecosystem + name) for the insured package. A single GitHub Security Advisory
    can list several affected packages -- sibling packages in a monorepo,
    unrelated packages that merely share a name across ecosystems, or a family
    of related npm scopes -- each with its own, independent patch status. This
    entry is evidence about the insured package only if it names that exact
    package; it is never inferred from the advisory as a whole.
    """
    if not isinstance(vuln, dict):
        return False
    pkg = vuln.get("package")
    if not isinstance(pkg, dict):
        return False
    v_eco = str(pkg.get("ecosystem", "")).strip().lower()
    v_name = str(pkg.get("name", "")).strip().lower()
    return v_eco == gh_ecosystem.strip().lower() and v_name == name.strip().lower()


def _worst_open_advisory(advisories: list, now: int, ecosystem: str, name: str) -> dict:
    """Deterministically reduce a raw advisory list to the fact set that matters,
    scoped EXACTLY to the insured `ecosystem/name` package -- never to the
    advisory as a whole.

    For each advisory, only `vulnerabilities[]` entries whose own `package`
    field exactly matches the insured ecosystem+name are considered. An
    advisory with no such entry doesn't actually affect this exact package
    (e.g. a fuzzy hit from the API's `affects` filter, or an advisory that
    affects a sibling/related package) and is skipped entirely -- it can
    neither open nor patch anything for this policy. Patch status is judged
    only from the matching entries: the package is "open" under that advisory
    if ANY matching entry lacks a fixed version, even if other entries (for
    that package or others) are already patched.

    Withdrawn advisories are ignored. Ties among matching advisories are
    broken by earliest publish date (longest-open first).

    Returns:
      - found_open / severity / ghsa_id / days_since_disclosure: the single
        highest-severity, longest-open matching advisory (used for the SLA
        judgement -- an advisory can only breach if it's the worst active one).
      - open_ghsa_ids: EVERY currently-open (unpatched), exactly-matching
        advisory's ghsa_id, of ANY severity -- not just the worst one --
        sorted for determinism. A lower-severity advisory open today can
        escalate to critical/high later, so every open advisory at purchase
        time needs to be trackable as pre-existing, not only whichever
        happened to be worst at that moment.
    """
    gh_ecosystem = _github_ecosystem(ecosystem)
    severity_rank = {"critical": 3, "high": 2, "moderate": 1, "medium": 1, "low": 0}
    best = None
    best_rank = -1
    best_days = -1
    any_critical_or_high = False
    open_ids: set = set()
    for adv in advisories[:MAX_ADVISORIES_CONSIDERED]:
        if not isinstance(adv, dict):
            continue
        if adv.get("withdrawn_at"):
            continue
        vulns = adv.get("vulnerabilities") or []
        matching = [v for v in vulns if _vuln_matches_package(v, gh_ecosystem, name)]
        if not matching:
            continue  # doesn't actually affect the exact insured package
        sev = str(adv.get("severity", "")).strip().lower()
        rank = severity_rank.get(sev, -1)
        if rank < 0:
            continue
        # Open for THIS package iff at least one matching entry has no fix yet.
        patched = all(_is_patched(v) for v in matching)
        if rank >= 2:
            any_critical_or_high = True
        if patched:
            continue
        ghsa_id = str(adv.get("ghsa_id", ""))[:32]
        if ghsa_id:
            open_ids.add(ghsa_id)
        days_open = _days_since(str(adv.get("published_at", "")), now)
        if rank > best_rank or (rank == best_rank and days_open > best_days):
            best_rank = rank
            best_days = days_open
            best = adv
    open_ghsa_ids = ",".join(sorted(open_ids))[:1024]
    if best is None:
        return {
            "found_open": False,
            "any_critical_or_high": any_critical_or_high,
            "severity": "",
            "days_since_disclosure": 0,
            "ghsa_id": "",
            "open_ghsa_ids": open_ghsa_ids,
        }
    return {
        "found_open": True,
        "any_critical_or_high": any_critical_or_high,
        "severity": str(best.get("severity", "")).strip().lower(),
        "days_since_disclosure": best_days,
        "ghsa_id": str(best.get("ghsa_id", ""))[:32],
        "open_ghsa_ids": open_ghsa_ids,
    }


class PatchGuard(gl.Contract):
    owner: Address
    fee_wallet: Address
    fee_bps: u256
    pools: TreeMap[str, Pool]
    shares: TreeMap[str, u256]        # key: _skey(package, underwriter)
    policies: TreeMap[str, Policy]    # key: _skey(package, holder)
    package_list: DynArray[str]
    policy_keys: DynArray[str]

    def __init__(self, fee_wallet: str, fee_bps: int):
        if fee_bps < 0 or fee_bps > MAX_FEE_BPS:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} fee_bps out of range")
        self.owner = gl.message.sender_address
        self.fee_wallet = Address(fee_wallet)
        self.fee_bps = u256(fee_bps)

    # ----------------------------------------------------------- underwriting
    @gl.public.write.payable
    def underwrite(self, package: str) -> None:
        """Stake native GEN into a package's pool; receive proportional shares."""
        package = _norm_package(package)
        value = int(gl.message.value)
        if value <= 0:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} stake must be positive")

        if package not in self.pools:
            self.pools[package] = Pool(
                package=package,
                total_stake=u256(0),
                total_shares=u256(0),
                locked=u256(0),
                premium_income=u256(0),
            )
            self.package_list.append(package)
        # Fetch the storage view AFTER insertion so mutations write through.
        pool = self.pools[package]

        total_stake = int(pool.total_stake)
        total_shares = int(pool.total_shares)
        # 1:1 for the first stake; otherwise proportional to current share price.
        if total_shares == 0 or total_stake == 0:
            minted = value
        else:
            minted = (value * total_shares) // total_stake
        if minted <= 0:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} stake too small to mint shares")

        pool.total_stake = u256(total_stake + value)
        pool.total_shares = u256(total_shares + minted)

        k = _skey(package, gl.message.sender_address)
        self.shares[k] = u256(int(self.shares.get(k, u256(0))) + minted)

    @gl.public.write
    def withdraw_stake(self, package: str, share_amount: u256) -> None:
        """Burn shares and withdraw the backing GEN, never below locked capacity."""
        package = _norm_package(package)
        pool = self._require_pool(package)
        k = _skey(package, gl.message.sender_address)
        owned = int(self.shares.get(k, u256(0)))
        burn = int(share_amount)
        if burn <= 0 or burn > owned:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} invalid share amount")

        total_stake = int(pool.total_stake)
        total_shares = int(pool.total_shares)
        amount = (burn * total_stake) // total_shares
        available = total_stake - int(pool.locked)
        if amount > available:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} amount exceeds unlocked capacity")

        pool.total_stake = u256(total_stake - amount)
        pool.total_shares = u256(total_shares - burn)
        self.shares[k] = u256(owned - burn)
        self._pay(gl.message.sender_address, amount)

    # --------------------------------------------------------------- coverage
    def _purchase_risk_check(self, package: str, now: int) -> dict:
        """Nondet consensus fetch of the same public GitHub Advisory Database
        evidence used at claim time, evaluated at *purchase* time. Unlike claim
        adjudication this needs no LLM judgement -- there's no subjective call
        to make, only a deterministic fact to agree on -- so validators reach
        consensus directly on the reduced, bounded fields (found_open, severity,
        ghsa_id) rather than routing through gl.nondet.exec_prompt.
        """
        ecosystem, name = package.split("/", 1)
        api = (
            "https://api.github.com/advisories?ecosystem="
            + _github_ecosystem(ecosystem)
            + "&affects="
            + name
            + "&per_page=30&sort=published&direction=desc"
        )

        def leader_fn() -> dict:
            res = gl.nondet.web.get(api)
            if res.status == 404:
                raise gl.vm.UserError(f"{ERROR_EXTERNAL} unknown ecosystem/package")
            if res.status == 403 or res.status == 429:
                raise gl.vm.UserError(f"{ERROR_TRANSIENT} github rate limited")
            if res.status >= 500:
                raise gl.vm.UserError(f"{ERROR_TRANSIENT} github unavailable")
            if res.status != 200:
                raise gl.vm.UserError(f"{ERROR_EXTERNAL} github status {res.status}")
            advisories = json.loads(res.body.decode("utf-8"))
            if not isinstance(advisories, list):
                raise gl.vm.UserError(f"{ERROR_EXTERNAL} unexpected advisories payload")
            return _worst_open_advisory(advisories, now, ecosystem, name)

        def validator_fn(leaders_res: gl.vm.Result) -> bool:
            if not isinstance(leaders_res, gl.vm.Return):
                return self._agree_on_error(leaders_res, leader_fn)
            try:
                mine = leader_fn()
                ld = leaders_res.calldata
            except gl.vm.UserError:
                return False
            # Agree only on the bounded purchase-risk fields, never on the exact
            # day count (which can tick over a day boundary between fetches).
            return (
                mine.get("found_open") == ld.get("found_open")
                and mine.get("severity") == ld.get("severity")
                and mine.get("ghsa_id") == ld.get("ghsa_id")
                and mine.get("open_ghsa_ids") == ld.get("open_ghsa_ids")
            )

        return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

    @gl.public.write.payable
    def buy_policy(self, package: str, coverage: u256, duration_days: u256) -> None:
        """Pay a premium to insure `coverage` wei against an unpatched-CVE SLA
        breach for `package`."""
        package = _norm_package(package)
        premium = int(gl.message.value)
        cover = int(coverage)
        days = int(duration_days)
        if premium <= 0:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} premium required")
        if cover <= 0:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} coverage must be positive")
        if days <= 0:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} duration must be positive")

        pool = self._require_pool(package)
        available = int(pool.total_stake) - int(pool.locked)
        if cover > available:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} insufficient pool capacity")

        key = _skey(package, gl.message.sender_address)
        existing = self.policies.get(key)
        if existing is not None and existing.status == STATUS_ACTIVE:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} active policy already exists")

        # --- enforceable pricing floor: coverage can't be bought for a token
        # premium regardless of package risk state (scales with cover & term).
        min_premium = (cover * MIN_PREMIUM_BPS_PER_30D * days) // (10000 * 30)
        if premium < min_premium:
            raise gl.vm.UserError(
                f"{ERROR_EXPECTED} premium below minimum risk-based rate"
            )

        # --- purchase-time risk check (adverse-selection gate): refuse to sell
        # coverage while the package already has a known, currently-open
        # CRITICAL/HIGH advisory -- that isn't future risk, it's a loss that
        # has already happened or is already in progress. Lower-severity open
        # advisories don't block the sale (they can't trigger a breach), but
        # their ghsa_id is still recorded below so a later severity escalation
        # of that *same* advisory is still treated as pre-existing at claim time.
        now = _now()
        facts = self._purchase_risk_check(package, now)
        if facts.get("found_open") and facts.get("severity") in ("critical", "high"):
            raise gl.vm.UserError(
                f"{ERROR_EXPECTED} package has an open {facts.get('severity')} "
                f"advisory ({facts.get('ghsa_id', '')}) -- not insurable until patched"
            )
        baseline_ghsa_ids = str(facts.get("open_ghsa_ids", ""))[:1024]

        # Protocol fee on the premium; remainder accrues to underwriters by raising
        # the pool's stake-per-share.
        fee = (premium * int(self.fee_bps)) // 10000
        to_pool = premium - fee
        pool.total_stake = u256(int(pool.total_stake) + to_pool)
        pool.locked = u256(int(pool.locked) + cover)
        pool.premium_income = u256(int(pool.premium_income) + premium)

        self.policies[key] = Policy(
            holder=gl.message.sender_address,
            package=package,
            coverage=u256(cover),
            premium=u256(premium),
            start=u256(now),
            expiry=u256(now + days * SECONDS_PER_DAY),
            status=STATUS_ACTIVE,
            verdict="",
            last_checked=u256(0),
            baseline_ghsa_ids=baseline_ghsa_ids,
        )
        if existing is None:
            self.policy_keys.append(key)

        if fee > 0:
            self._pay(self.fee_wallet, fee)

    @gl.public.write
    def expire_policy(self, package: str, holder: str) -> None:
        """Free locked capacity for a policy whose term has ended without payout."""
        package = _norm_package(package)
        key = _skey(package, Address(holder))
        policy = self._require_policy(key)
        if policy.status != STATUS_ACTIVE:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} policy not active")
        if _now() < int(policy.expiry):
            raise gl.vm.UserError(f"{ERROR_EXPECTED} policy not yet expired")
        pool = self._require_pool(package)
        pool.locked = u256(int(pool.locked) - int(policy.coverage))
        policy.status = STATUS_EXPIRED

    # ----------------------------------------------------- claim adjudication
    @gl.public.write
    def file_claim(self, package: str) -> None:
        """Adjudicate SLA status from public GitHub Security Advisory evidence and
        settle if breached.

        Validators each fetch the same public GitHub Advisory Database endpoint,
        deterministically reduce it to the single worst open (unpatched) advisory
        and its age, ground the LLM with those facts, and agree only on the bounded
        `sla_status` decision field. Funds move only after consensus, in
        deterministic code.
        """
        package = _norm_package(package)
        key = _skey(package, gl.message.sender_address)
        policy = self._require_policy(key)
        if policy.status != STATUS_ACTIVE:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} no active policy")
        now = _now()
        if now > int(policy.expiry):
            raise gl.vm.UserError(f"{ERROR_EXPECTED} policy expired")
        if now < int(policy.start) + WAITING_PERIOD_DAYS * SECONDS_PER_DAY:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} waiting period not yet elapsed")

        ecosystem, name = package.split("/", 1)
        api = (
            "https://api.github.com/advisories?ecosystem="
            + _github_ecosystem(ecosystem)
            + "&affects="
            + name
            + "&per_page=30&sort=published&direction=desc"
        )

        def leader_fn() -> dict:
            res = gl.nondet.web.get(api)
            if res.status == 404:
                raise gl.vm.UserError(f"{ERROR_EXTERNAL} unknown ecosystem/package")
            if res.status == 403 or res.status == 429:
                raise gl.vm.UserError(f"{ERROR_TRANSIENT} github rate limited")
            if res.status >= 500:
                raise gl.vm.UserError(f"{ERROR_TRANSIENT} github unavailable")
            if res.status != 200:
                raise gl.vm.UserError(f"{ERROR_EXTERNAL} github status {res.status}")
            advisories = json.loads(res.body.decode("utf-8"))
            if not isinstance(advisories, list):
                raise gl.vm.UserError(f"{ERROR_EXTERNAL} unexpected advisories payload")

            facts = _worst_open_advisory(advisories, now, ecosystem, name)
            sla_days = (
                SLA_DAYS_CRITICAL if facts["severity"] == "critical" else SLA_DAYS_HIGH
            )
            facts["sla_days"] = sla_days

            prompt = (
                "You classify open-source vulnerability-SLA compliance for an "
                "insurance payout decision. Use the VERIFIED FACTS below as ground "
                "truth. Do not override them with guesses.\n\n"
                f"Package: {package}\n"
                f"Verified facts: {json.dumps(facts)}\n\n"
                "Apply these rules in order:\n"
                '- "breach" if found_open is true AND severity is "critical" or '
                '"high" AND days_since_disclosure > sla_days.\n'
                '- "watch" if found_open is true AND severity is "critical" or '
                '"high" (but still inside the SLA window), OR any_critical_or_high '
                "is true without a currently-open unpatched one.\n"
                '- "clear" otherwise.\n\n'
                'Respond with ONLY a JSON object, no prose:\n'
                '{"sla_status": "clear|watch|breach", '
                '"reasoning": "<one sentence>"}'
            )
            res_llm = gl.nondet.exec_prompt(prompt, response_format="json")
            parsed = _parse_json(res_llm)
            tier = _tier_of(parsed)
            return {
                "sla_status": tier,
                "severity": facts["severity"],
                "days_since_disclosure": facts["days_since_disclosure"],
                "ghsa_id": facts["ghsa_id"],
                "reasoning": str(parsed.get("reasoning", ""))[:300],
            }

        def validator_fn(leaders_res: gl.vm.Result) -> bool:
            if not isinstance(leaders_res, gl.vm.Return):
                return self._agree_on_error(leaders_res, leader_fn)
            try:
                mine = leader_fn()
                my_tier = mine["sla_status"]
                ld_tier = _tier_of(leaders_res.calldata)
            except gl.vm.UserError:
                return False
            # Agree only on the bounded decision field.
            return my_tier == ld_tier

        result = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

        # --- deterministic settlement (post-consensus) ------------------------
        tier = _tier_of(result)
        policy.verdict = tier
        policy.last_checked = u256(now)

        if tier == TIER_BREACH:
            claim_ghsa_id = str(result.get("ghsa_id", ""))[:32]
            if not claim_ghsa_id:
                # Consensus reached "breach" but the returned fact set carries no
                # package-specific advisory id to back it (e.g. a malformed or
                # hallucinated model response inconsistent with its own grounding
                # facts) -- never move funds without a verified, exact-matched
                # advisory behind the payout.
                policy.status = STATUS_ACTIVE
                policy.verdict = "unverified"
            else:
                baseline_ids = (
                    set(policy.baseline_ghsa_ids.split(",")) if policy.baseline_ghsa_ids else set()
                )
                if claim_ghsa_id in baseline_ids:
                    # Exact same advisory (package-specific ghsa_id match) that was
                    # already open when this policy was bought -- e.g. it later
                    # escalated from moderate/low to critical/high. That's a known
                    # pre-existing condition at inception, not new insurable risk,
                    # so it's excluded from settlement. Coverage stays in force for
                    # any genuinely new advisory that appears before expiry.
                    policy.status = STATUS_ACTIVE
                    policy.verdict = "excluded"
                else:
                    pool = self._require_pool(package)
                    cover = int(policy.coverage)
                    pool.total_stake = u256(int(pool.total_stake) - cover)
                    pool.locked = u256(int(pool.locked) - cover)
                    policy.status = STATUS_PAID
                    self._pay(policy.holder, cover)
        else:
            # Claim denied for now; coverage stays in force until expiry so the
            # holder can re-file if a later advisory goes unpatched too long.
            policy.status = STATUS_ACTIVE

    # ------------------------------------------------------------------- views
    @gl.public.view
    def get_pool(self, package: str) -> dict:
        return self._pool_dict(self._require_pool(_norm_package(package)))

    @gl.public.view
    def get_pools(self) -> list:
        return [self._pool_dict(self.pools[p]) for p in self.package_list]

    @gl.public.view
    def get_policy(self, package: str, holder: str) -> dict:
        key = _skey(_norm_package(package), Address(holder))
        return self._policy_dict(self._require_policy(key))

    @gl.public.view
    def get_shares(self, package: str, underwriter: str) -> str:
        k = _skey(_norm_package(package), Address(underwriter))
        return str(int(self.shares.get(k, u256(0))))

    @gl.public.view
    def get_config(self) -> dict:
        return {
            "owner": self.owner.as_hex,
            "fee_wallet": self.fee_wallet.as_hex,
            "fee_bps": int(self.fee_bps),
            "sla_days_critical": SLA_DAYS_CRITICAL,
            "sla_days_high": SLA_DAYS_HIGH,
            "waiting_period_days": WAITING_PERIOD_DAYS,
            "min_premium_bps_per_30d": MIN_PREMIUM_BPS_PER_30D,
        }

    @gl.public.view
    def get_stats(self) -> dict:
        total_staked = 0
        total_locked = 0
        for p in self.package_list:
            pool = self.pools[p]
            total_staked += int(pool.total_stake)
            total_locked += int(pool.locked)
        active = 0
        paid = 0
        for key in self.policy_keys:
            pol = self.policies[key]
            if pol.status == STATUS_ACTIVE:
                active += 1
            elif pol.status == STATUS_PAID:
                paid += 1
        return {
            "pools": len(self.package_list),
            "policies": len(self.policy_keys),
            "active_policies": active,
            "paid_claims": paid,
            "total_staked_wei": str(total_staked),
            "total_locked_wei": str(total_locked),
        }

    # --------------------------------------------------------------- internals
    def _require_pool(self, package: str) -> Pool:
        if package not in self.pools:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} pool not found")
        return self.pools[package]

    def _require_policy(self, key: str) -> Policy:
        if key not in self.policies:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} policy not found")
        return self.policies[key]

    def _pay(self, to: Address, amount: int) -> None:
        if amount > 0:
            gl.get_contract_at(to).emit_transfer(value=u256(amount), on="finalized")

    def _agree_on_error(self, leaders_res: gl.vm.Result, leader_fn) -> bool:
        leader_msg = getattr(leaders_res, "message", "") or ""
        try:
            leader_fn()
            return False  # leader errored, validator succeeded -> disagree
        except gl.vm.UserError as e:
            validator_msg = getattr(e, "message", "") or str(e)
            if validator_msg.startswith(ERROR_EXPECTED) or validator_msg.startswith(
                ERROR_EXTERNAL
            ):
                return validator_msg == leader_msg
            if validator_msg.startswith(ERROR_TRANSIENT) and leader_msg.startswith(
                ERROR_TRANSIENT
            ):
                return True
            return False
        except Exception:
            return False

    def _pool_dict(self, p: Pool) -> dict:
        total_stake = int(p.total_stake)
        total_shares = int(p.total_shares)
        return {
            "package": p.package,
            "total_stake_wei": str(total_stake),
            "total_shares": str(total_shares),
            "locked_wei": str(int(p.locked)),
            "available_wei": str(total_stake - int(p.locked)),
            "premium_income_wei": str(int(p.premium_income)),
        }

    def _policy_dict(self, a: Policy) -> dict:
        return {
            "holder": a.holder.as_hex,
            "package": a.package,
            "coverage_wei": str(int(a.coverage)),
            "premium_wei": str(int(a.premium)),
            "start": int(a.start),
            "expiry": int(a.expiry),
            "status": a.status,
            "verdict": a.verdict,
            "last_checked": int(a.last_checked),
            "baseline_ghsa_ids": a.baseline_ghsa_ids,
        }


def _norm_package(package: str) -> str:
    """Normalize a package identifier to `ecosystem/name`, rejecting malformed input."""
    if not isinstance(package, str):
        raise gl.vm.UserError(f"{ERROR_EXPECTED} package must be a string")
    r = package.strip().strip("/")
    parts = r.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise gl.vm.UserError(f"{ERROR_EXPECTED} package must be 'ecosystem/name'")
    return parts[0] + "/" + parts[1]
