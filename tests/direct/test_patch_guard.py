"""Direct-mode tests for the PatchGuard parametric insurance contract."""

from conftest import (
    CONTRACT, FEE_WALLET, FEE_BPS, GEN,
    mock_no_advisories, mock_open_critical, mock_open_moderate,
    mock_patched_critical, mock_verdict, mock_advisories,
    mock_wrong_package_critical, mock_two_open_advisories,
    _advisory, addr_hex,
)

PACKAGE = "PyPI/example"
T0 = "2026-06-01T00:00:00Z"
# file_claim requires WAITING_PERIOD_DAYS (7) to have elapsed since purchase.
POST_WAITING_PERIOD = "2026-06-10T00:00:00Z"


def _deploy(direct_deploy):
    return direct_deploy(CONTRACT, FEE_WALLET, FEE_BPS)


def _underwrite(direct_vm, c, sender, amount=100 * GEN):
    direct_vm.sender = sender
    direct_vm.value = amount
    c.underwrite(PACKAGE)


def _buy(direct_vm, c, sender, coverage, premium, days=30):
    """Buy a policy against a package with no open advisories (the default
    'clean' purchase-time state used by tests that aren't specifically
    exercising the purchase-time risk gate)."""
    mock_no_advisories(direct_vm)
    direct_vm.sender = sender
    direct_vm.value = premium
    c.buy_policy(PACKAGE, coverage, days)


# ---------------------------------------------------------------- underwriting
def test_underwrite_mints_first_shares_one_to_one(direct_vm, direct_deploy, direct_bob):
    c = _deploy(direct_deploy)
    direct_vm.sender = direct_bob
    direct_vm.value = 100 * GEN
    c.underwrite(PACKAGE)

    pool = c.get_pool(PACKAGE)
    assert pool["total_stake_wei"] == str(100 * GEN)
    assert pool["total_shares"] == str(100 * GEN)
    assert pool["available_wei"] == str(100 * GEN)
    assert c.get_shares(PACKAGE, addr_hex(direct_bob)) == str(100 * GEN)


def test_underwrite_rejects_zero_value(direct_vm, direct_deploy, direct_bob):
    c = _deploy(direct_deploy)
    direct_vm.sender = direct_bob
    direct_vm.value = 0
    with direct_vm.expect_revert("stake must be positive"):
        c.underwrite(PACKAGE)


# ------------------------------------------------------------------- coverage
def test_buy_policy_locks_capacity_and_accrues_premium(direct_vm, direct_deploy,
                                                        direct_alice, direct_bob):
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)
    _buy(direct_vm, c, direct_alice, 10 * GEN, 1 * GEN, 30)

    pool = c.get_pool(PACKAGE)
    expected_stake = 100 * GEN + (1 * GEN - (1 * GEN * FEE_BPS) // 10000)
    assert pool["locked_wei"] == str(10 * GEN)
    assert pool["total_stake_wei"] == str(expected_stake)
    assert pool["available_wei"] == str(expected_stake - 10 * GEN)

    pol = c.get_policy(PACKAGE, addr_hex(direct_alice))
    assert pol["status"] == "ACTIVE"
    assert pol["coverage_wei"] == str(10 * GEN)
    assert pol["baseline_ghsa_ids"] == ""  # no open advisory at purchase


def test_buy_policy_rejects_over_capacity(direct_vm, direct_deploy,
                                          direct_alice, direct_bob):
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 5 * GEN)

    direct_vm.sender = direct_alice
    direct_vm.value = 1 * GEN
    with direct_vm.expect_revert("insufficient pool capacity"):
        c.buy_policy(PACKAGE, 10 * GEN, 30)


def test_buy_policy_rejects_premium_below_minimum_rate(direct_vm, direct_deploy,
                                                        direct_alice, direct_bob):
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)

    mock_no_advisories(direct_vm)
    direct_vm.sender = direct_alice
    # 90 GEN coverage for 30 days needs >= 2.7 GEN premium (3% / 30d floor);
    # 1 GEN is a token premium relative to that much coverage.
    direct_vm.value = 1 * GEN
    with direct_vm.expect_revert("premium below minimum risk-based rate"):
        c.buy_policy(PACKAGE, 90 * GEN, 30)


def test_buy_policy_rejects_when_open_critical_advisory_exists(direct_vm, direct_deploy,
                                                                direct_alice, direct_bob):
    """Can't buy cheap, immediately-claimable coverage against a package that
    already has a known unpatched CRITICAL advisory -- adverse selection."""
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)

    mock_open_critical(direct_vm, days_ago_published=45)  # already past SLA
    direct_vm.sender = direct_alice
    direct_vm.value = 1 * GEN
    with direct_vm.expect_revert("not insurable until patched"):
        c.buy_policy(PACKAGE, 10 * GEN, 30)

    # No policy should have been created and no capacity locked.
    pool = c.get_pool(PACKAGE)
    assert pool["locked_wei"] == "0"


def test_buy_policy_allows_open_moderate_advisory(direct_vm, direct_deploy,
                                                   direct_alice, direct_bob):
    """A currently-open advisory that isn't CRITICAL/HIGH can't trigger a
    breach, so it shouldn't block the purchase."""
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)

    mock_open_moderate(direct_vm)
    direct_vm.sender = direct_alice
    direct_vm.value = 1 * GEN
    c.buy_policy(PACKAGE, 10 * GEN, 30)

    pol = c.get_policy(PACKAGE, addr_hex(direct_alice))
    assert pol["status"] == "ACTIVE"
    assert pol["baseline_ghsa_ids"] == "GHSA-test-0000"


def test_buy_policy_ignores_advisory_for_a_different_package(direct_vm, direct_deploy,
                                                              direct_alice, direct_bob):
    """An advisory returned by the API but whose vulnerabilities[] entries name
    a DIFFERENT package must never block a purchase or seed the baseline for
    PACKAGE -- it isn't evidence about the exact insured package."""
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)

    mock_wrong_package_critical(direct_vm, days_ago_published=45)
    direct_vm.sender = direct_alice
    direct_vm.value = 1 * GEN
    c.buy_policy(PACKAGE, 10 * GEN, 30)  # must NOT revert

    pol = c.get_policy(PACKAGE, addr_hex(direct_alice))
    assert pol["status"] == "ACTIVE"
    assert pol["baseline_ghsa_ids"] == ""  # the wrong-package advisory isn't recorded


def test_claim_ignores_breach_for_a_different_package(direct_vm, direct_deploy,
                                                       direct_alice, direct_bob):
    """Even if the LLM is (incorrectly) told to return 'breach', a claim must
    not pay out based on an advisory that doesn't name the exact insured
    package -- deterministic settlement re-derives ghsa_id from a properly
    package-scoped reduction, and refuses to settle a 'breach' with no
    package-matched advisory id behind it."""
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)
    _buy(direct_vm, c, direct_alice, 10 * GEN, 1 * GEN, 30)

    direct_vm.warp(POST_WAITING_PERIOD)

    mock_wrong_package_critical(direct_vm, days_ago_published=45)
    mock_verdict(direct_vm, "breach")  # forced/incorrect model output

    direct_vm.sender = direct_alice
    c.file_claim(PACKAGE)

    pol = c.get_policy(PACKAGE, addr_hex(direct_alice))
    assert pol["status"] == "ACTIVE"       # never paid out
    assert pol["verdict"] == "unverified"

    pool = c.get_pool(PACKAGE)
    assert pool["locked_wei"] == str(10 * GEN)  # nothing paid out


def test_claim_excludes_advisory_open_at_purchase_time(direct_vm, direct_deploy,
                                                        direct_alice, direct_bob):
    """A moderate advisory that was already open (and recorded in the policy's
    baseline) at purchase time later escalates to CRITICAL. Even though the
    consensus verdict is 'breach', settlement must exclude it as a
    pre-existing condition rather than pay out."""
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)

    mock_open_moderate(direct_vm)
    direct_vm.sender = direct_alice
    direct_vm.value = 1 * GEN
    c.buy_policy(PACKAGE, 10 * GEN, 30)

    pol_before = c.get_policy(PACKAGE, addr_hex(direct_alice))
    assert pol_before["baseline_ghsa_ids"] == "GHSA-test-0000"

    direct_vm.warp(POST_WAITING_PERIOD)

    # Same advisory (same ghsa_id), now escalated to CRITICAL and past SLA.
    mock_open_critical(direct_vm, days_ago_published=45)
    mock_verdict(direct_vm, "breach")

    direct_vm.sender = direct_alice
    c.file_claim(PACKAGE)

    pol = c.get_policy(PACKAGE, addr_hex(direct_alice))
    assert pol["status"] == "ACTIVE"       # not paid out
    assert pol["verdict"] == "excluded"

    pool = c.get_pool(PACKAGE)
    assert pool["locked_wei"] == str(10 * GEN)  # coverage never released


def test_claim_excludes_any_of_multiple_advisories_open_at_purchase(direct_vm, direct_deploy,
                                                                     direct_alice, direct_bob):
    """Two independent advisories (different ghsa_ids) are open at purchase
    time. The one that later escalates and breaches is NOT the 'worst' one
    that a single-id baseline would have captured -- proving every open
    advisory at purchase, not just the worst, is tracked as pre-existing."""
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)

    # At purchase: GHSA-test-aaaa (low) and GHSA-test-bbbb (moderate) both open.
    # The worst-open reduction picks bbbb (higher severity) as "best", but
    # BOTH ids must land in the baseline.
    mock_two_open_advisories(direct_vm, ghsa_id_a="GHSA-test-aaaa", ghsa_id_b="GHSA-test-bbbb")
    direct_vm.sender = direct_alice
    direct_vm.value = 1 * GEN
    c.buy_policy(PACKAGE, 10 * GEN, 30)

    pol_before = c.get_policy(PACKAGE, addr_hex(direct_alice))
    baseline_ids = set(pol_before["baseline_ghsa_ids"].split(","))
    assert baseline_ids == {"GHSA-test-aaaa", "GHSA-test-bbbb"}

    direct_vm.warp(POST_WAITING_PERIOD)

    # GHSA-test-aaaa -- the one that was NOT "best" at purchase -- escalates to
    # CRITICAL and breaches. A single-id baseline (only tracking bbbb) would
    # have wrongly paid this out; the full-set baseline must still exclude it.
    mock_advisories(direct_vm, [
        _advisory(severity="critical", published_at="2026-04-18T00:00:00Z",
                  patched=False, ghsa_id="GHSA-test-aaaa"),
    ])
    mock_verdict(direct_vm, "breach")

    direct_vm.sender = direct_alice
    c.file_claim(PACKAGE)

    pol = c.get_policy(PACKAGE, addr_hex(direct_alice))
    assert pol["status"] == "ACTIVE"
    assert pol["verdict"] == "excluded"

    pool = c.get_pool(PACKAGE)
    assert pool["locked_wei"] == str(10 * GEN)


# -------------------------------------------------------- claim adjudication
def test_claim_rejects_within_waiting_period(direct_vm, direct_deploy,
                                             direct_alice, direct_bob):
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)
    _buy(direct_vm, c, direct_alice, 10 * GEN, 1 * GEN, 30)

    mock_open_critical(direct_vm, days_ago_published=45)
    mock_verdict(direct_vm, "breach")

    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("waiting period not yet elapsed"):
        c.file_claim(PACKAGE)


def test_claim_breach_pays_out_and_reduces_pool(direct_vm, direct_deploy,
                                                direct_alice, direct_bob):
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)
    _buy(direct_vm, c, direct_alice, 10 * GEN, 1 * GEN, 30)

    direct_vm.warp(POST_WAITING_PERIOD)

    # Unpatched CRITICAL advisory published well past the 30-day SLA window.
    mock_open_critical(direct_vm, days_ago_published=45)
    mock_verdict(direct_vm, "breach")

    direct_vm.sender = direct_alice
    c.file_claim(PACKAGE)

    pol = c.get_policy(PACKAGE, addr_hex(direct_alice))
    assert pol["status"] == "PAID"
    assert pol["verdict"] == "breach"

    pool = c.get_pool(PACKAGE)
    assert pool["locked_wei"] == "0"


def test_claim_denied_when_patched(direct_vm, direct_deploy,
                                   direct_alice, direct_bob):
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)
    _buy(direct_vm, c, direct_alice, 10 * GEN, 1 * GEN, 30)

    direct_vm.warp(POST_WAITING_PERIOD)

    mock_patched_critical(direct_vm)
    mock_verdict(direct_vm, "clear")

    direct_vm.sender = direct_alice
    c.file_claim(PACKAGE)

    pol = c.get_policy(PACKAGE, addr_hex(direct_alice))
    assert pol["status"] == "ACTIVE"
    assert pol["verdict"] == "clear"

    pool = c.get_pool(PACKAGE)
    assert pool["locked_wei"] == str(10 * GEN)  # coverage stays locked, still in force


def test_claim_watch_when_inside_sla_window(direct_vm, direct_deploy,
                                            direct_alice, direct_bob):
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)
    _buy(direct_vm, c, direct_alice, 10 * GEN, 1 * GEN, 30)

    direct_vm.warp(POST_WAITING_PERIOD)

    # Unpatched CRITICAL advisory, but only 5 days old -- still inside the 30-day SLA.
    mock_open_critical(direct_vm, days_ago_published=5)
    mock_verdict(direct_vm, "watch")

    direct_vm.sender = direct_alice
    c.file_claim(PACKAGE)

    pol = c.get_policy(PACKAGE, addr_hex(direct_alice))
    assert pol["status"] == "ACTIVE"
    assert pol["verdict"] == "watch"


def test_claim_rejects_without_active_policy(direct_vm, direct_deploy, direct_alice):
    c = _deploy(direct_deploy)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("no active policy"):
        c.file_claim(PACKAGE)


def test_claim_no_advisories_stays_clear(direct_vm, direct_deploy,
                                         direct_alice, direct_bob):
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)
    _buy(direct_vm, c, direct_alice, 10 * GEN, 1 * GEN, 30)

    direct_vm.warp(POST_WAITING_PERIOD)

    mock_no_advisories(direct_vm)
    mock_verdict(direct_vm, "clear")

    direct_vm.sender = direct_alice
    c.file_claim(PACKAGE)

    pol = c.get_policy(PACKAGE, addr_hex(direct_alice))
    assert pol["verdict"] == "clear"
    assert pol["status"] == "ACTIVE"


# ------------------------------------------------------------------ withdrawal
def test_withdraw_stake_respects_locked_capacity(direct_vm, direct_deploy,
                                                 direct_alice, direct_bob):
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)
    # 90 GEN coverage / 30 days needs >= 2.7 GEN premium under the pricing floor.
    _buy(direct_vm, c, direct_alice, 90 * GEN, 3 * GEN, 30)

    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("amount exceeds unlocked capacity"):
        c.withdraw_stake(PACKAGE, 50 * GEN)


# --------------------------------------------------------------------- expiry
def test_expire_policy_rejects_before_term_ends(direct_vm, direct_deploy,
                                                direct_alice, direct_bob):
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)
    _buy(direct_vm, c, direct_alice, 10 * GEN, 1 * GEN, 30)

    # Still well within the 30-day term -- expiry must be rejected.
    direct_vm.warp("2026-06-05T00:00:00Z")
    with direct_vm.expect_revert("policy not yet expired"):
        c.expire_policy(PACKAGE, addr_hex(direct_alice))


def test_expire_policy_frees_locked_capacity_after_term_ends(direct_vm, direct_deploy,
                                                              direct_alice, direct_bob):
    c = _deploy(direct_deploy)
    direct_vm.warp(T0)

    _underwrite(direct_vm, c, direct_bob, 100 * GEN)
    _buy(direct_vm, c, direct_alice, 10 * GEN, 1 * GEN, 30)

    pool_before = c.get_pool(PACKAGE)
    assert pool_before["locked_wei"] == str(10 * GEN)

    # Past the 30-day term -- anyone can now expire it and free the capacity.
    direct_vm.warp("2026-07-05T00:00:00Z")
    direct_vm.sender = direct_bob  # expiry isn't holder-gated; the underwriter can call it too
    c.expire_policy(PACKAGE, addr_hex(direct_alice))

    pol = c.get_policy(PACKAGE, addr_hex(direct_alice))
    assert pol["status"] == "EXPIRED"

    pool_after = c.get_pool(PACKAGE)
    assert pool_after["locked_wei"] == "0"
    assert pool_after["available_wei"] == pool_after["total_stake_wei"]


def test_expire_policy_rejects_without_active_policy(direct_vm, direct_deploy, direct_alice):
    c = _deploy(direct_deploy)
    with direct_vm.expect_revert("policy not found"):
        c.expire_policy(PACKAGE, addr_hex(direct_alice))
