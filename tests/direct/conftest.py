"""Shared fixtures and mock helpers for PatchGuard direct-mode tests.

Direct mode runs the leader function only (validator logic is exercised by
integration tests), so these helpers mock the single public GitHub Advisory
Database endpoint the contract reads, plus the LLM classification call.
"""

import json

CONTRACT = "contracts/patch_guard.py"
FEE_WALLET = "0x" + "ab" * 20
FEE_BPS = 500  # 5%

GEN = 10**18  # 1 GEN in wei

ADVISORIES_URL = r"https://api\.github\.com/advisories\?.*"
LLM_PROMPT = r".*vulnerability-SLA compliance.*"


def addr_hex(a) -> str:
    """Normalize a direct-mode address fixture (bytes or Address) to 0x-hex."""
    if isinstance(a, str):
        return a
    if hasattr(a, "as_hex"):
        return a.as_hex
    return "0x" + bytes(a).hex()


def _advisory(*, severity="critical", published_at="2026-05-01T00:00:00Z",
              patched=False, withdrawn=False, ghsa_id="GHSA-test-0000",
              pkg_ecosystem="PyPI", pkg_name="example"):
    adv = {
        "ghsa_id": ghsa_id,
        "severity": severity,
        "published_at": published_at,
        "vulnerabilities": [
            {
                "package": {"ecosystem": pkg_ecosystem, "name": pkg_name},
                "patched_versions": ">=2.0.0" if patched else "",
            }
        ],
    }
    if withdrawn:
        adv["withdrawn_at"] = published_at
    return adv


def mock_advisories(direct_vm, advisories):
    """Mock the GitHub Advisory Database list endpoint with a raw list of records."""
    direct_vm.mock_web(
        ADVISORIES_URL,
        {"status": 200, "body": json.dumps(advisories)},
    )


def mock_no_advisories(direct_vm):
    mock_advisories(direct_vm, [])


def mock_open_critical(direct_vm, days_ago_published):
    """A single unpatched CRITICAL advisory published `days_ago_published` days ago."""
    from datetime import datetime, timedelta, timezone

    published = (datetime.now(timezone.utc) - timedelta(days=days_ago_published))
    mock_advisories(
        direct_vm,
        [_advisory(severity="critical", published_at=published.isoformat(), patched=False)],
    )


def mock_patched_critical(direct_vm):
    mock_advisories(
        direct_vm,
        [_advisory(severity="critical", patched=True)],
    )


def mock_verdict(direct_vm, sla_status, reasoning="test"):
    """Mock the LLM classification response."""
    direct_vm.mock_llm(LLM_PROMPT, json.dumps({"sla_status": sla_status, "reasoning": reasoning}))


def mock_open_moderate(direct_vm, published_at="2026-05-20T00:00:00Z", ghsa_id="GHSA-test-0000"):
    """A single unpatched MODERATE advisory -- open, but not critical/high, so
    it doesn't block a purchase. Defaults to the same fixed ghsa_id used
    elsewhere so tests can simulate that same advisory later escalating to
    critical/high severity; pass a different ghsa_id to model a second,
    independent open advisory."""
    mock_advisories(
        direct_vm,
        [_advisory(severity="moderate", published_at=published_at, patched=False, ghsa_id=ghsa_id)],
    )


def mock_wrong_package_critical(direct_vm, days_ago_published=45,
                                pkg_ecosystem="npm", pkg_name="unrelated-package"):
    """An unpatched CRITICAL advisory that GitHub's `affects` filter returned,
    but whose `vulnerabilities[]` entries are for a DIFFERENT package than the
    one being insured (PACKAGE = PyPI/example). Must never block a purchase
    or trigger a claim for PACKAGE -- it isn't evidence about it."""
    from datetime import datetime, timedelta, timezone

    published = (datetime.now(timezone.utc) - timedelta(days=days_ago_published))
    mock_advisories(
        direct_vm,
        [_advisory(
            severity="critical", published_at=published.isoformat(), patched=False,
            ghsa_id="GHSA-wrong-pkg1", pkg_ecosystem=pkg_ecosystem, pkg_name=pkg_name,
        )],
    )


def mock_two_open_advisories(direct_vm, ghsa_id_a="GHSA-test-aaaa", ghsa_id_b="GHSA-test-bbbb",
                             published_at="2026-05-20T00:00:00Z"):
    """Two distinct, simultaneously-open LOW/MODERATE advisories for the same
    insured package, so tests can verify BOTH ghsa_ids end up in the purchase-
    time baseline -- not only whichever one the worst-open reduction picks."""
    mock_advisories(
        direct_vm,
        [
            _advisory(severity="low", published_at=published_at, patched=False, ghsa_id=ghsa_id_a),
            _advisory(severity="moderate", published_at=published_at, patched=False, ghsa_id=ghsa_id_b),
        ],
    )
