"""Offline product-bound matching of raw cve.now advisory records."""
import copy

import pytest


@pytest.mark.parametrize(("kev", "expected"), [
    ({"dateAdded": "2026-01-01"}, True), (True, True), (False, False), (None, False),
    ("false", False), (["untrusted"], False), (42, False),
])
def test_kev_requires_supported_source_metadata_not_arbitrary_truthy_values(kev, expected):
    from rennacs.matching import match_advisory

    raw = advisory({"product": "New Service"}, exploitation={"kev": kev})
    assert match_advisory("New Service", "1.5", raw)["kev"] is expected



@pytest.mark.parametrize("fields", [
    {"status": "superseded", "supersededBy": ["CVE-2026-54321"]},
    {"status": "published", "supersededBy": ["CVE-2026-54321"]},
])
def test_superseded_advisories_are_unknown_until_replacement_applicability_is_evaluated(fields):
    from rennacs.matching import match_advisory

    raw = advisory({"product": "New Service", "ranges": [{"introduced": "1", "fixed": "2"}]}, **fields)
    result = match_advisory("New Service", "1.5", raw)
    assert result["match_status"] == result["confirmed"] == "unknown"
    assert result["fixed_versions"] == []
    assert result["superseded_by"] == fields["supersededBy"]
    assert any("superseded" in text for text in result["limitations"])



@pytest.mark.parametrize("severity", ["critical", 9.8, ["critical"], True, None])
@pytest.mark.parametrize("exploitation", [True, "KEV", ["kev"], 42, None])
def test_malformed_nested_metadata_cannot_crash_or_confirm_an_asset(severity, exploitation):
    from rennacs.matching import match_advisory

    raw = advisory({"product": "New Service", "ranges": [{"introduced": "1", "fixed": "2"}]},
                   severity=severity, exploitation=exploitation)
    result = match_advisory("New Service", "1.5", raw)
    assert result["match_status"] == "affected"
    assert result["confidence"] == "low"
    assert result["severity"] == "unknown"
    assert result["cvss"] is None
    assert result["kev"] is False



def test_oversized_untrusted_versions_degrade_to_unknown():
    from rennacs.matching import match_advisory

    huge = "9" * 5000
    raw = advisory({"product": "New Service", "ranges": [{"introduced": "1", "fixed": "2"}]})
    assert match_advisory("New Service", huge, raw)["match_status"] == "unknown"
    raw["affected"][0]["ranges"] = [{"introduced": huge, "fixed": "*"}]
    assert match_advisory("New Service", "1.5", raw)["match_status"] == "unknown"



@pytest.mark.parametrize("bounds", [
    {"introduced": "3", "fixed": "2"},
    {"introduced": "1", "fixed": "2", "status": "unaffected"},
    {"introduced": "1", "fixed": "2", "versionType": {"scheme": "rpm"}},
])
def test_uninterpretable_ranges_do_not_supply_fix_guidance(bounds):
    from rennacs.matching import match_advisory

    result = match_advisory("New Service", "1.5", advisory(
        {"product": "New Service", "ranges": [bounds]},
    ))
    assert result["match_status"] == "unknown"
    assert result["fixed_versions"] == []



@pytest.mark.parametrize("record", [
    {"product": "OpenSSH", "package": "Other Component"},
    {"product": "OpenSSH", "package": {"name": "Other Component", "ecosystem": "generic"}},
    {"product": "OpenSSH", "vendor": {"name": "Red Hat"}},
    {"product": "OpenSSH", "ecosystem": {"name": "Debian"}},
    None, "OpenSSH", [],
])
def test_conflicting_or_malformed_record_identity_cannot_supply_service_ranges(record):
    from rennacs.matching import match_advisory

    assert match_advisory("OpenSSH", "9.7p1", advisory(record)) is None



def test_querying_explicit_commercial_edition_does_not_match_community_records():
    from rennacs.matching import match_advisory

    plus = {"vendor": "F5", "product": "NGINX Plus", "edition": "Plus",
            "ranges": [{"introduced": "R4", "fixed": "R33"}]}
    raw = advisory(plus, {"vendor": "F5", "product": "NGINX Open Source", "ranges": [{"introduced": "0"}]})
    result = match_advisory("NGINX Plus", "R20", raw)
    assert result["match_status"] == "unknown"
    assert result["matched_affected"] == [plus]
    assert result["fixed_versions"] == []



def test_openssh_zero_introduction_is_the_explicit_osv_all_releases_sentinel():
    from rennacs.matching import match_advisory

    raw = advisory({"package": "OpenSSH", "ranges": [{"introduced": "0", "fixed": "9.8p1"}]})
    assert match_advisory("OpenSSH", "9.7p1", raw)["match_status"] == "affected"
    assert match_advisory("OpenSSH", "9.8p1", raw) is None



@pytest.mark.parametrize(("cvss", "stated", "score", "label"), [
    (None, "critical", None, "critical"), ("8.1", None, 8.1, "high"),
    (0, None, 0, "none"), (10, None, 10, "critical"),
    (float("nan"), None, None, "unknown"), (float("inf"), None, None, "unknown"),
    (True, None, None, "unknown"), (11, None, None, "unknown"),
    (-1, None, None, "unknown"), ("unscored", None, None, "unknown"),
])
def test_severity_metadata_is_validated_without_affecting_product_range_state(cvss, stated, score, label):
    from rennacs.matching import match_advisory

    result = match_advisory("New Service", "1.5", advisory(
        {"product": "New Service"}, severity={"cvss": cvss}, statedSeverity=stated,
    ))
    assert result["cvss"] == score
    assert result["severity"] == label
    assert result["match_status"] == "unknown"



@pytest.mark.parametrize("fields", [
    {"ranges": None}, {"ranges": "1.0-2.0"}, {"ranges": {"introduced": "1"}},
    {"ranges": [None]}, {"ranges": ["not a range"]}, {"ranges": [[]]},
    {"versions": None}, {"versions": "1.5"}, {"versions": {}},
])
def test_missing_or_unsupported_version_evidence_never_crashes_or_proves_security(fields):
    from rennacs.matching import match_advisory

    result = match_advisory("New Service", "1.5", advisory({"product": "New Service", **fields}))
    assert result["match_status"] == "unknown"
    assert result["confirmed"] == "unknown"
    assert result["fixed_versions"] == []



def test_fix_guidance_excludes_other_release_branches_and_unsupported_schemes():
    from rennacs.matching import match_advisory

    raw = advisory(
        {"product": "New Service", "ranges": [{"introduced": "1", "fixed": "2"}]},
        {"product": "New Service", "ranges": [{"introduced": "10", "fixed": "11"}]},
        {"product": "New Service", "versionType": "rpm", "ranges": [{"introduced": "0", "fixed": "99"}]},
        {"product": "New Service", "ranges": [{"introduced": "1", "fixed": "*"}]},
        {"product": "Other Service", "ranges": [{"introduced": "0", "fixed": "100"}]},
    )
    result = match_advisory("New Service", "1.5", raw)
    assert result["match_status"] == "affected"
    assert result["fixed_versions"] == ["2"]



@pytest.mark.parametrize(("summary", "expected", "field", "kind", "metadata"), [
    ({"text": "Model summary.", "model": "example/model", "generatedAt": "2026-01-01"},
     "Model summary.", "summary", "catalog_summary_may_be_model_written",
     {"model": "example/model", "generatedAt": "2026-01-01"}),
    ("Catalog summary text.", "Catalog summary text.", "summary", "catalog_summary_may_be_model_written", {}),
    (None, "Vendor advisory description.", "originalDescription", "sourced_description", {}),
])
def test_summary_provenance_distinguishes_catalog_summaries_from_sourced_descriptions(
        summary, expected, field, kind, metadata):
    from rennacs.matching import match_advisory

    raw = advisory({"product": "New Service"}, summary=summary,
                   sources=[{"name": "cvelistV5", "license": "CVE Terms of Use"}])
    result = match_advisory("New Service", "1", raw)
    assert result["summary"] == expected
    assert result["summary_provenance"] == {"field": field, "kind": kind, "metadata": metadata}
    assert result["original_description"] == raw["originalDescription"]
    assert result["sources"] == raw["sources"]
    result["sources"].clear()
    assert raw["sources"]



@pytest.mark.parametrize("identifier", [
    "CVE-2026-12345", "GHSA-vg84-c5mg-76xh", "GHSA-4MFG-R38W-W8FG", "GO-2026-1234", "GO-2026-1",
])
def test_advisory_ids_are_validated_and_preserved_exactly(identifier):
    from rennacs.matching import match_advisory

    result = match_advisory("New Service", "1.0", advisory({"product": "New Service"}, id=identifier))
    assert result["cve"] == result["catalog_id"] == identifier
    assert result["source_url"] == "https://cve.now/" + identifier


@pytest.mark.parametrize("identifier", [
    "cve-2026-12345", " CVE-2026-12345", "CVE-2026-12345\n", "CVE-2026-12345/../../",
    "CVE-２０２６-12345", "CVE-2026-123", "GHSA-1234-5678-90ab/", "", None, 123,
])
def test_malformed_advisory_ids_raise_without_repair_or_feed_id_fallback(identifier):
    from rennacs.matching import match_advisory

    raw = advisory({"product": "New Service"}, id=identifier, feedId="CVE-2026-12345")
    with pytest.raises(ValueError, match="advisory ID"):
        match_advisory("New Service", "1.0", raw)


@pytest.mark.parametrize("fields", [
    {"status": "rejected"}, {"status": "REJECTED"}, {"status": "withdrawn"},
    {"withdrawn": "2026-01-01T00:00:00Z"}, {"withdrawnAt": "2026-01-01T00:00:00Z"},
])
def test_rejected_or_withdrawn_advisories_never_produce_findings(fields):
    from rennacs.matching import match_advisory

    assert match_advisory("New Service", "1.0", advisory(
        {"product": "New Service", "ranges": [{"introduced": "0"}]}, **fields,
    )) is None



@pytest.mark.parametrize(("product", "version", "listed", "expected"), [
    ("New Service", "1.2.3", ["1.2.3", "1.3"], "affected"),
    ("New Service", "1.3.0", ["1.2.3", "1.3"], "affected"),
    ("New Service", "1.2.4", ["1.2.3", "1.3"], None),
    ("OpenSSH", "9.7p1", ["9.7p1"], "affected"),
    ("OpenSSH", "9.7p2", ["9.7p1"], None),
    ("New Service", "1.5", ["1.2", "1.5-ubuntu1"], "unknown"),
    ("New Service", "1.5-ubuntu1", ["1.5-ubuntu1"], "unknown"),
    ("New Service", "1.5", [{"version": "1.5", "status": "affected"}], "unknown"),
])
def test_exact_versions_are_compared_only_under_supported_schemes(product, version, listed, expected):
    from rennacs.matching import match_advisory

    result = match_advisory(product, version, advisory(
        {"package": product, "versions": listed, "ranges": []},
    ))
    assert (result["match_status"] if result else None) == expected


def test_exact_versions_and_ranges_are_a_union_with_unknown_preserved():
    from rennacs.matching import match_advisory

    row = {"product": "New Service", "versions": ["3.0"],
           "ranges": [{"introduced": "1", "fixed": "2"}]}
    raw = advisory(row)
    assert match_advisory("New Service", "3.0", raw)["match_status"] == "affected"
    assert match_advisory("New Service", "2.5", raw) is None
    row["ranges"].append({"introduced": "unknown", "fixed": "*"})
    assert match_advisory("New Service", "2.5", raw)["match_status"] == "unknown"
    assert match_advisory("New Service", "3.0", raw)["match_status"] == "affected"



@pytest.mark.parametrize("row", [
    {"ranges": [{"introduced": "1", "fixed": "*"}]},
    {"ranges": [{"introduced": "Apache HTTP Server 2.4", "lastAffected": "2.4.51"}]},
    {"ranges": [{"introduced": "3", "fixed": "2"}]},
    {"ranges": [{"introduced": "3", "lastAffected": "2"}]},
    {"ranges": [{"introduced": "1", "fixed": "3", "type": "GIT"}]},
    {"ranges": [{"introduced": "1", "fixed": "3", "versionType": "rpm"}]},
    {"ranges": [{"introduced": "1", "fixed": "3", "events": [{"fixed": "1.1"}]}]},
    {"ranges": [{"version": "2.0", "status": "affected"}]},
    {"versionType": "debian", "ranges": [{"introduced": "1", "fixed": "3"}]},
])
def test_ambiguous_or_unsupported_range_schemes_remain_unknown(row):
    from rennacs.matching import match_advisory

    result = match_advisory("New Service", "2.0", advisory({"product": "New Service", **row}))
    assert result["match_status"] == "unknown"
    assert result["confirmed"] == "unknown"


@pytest.mark.parametrize("version", [
    "", None, "1.5-2ubuntu1", "1.5rc1", "v1.5", "1.5+build", "1:1.5", "1.5p1",
    "1.5.0-beta.1", " 1.5", "1.5\n", "1.5 (Debian)",
])
def test_unsupported_observed_versions_are_not_silently_truncated(version):
    from rennacs.matching import match_advisory

    result = match_advisory("New Service", version, advisory(
        {"product": "New Service", "ranges": [{"introduced": "1", "fixed": "2"}]},
    ))
    assert result["match_status"] == "unknown"



@pytest.mark.parametrize(("query", "record", "expected"), [
    ("nginx", {"vendor": "F5", "product": "NGINX Open Source"}, True),
    ("Apache httpd", {"vendor": "Apache Software Foundation", "product": "Apache HTTP Server"}, True),
    ("Dropbear SSH", {"product": "Dropbear"}, True),
    ("Microsoft IIS", {"vendor": "Microsoft", "product": "Internet Information Services"}, True),
    ("OpenSSH", {"vendor": "Unrelated Vendor", "product": "OpenSSH"}, False),
    ("nginx", {"vendor": "F5", "product": "NGINX Plus", "package": "nginx"}, False),
    ("nginx", {"product": "nginx", "edition": "Plus"}, False),
    ("nginx", {"product": "nginx", "edition": "Open Source"}, True),
    ("OpenSSH", {"vendor": "Red Hat", "product": "Red Hat Enterprise Linux 9", "package": "openssh"}, False),
    ("nginx", {"package": "nginx", "ecosystem": "npm"}, False),
    ("nginx", {"package": {"name": "nginx", "ecosystem": "npm"}}, False),
    ("New Service", {"package": {"name": "New Service", "ecosystem": "generic"}}, True),
    ("nginx", {"product": "nginx-helper"}, False),
    ("nginx", {"product": "not nginx"}, False),
    ("Apache httpd", {"product": "Apache Tomcat"}, False),
])
def test_only_compatible_exact_product_or_package_identities_match(query, record, expected):
    from rennacs.matching import match_advisory, product_keys

    result = match_advisory(query, "1.2", advisory(record))
    assert (result is not None) is expected
    if expected:
        label = record.get("product") or record["package"]
        if isinstance(label, dict):
            label = label["name"]
        assert " ".join(label.casefold().split()) in product_keys(query)


def test_unrelated_products_cannot_contaminate_ranges_or_fix_guidance():
    from rennacs.matching import match_advisory

    upstream = {"package": "OpenSSH", "ranges": [{"introduced": "8.5p1", "fixed": "9.8p1"}]}
    raw = advisory(upstream,
        {"vendor": "Red Hat", "product": "Red Hat Enterprise Linux 9", "package": "openssh", "ranges": []},
        {"product": "Unrelated", "ranges": [{"introduced": "0", "fixed": "99.0"}]},
    )
    result = match_advisory("OpenSSH", "9.7p1", raw)
    assert result["matched_affected"] == [upstream]
    assert result["fixed_versions"] == ["9.8p1"]
    assert match_advisory("OpenSSH", "9.8p1", raw) is None



@pytest.mark.parametrize(("bounds", "version", "expected"), [
    ({"introduced": "1.2", "fixed": "2.0"}, "1.1.99", None),
    ({"introduced": "1.2", "fixed": "2.0"}, "1.2", "affected"),
    ({"introduced": "1.2", "fixed": "2.0"}, "1.2.0", "affected"),
    ({"introduced": "1.2", "fixed": "2.0"}, "1.99", "affected"),
    ({"introduced": "1.2", "fixed": "2.0"}, "2.0", None),
    ({"introduced": "1.2", "fixed": "2.0"}, "2.0.1", None),
    ({"introduced": "1.2", "lastAffected": "2.0"}, "2.0", "affected"),
    ({"introduced": "1.2", "lastAffected": "2.0"}, "2.0.1", None),
    ({"fixed": "2.0"}, "1.0", "affected"),
    ({"introduced": "1.0"}, "9.0", "affected"),
])
def test_numeric_range_boundaries(bounds, version, expected):
    from rennacs.matching import match_advisory

    result = match_advisory("New Service", version, advisory(
        {"product": "New Service", "ranges": [bounds]},
    ))
    if expected is None:
        assert result is None
    else:
        assert result["match_status"] == expected
        assert result["confirmed"] == "yes"
        assert result["confidence"] == "low"
        assert result["fixed_versions"] == ([bounds["fixed"]] if "fixed" in bounds else [])



def advisory(*affected, **fields):
    return {
        "id": "CVE-2026-12345", "status": "published", "affected": list(affected),
        "originalDescription": "Vendor advisory description.", **fields,
    }


def test_exact_generic_package_without_version_evidence_is_a_potential_finding():
    from rennacs.matching import match_advisory

    row = {"package": "New Service", "ranges": []}
    raw = advisory(row, summary={"text": "Sourced summary."},
                   severity={"cvss": 8.1, "vector": "CVSS:3.1/test"},
                   exploitation={"kev": {"dateAdded": "2026-01-01"}})
    before = copy.deepcopy(raw)
    result = match_advisory("new\t service", "1.2", raw)
    assert result is not None
    assert {key: result[key] for key in (
        "cve", "catalog_id", "source", "source_url", "detection_method",
        "match_status", "confirmed", "confidence", "summary", "severity",
        "cvss", "kev", "fixed_versions", "matched_affected",
    )} == {
        "cve": raw["id"], "catalog_id": raw["id"], "source": "cve.now-catalog",
        "source_url": "https://cve.now/CVE-2026-12345",
        "detection_method": "catalog_product_version", "match_status": "unknown",
        "confirmed": "unknown", "confidence": "low", "summary": "Sourced summary.",
        "severity": "high", "cvss": 8.1, "kev": True,
        "fixed_versions": [], "matched_affected": [row],
    }
    assert result["affected"] == [row]
    assert result["limitations"]
    assert any("not proof" in text for text in result["limitations"])
    assert any("unknown" in text.lower() for text in result["limitations"])
    assert raw == before



def test_product_keys_expand_explicit_aliases_with_catalog_normalization():
    from rennacs.matching import product_keys

    assert product_keys("  APACHE\tHTTPD  ") == (
        "apache http server", "apache httpd", "httpd",
    )
    assert product_keys("New\tVendor   Service") == ("new vendor service",)
    assert product_keys("  ") == ()


@pytest.mark.parametrize(("version", "expected"), [
    ("8.5p0", None), ("8.5p1", "affected"), ("8.9p1", "affected"),
    ("9.7p1", "affected"), ("9.7p2", None), ("9.8p1", None),
])
def test_openssh_portable_patch_suffix_is_part_of_the_version(version, expected):
    from rennacs.matching import match_advisory

    raw = advisory({"package": "OpenSSH", "ranges": [
        {"introduced": "8.5p1", "lastAffected": "9.7p1"},
    ]})
    result = match_advisory("OpenSSH", version, raw)
    assert (result["match_status"] if result else None) == expected


def test_openssh_fixed_portable_patch_is_exclusive_and_available_as_guidance():
    from rennacs.matching import match_advisory

    raw = advisory({"product": "OpenSSH", "ranges": [
        {"introduced": "9.7p1", "fixed": "9.7p2"},
    ]})
    assert match_advisory("OpenSSH", "9.7p1", raw)["fixed_versions"] == ["9.7p2"]
    assert match_advisory("OpenSSH", "9.7p2", raw) is None
