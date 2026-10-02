import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures"
sys.path.insert(0, str(ROOT))

import cbom_check  # noqa: E402


def run(*args):
    proc = subprocess.run(
        [sys.executable, str(ROOT / "cbom_check.py"), *map(str, args), "--json"],
        capture_output=True, text=True)
    return proc.returncode, json.loads(proc.stdout)


def codes(doc):
    return {f["code"] for f in doc["findings"]}


# (fixture, extra args, expected code). Each fixture is otherwise clean, so the
# expected code must be the *only* finding.
BAD = [
    ("schema_invalid.json", [], "CBOM_SCHEMA_INVALID"),
    ("asset_missing_crypto_properties.json", [], "CBOM_ASSET_MISSING_CRYPTO_PROPERTIES"),
    ("assettype_implausible.json", ["--strict"], "CBOM_ASSETTYPE_IMPLAUSIBLE"),
    ("assettype_implausible_protocol.json", ["--strict"], "CBOM_ASSETTYPE_IMPLAUSIBLE"),
    ("nist_level_on_non_algorithm.json", [], "CBOM_NIST_LEVEL_ON_NON_ALGORITHM"),
    ("nist_level_mismatch.json", [], "CBOM_NIST_LEVEL_MISMATCH"),
    ("parameter_set_name_incomplete.json", [], "CBOM_PARAMETER_SET_NAME_INCOMPLETE"),
    ("no_classical_algorithms.json", [], "CBOM_NO_CLASSICAL_ALGORITHMS"),
    ("serialnumber_not_refreshed.json", ["--baseline", FIX / "baseline.json"],
     "CBOM_SERIALNUMBER_NOT_REFRESHED"),
    ("timestamp_not_refreshed.json", ["--baseline", FIX / "baseline.json"],
     "CBOM_TIMESTAMP_NOT_REFRESHED"),
    ("clean.json", ["--acvp", FIX / "acvp_algorithm_not_in_cbom.json"], "ACVP_ALGORITHM_NOT_IN_CBOM"),
    ("clean.json", ["--acvp", FIX / "acvp_cbom_algorithm_not_tested.json"], "CBOM_ALGORITHM_NOT_TESTED"),
    ("clean.json", ["--acvp", FIX / "acvp_algorithm_name_mismatch.json"], "ALGORITHM_NAME_MISMATCH"),
    ("clean.json", ["--profile", "cert-in"], "CBOM_CERTIN_ELEMENT_MISSING"),
    ("unsupported_spec_version.json", [], "CBOM_SCHEMA_INVALID"),
]


@pytest.mark.parametrize("fixture,extra,code", BAD, ids=[b[2] + ":" + b[0] for b in BAD])
def test_bad_fixture_yields_its_code_and_nonzero_exit(fixture, extra, code):
    rc, doc = run(FIX / fixture, *extra)
    assert codes(doc) == {code}
    assert rc == 1


def test_every_reason_code_has_a_fixture():
    expected = {
        "CBOM_SCHEMA_INVALID", "CBOM_ASSET_MISSING_CRYPTO_PROPERTIES", "CBOM_ASSETTYPE_IMPLAUSIBLE",
        "CBOM_NIST_LEVEL_ON_NON_ALGORITHM", "CBOM_NIST_LEVEL_MISMATCH",
        "CBOM_PARAMETER_SET_NAME_INCOMPLETE", "CBOM_NO_CLASSICAL_ALGORITHMS",
        "CBOM_SERIALNUMBER_NOT_REFRESHED", "CBOM_TIMESTAMP_NOT_REFRESHED",
        "ACVP_ALGORITHM_NOT_IN_CBOM", "CBOM_ALGORITHM_NOT_TESTED", "ALGORITHM_NAME_MISMATCH",
        "CBOM_CERTIN_ELEMENT_MISSING",
    }
    assert {b[2] for b in BAD} == expected


def test_clean_cbom_exits_zero_with_all_options():
    rc, doc = run(FIX / "clean.json", "--acvp", FIX / "acvp_clean.json",
                  "--baseline", FIX / "baseline.json", "--strict")
    assert doc["schema"]["valid"] is True
    assert doc["findings"] == []
    assert rc == 0


def test_assettype_heuristic_is_warning_without_strict():
    rc, doc = run(FIX / "assettype_implausible.json")
    assert [f["severity"] for f in doc["findings"]] == ["warning"]
    assert "modelling decision is yours" in doc["findings"][0]["message"]
    assert rc == 0


def test_schema_valid_but_semantically_wrong_cbom_fails():
    bom = json.loads((FIX / "nist_level_mismatch.json").read_text())
    valid, errors = cbom_check.schema_validate(bom)
    assert valid and errors == []          # the schema is satisfied...
    rc, doc = run(FIX / "nist_level_mismatch.json")
    assert doc["schema"]["valid"] is True
    assert "does NOT mean" in doc["schema"]["note"]
    assert rc == 1                         # ...and the CBOM is still wrong.


def test_acvp_extraction_reports_source_fields_and_ignores_non_alg_fields():
    _, doc = run(FIX / "clean.json", "--acvp", FIX / "acvp_clean.json")
    fields = [a["field"] for a in doc["acvp_extraction"]["algorithms"]]
    assert "testSessions[0].vectorSets[2].algorithm" in fields
    # 'vendorName: ACME RSA Labs' contains RSA but is not an algorithm field
    assert not any(f.startswith("vendorName") for f in fields)


@pytest.mark.parametrize("name,level", [
    ("ML-KEM-512", 1), ("ML-KEM-768", 3), ("ML-KEM-1024", 5),
    ("ML-DSA-44", 2), ("ML-DSA-65", 3), ("ML-DSA-87", 5),
    ("SLH-DSA-SHA2-128s", 1), ("SLH-DSA-SHAKE-128f", 1), ("SLH-DSA-SHA2-192f", 3),
    ("SLH-DSA-SHAKE-256s", 5), ("ML-KEM 768", 3),
])
def test_nist_level_table(name, level):
    [tok] = cbom_check.extract_algorithms(name)
    assert cbom_check.expected_nist_level(tok) == level


def test_unreadable_input_exits_two():
    proc = subprocess.run([sys.executable, str(ROOT / "cbom_check.py"), str(FIX / "nope.json")],
                          capture_output=True, text=True)
    assert proc.returncode == 2
    assert "INPUT_ERROR" in proc.stderr


def test_acvp_extraction_ignores_sibling_fields_under_algorithm_list():
    # Regression: a parent path containing 'alg' must not pull in sibling fields,
    # or 'AES-256 equivalent' in a security-level label reads as "AES was tested".
    report = {"algorithms": [{
        "algorithm": "ML-KEM-1024",
        "securityLevel": "NIST Level 5 (AES-256 equivalent)",
        "testTypes": [{"name": "SHA-256 KeyGen vectors"}],
    }]}
    hits, _ = cbom_check.extract_from_report(report)
    assert [(h.token.text, h.field) for h in hits] == [("ML-KEM-1024", "algorithms[0].algorithm")]


@pytest.mark.parametrize("name,expected", [
    ("SHA256withRSA", ["SHA-2:SHA2-256", "RSA"]),
    ("sha256WithRSAEncryption", ["SHA-2:SHA2-256", "RSA"]),
    ("ECDSAwithSHA256", ["ECDSA", "SHA-2:SHA2-256"]),
    ("X25519MLKEM768", ["X25519", "ML-KEM:768"]),
    ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ["ECDH", "RSA", "AES:GCM", "SHA-2:SHA2-256"]),
    ("HMAC-SHA2-256", ["HMAC:SHA2-256"]),
    ("ACVP-AES-GCM", ["AES:GCM"]),
    ("Module-Lattice-Based KEM", []),
    ("XML-KEM", []),
])
def test_real_world_name_forms(name, expected):
    assert [t.ident for t in cbom_check.extract_algorithms(name)] == expected


def _bom(*components):
    bom = json.loads((FIX / "clean.json").read_text())
    bom["components"] = list(components)
    return bom


def _alg(name, level=None, psi=None, description=None):
    ap = {"primitive": "kem"}
    if psi:
        ap["parameterSetIdentifier"] = psi
    if level is not None:
        ap["nistQuantumSecurityLevel"] = level
    c = {"type": "cryptographic-asset", "name": name,
         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": ap}}
    if description:
        c["description"] = description
    return c


def test_parameter_set_from_identifier_is_not_incomplete():
    bom = _bom(_alg("RSA-2048"), _alg("ML-KEM", 3, psi="ML-KEM-768"), _alg("ML-KEM", 5, psi="1024"))
    assert cbom_check.check_components(bom) == []


def test_parameter_set_from_identifier_feeds_level_check():
    bom = _bom(_alg("RSA-2048"), _alg("ML-KEM", 5, psi="768"))
    assert [f.code for f in cbom_check.check_components(bom)] == ["CBOM_NIST_LEVEL_MISMATCH"]


def test_fips_title_in_description_is_not_an_implementation_word():
    bom = _bom(_alg("RSA-2048"),
               _alg("ML-KEM-768", 3, description="Module-Lattice-Based Key-Encapsulation Mechanism"))
    assert cbom_check.check_components(bom) == []


def test_hybrid_group_counts_as_classical():
    bom = _bom(_alg("X25519MLKEM768", 3))
    assert cbom_check.check_components(bom) == []


def test_slh_dsa_without_hash_family_in_report_is_one_name_mismatch():
    bom = _bom(_alg("RSA-2048"), _alg("SLH-DSA-SHAKE-128s", 1))
    report = {"results": [{"algorithm": "RSA"}, {"algorithm": "SLH-DSA-128s"}]}
    findings, _, _ = cbom_check.check_acvp(bom, report)
    assert [f.code for f in findings] == ["ALGORITHM_NAME_MISMATCH"]


def test_slh_dsa_different_hash_family_is_not_the_same_algorithm():
    bom = _bom(_alg("RSA-2048"), _alg("SLH-DSA-SHAKE-128s", 1))
    report = {"results": [{"algorithm": "RSA"}, {"algorithm": "SLH-DSA-SHA2-128s"}]}
    findings, _, _ = cbom_check.check_acvp(bom, report)
    assert sorted(f.code for f in findings) == ["ACVP_ALGORITHM_NOT_IN_CBOM", "CBOM_ALGORITHM_NOT_TESTED"]


def test_utf8_bom_file_is_read(tmp_path):
    p = tmp_path / "bom.json"
    p.write_bytes(b"\xef\xbb\xbf" + (FIX / "clean.json").read_bytes())
    rc, doc = run(p)
    assert rc == 0 and doc["findings"] == []


def test_cyclonedx_1_7_cbom_validates_against_1_7():
    rc, doc = run(FIX / "clean_v1_7.json", "--acvp", FIX / "acvp_clean.json", "--strict")
    assert doc["schema"] == {**doc["schema"], "version": "1.7", "valid": True}
    assert doc["findings"] == []
    assert rc == 0


def test_algorithm_family_does_not_cause_acvp_spelling_mismatch():
    # 1.7 algorithmFamily 'RSASSA-PKCS1' is a category, not the vendor's name for it.
    bom = json.loads((FIX / "clean_v1_7.json").read_text())
    findings, _, _ = cbom_check.check_acvp(bom, {"a": [{"algorithm": "RSA"}]})
    assert "ALGORITHM_NAME_MISMATCH" not in {f.code for f in findings}


def test_certin_profile_passes_when_all_elements_present():
    rc, doc = run(FIX / "certin_complete.json", "--profile", "cert-in", "--strict")
    assert doc["findings"] == [] and rc == 0


def test_certin_profile_is_opt_in():
    rc, doc = run(FIX / "clean.json")
    assert rc == 0 and doc["summary"]["profile"] is None


def test_certin_profile_names_missing_elements():
    _, doc = run(FIX / "clean.json", "--profile", "cert-in")
    by_loc = {f["location"]: f["message"] for f in doc["findings"]}
    aes = next(m for loc, m in by_loc.items() if "AES-256-GCM" in loc)
    assert "OID" in aes and "classical security level" in aes and "mode" in aes
    cert = next(m for loc, m in by_loc.items() if "server certificate" in loc)
    assert "issuer name" in cert and "certificate format" in cert


def test_inventory_marks_quantum_status_and_follows_references():
    _, doc = run(FIX / "certin_complete.json")
    inv = {r["name"]: r for r in doc["inventory"]}
    assert inv["RSA-2048"]["quantum"] == "vulnerable"
    assert inv["ML-KEM-768"]["quantum"] == "quantum-resistant"
    assert inv["AES-256-GCM"]["quantum"] == "symmetric/hash"
    assert inv["server certificate"]["quantum"] == "vulnerable"
    assert inv["server certificate"]["via"] == ["RSA-2048"]
    assert inv["server private key"]["parameter_set_or_size"] == 2048


def test_inventory_hybrid_group():
    bom = _bom(_alg("X25519MLKEM768", 3))
    assert cbom_check.inventory(bom)[0]["quantum"] == "hybrid"
