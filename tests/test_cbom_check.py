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
