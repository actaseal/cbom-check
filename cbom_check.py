#!/usr/bin/env python3
"""cbom_check: semantic checks for CycloneDX CBOMs.

Schema validation answers "is this well-formed CycloneDX 1.6/1.7?".
This tool answers "does what the CBOM *says* make sense?".
A CBOM can pass the schema and still be wrong; that gap is the point of this tool.

Usage:
    python cbom_check.py <cbom.json> [--acvp <report.json>]
                         [--baseline <previous_cbom.json>]
                         [--profile cert-in|weak|cnsa2 ...]
                         [--inventory] [--strict] [--json]
    python cbom_check.py <cbom.json> <cbom.json> ... [--profile ...] [--strict] [--json]
        (bulk: one line per file, exit code of the worst file)

Exit codes:
    0  no errors (warnings allowed unless --strict)
    1  at least one error (with --strict, warnings count as errors)
    2  input could not be read / parsed
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Iterator, Optional

__version__ = "1.1.0"

SCHEMA_NOTE = (
    "Schema validation passing does NOT mean the CBOM is semantically correct. "
    "The schema checks shape; the checks below check meaning."
)

ERROR = "error"
WARNING = "warning"


@dataclass
class Finding:
    code: str
    severity: str
    location: str
    message: str
    promoted_by_strict: bool = False


# --------------------------------------------------------------------------
# Algorithm name catalogue
# --------------------------------------------------------------------------
# Each entry: (family, regex, variant_fn). The regex must define a `fam` group:
# the part of the name that is compared for spelling (ALGORITHM_NAME_MISMATCH).
# Matching is case-insensitive; separators '-', '_', ' ' or none are accepted.

_S = r"[-_ ]?"
# Boundaries: a name may not start right after a letter or end right before
# one, except after a digit ('X25519MLKEM768') and around 'with'
# ('SHA256withRSA', 'ECDSAwithSHA256').
_LB = r"(?:(?<![A-Za-z])|(?<=with))"
_LA = r"(?:(?<=\d)(?!\d)|(?![A-Za-z0-9])|(?=with))"


def _hash_id(kind: Optional[str], size: str, trunc: Optional[str] = None) -> str:
    if size == "1":
        return "SHA-1"
    if kind == "3":
        return f"SHA3-{size}"
    return f"SHA2-{size}" + (trunc or "")


_CATALOGUE: list[tuple[str, str, Any]] = [
    # Post-quantum (FIPS 203 / 204 / 205)
    ("SLH-DSA",
     rf"(?P<fam>SLH{_S}DSA)(?:{_S}(?P<hash>SHA2|SHAKE))?(?:{_S}(?P<size>128|192|256)(?P<sf>[sf])?)?",
     lambda m: _slh_variant(m)),
    ("ML-KEM", rf"(?P<fam>ML{_S}KEM)(?:{_S}(?P<p>512|768|1024)(?!\d))?", lambda m: m["p"]),
    ("ML-DSA", rf"(?P<fam>ML{_S}DSA)(?:{_S}(?P<p>44|65|87)(?!\d))?", lambda m: m["p"]),
    # Stateful hash-based signatures (NIST SP 800-208)
    ("LMS", r"(?P<fam>LMS|HSS)", lambda m: None),
    ("XMSS", r"(?P<fam>XMSS(?:MT|\^MT)?)", lambda m: None),
    # MACs / hashes
    ("HMAC",
     rf"(?P<fam>HMAC{_S}SHA(?:{_S}(?P<k>[23])(?={_S}\d{{3}}))?{_S})(?P<size>1|224|256|384|512)(?!\d)",
     lambda m: _hash_id(m["k"], m["size"])),
    ("HMAC", r"(?P<fam>HMAC)", lambda m: None),
    ("SHAKE", rf"(?P<fam>SHAKE{_S})(?P<size>128|256)(?!\d)", lambda m: f"SHAKE{m['size']}"),
    ("SHA-1", rf"(?P<fam>SHA{_S})(?P<size>1)(?!\d)", lambda m: "SHA-1"),
    ("SHA-3", rf"(?P<fam>SHA{_S}3{_S})(?P<size>224|256|384|512)(?!\d)", lambda m: _hash_id("3", m["size"])),
    ("SHA-2",
     rf"(?P<fam>SHA{_S}(?:2{_S})?)(?P<size>224|256|384|512)(?P<trunc>/(?:224|256))?(?!\d)",
     lambda m: _hash_id("2", m["size"], m["trunc"])),
    ("SHA-2", rf"(?P<fam>SHA{_S}2)(?!\d)", lambda m: None),
    ("SHA-3", rf"(?P<fam>SHA{_S}3)(?!\d)", lambda m: None),
    # Classical public key
    ("EdDSA", r"(?P<fam>Ed25519|Ed448|EdDSA)", lambda m: None),
    ("X25519", r"(?P<fam>X25519)", lambda m: None),
    ("X448", r"(?P<fam>X448)", lambda m: None),
    ("ECDSA", r"(?P<fam>ECDSA)", lambda m: None),
    ("DSA", r"(?P<fam>DSA)", lambda m: None),
    ("ECDH", r"(?P<fam>ECDHE?|KAS-ECC(?:-SSC)?)", lambda m: None),
    ("DH", r"(?P<fam>FFDHE?|DHE?|Diffie[-_ ]?Hellman|KAS-FFC(?:-SSC)?)", lambda m: None),
    ("RSA", r"(?P<fam>RSA(?:SSA|ES)?(?:Encryption)?)(?:[-_ ]?(?:1024|2048|3072|4096|8192)(?!\d))?", lambda m: None),
    # Symmetric
    ("AES",
     r"(?P<fam>AES)(?:[-_ ]?(?:128|192|256)(?!\d))?"
     r"(?:[-_ ]?(?P<mode>GCM-SIV|GCM|CCM|CBC|CTR|ECB|XTS|KWP|KW|CFB(?:1|8|128)?|OFB|CMAC|GMAC|FF1|FF3-1))?",
     lambda m: m["mode"].upper() if m["mode"] else None),
    ("3DES", r"(?P<fam>3DES|TDES|TDEA|Triple[-_ ]?DES)", lambda m: None),
    ("ChaCha20", r"(?P<fam>ChaCha20)", lambda m: None),
    ("MD5", r"(?P<fam>MD5)", lambda m: None),
]

_COMPILED = [(fam, re.compile(_LB + rx + _LA, re.IGNORECASE), fn) for fam, rx, fn in _CATALOGUE]

PQ_FAMILIES = {"ML-KEM", "ML-DSA", "SLH-DSA", "LMS", "XMSS"}
CLASSICAL_FAMILIES = {"RSA", "DSA", "ECDSA", "ECDH", "EdDSA", "X25519", "X448", "DH", "AES",
                      "3DES", "ChaCha20", "SHA-1", "SHA-2", "SHA-3", "SHAKE", "MD5", "HMAC"}


def _slh_variant(m: re.Match) -> Optional[str]:
    if not m["size"]:
        return None
    h = (m["hash"] or "?").upper()
    return f"{h}-{m['size']}{(m['sf'] or '?').lower()}"


@dataclass
class AlgToken:
    family: str
    variant: Optional[str]
    spelling: str          # the `fam` part, as written
    text: str              # full matched text, as written
    groups: dict = field(default_factory=dict)

    @property
    def ident(self) -> str:
        return f"{self.family}:{self.variant}" if self.variant else self.family


def extract_algorithms(text: str) -> list[AlgToken]:
    """Find known algorithm names in free text. Earlier catalogue entries win;
    a matched span is consumed so 'HMAC-SHA2-256' does not also yield 'SHA2-256'."""
    taken: list[tuple[int, int]] = []
    found: list[tuple[int, AlgToken]] = []
    for family, rx, fn in _COMPILED:
        for m in rx.finditer(text):
            s, e = m.span()
            if any(s < te and ts < e for ts, te in taken):
                continue
            taken.append((s, e))
            found.append((s, AlgToken(family, fn(m), m["fam"], m.group(0), m.groupdict())))
    return [t for _, t in sorted(found, key=lambda x: x[0])]


# --------------------------------------------------------------------------
# NIST PQC security categories.
# Sources:
#   FIPS 203 (ML-KEM), Table 2:  ML-KEM-512 -> 1, ML-KEM-768 -> 3, ML-KEM-1024 -> 5
#   FIPS 204 (ML-DSA), Table 1:  ML-DSA-44 -> 2, ML-DSA-65 -> 3, ML-DSA-87 -> 5
#   FIPS 205 (SLH-DSA), Table 2: SLH-DSA-{SHA2,SHAKE}-128{s,f} -> 1,
#                                -192{s,f} -> 3, -256{s,f} -> 5
# --------------------------------------------------------------------------
NIST_LEVELS = {
    ("ML-KEM", "512"): 1, ("ML-KEM", "768"): 3, ("ML-KEM", "1024"): 5,
    ("ML-DSA", "44"): 2, ("ML-DSA", "65"): 3, ("ML-DSA", "87"): 5,
}
SLH_DSA_LEVELS = {"128": 1, "192": 3, "256": 5}


def expected_nist_level(tok: AlgToken) -> Optional[int]:
    if tok.family == "SLH-DSA":
        return SLH_DSA_LEVELS.get(tok.groups.get("size") or "")
    return NIST_LEVELS.get((tok.family, tok.variant or ""))


# --------------------------------------------------------------------------
# Heuristics for CBOM_ASSETTYPE_IMPLAUSIBLE
# --------------------------------------------------------------------------
IMPLEMENTATION_WORDS = re.compile(
    r"\b(HSMs?|modules?(?![-\s]lattice)|cards?|smart\s*cards?|appliances?|engines?|devices?|chips?|TPMs?)\b",
    re.IGNORECASE)
KNOWN_PROTOCOLS = re.compile(
    r"\b(D?TLS|SSL|RFC\s*3161|time[-\s]?stamp(?:ing)?\s+protocol|IKE(?:v[12])?|IPsec|SSH(?:v?2)?"
    r"|X\.?509\s+(?:certificate\s+|certification\s+)?path\s+validation)",
    re.IGNORECASE)

MODELLING_NOTE = ("This is a heuristic: the modelling decision is yours. "
                  "The tool only raises the question.")


# --------------------------------------------------------------------------
# CBOM traversal helpers
# --------------------------------------------------------------------------

def iter_components(bom: dict) -> Iterator[tuple[str, dict]]:
    def walk(comps: Any, prefix: str) -> Iterator[tuple[str, dict]]:
        if not isinstance(comps, list):
            return
        for i, c in enumerate(comps):
            if not isinstance(c, dict):
                continue
            path = f"{prefix}[{i}]"
            yield path, c
            yield from walk(c.get("components"), f"{path}.components")
    yield from walk(bom.get("components"), "components")
    meta_comp = (bom.get("metadata") or {}).get("component")
    if isinstance(meta_comp, dict):
        yield from walk(meta_comp.get("components"), "metadata.component.components")


def label(path: str, c: dict) -> str:
    name = c.get("name", "?")
    ref = c.get("bom-ref")
    return f"{path} '{name}'" + (f" (bom-ref {ref})" if ref and ref != name else "")


def crypto_props(c: dict) -> Optional[dict]:
    cp = c.get("cryptoProperties")
    return cp if isinstance(cp, dict) else None


def asset_type(c: dict) -> Optional[str]:
    cp = crypto_props(c)
    return cp.get("assetType") if cp else None


def algorithm_text(c: dict, with_family: bool = True) -> str:
    """Name, algorithmFamily (1.7) and parameterSetIdentifier, e.g.
    'my-kem' + 'ML-KEM' + '768'. The family goes right before the parameter
    set so the two read as one name."""
    cp = crypto_props(c) or {}
    ap = cp.get("algorithmProperties") or {}
    family = ap.get("algorithmFamily") if with_family else None
    parts = [c.get("name", ""), family, ap.get("parameterSetIdentifier")]
    return " ".join(str(p) for p in parts if p)


def algorithm_tokens_of(c: dict, with_family: bool = True) -> list[AlgToken]:
    """Algorithm names from name + parameterSetIdentifier. When the same family
    appears both bare and complete (name 'ML-KEM', parameterSetIdentifier
    'ML-KEM-768'), the bare one is dropped."""
    toks = extract_algorithms(algorithm_text(c, with_family))
    complete = {t.family for t in toks if _incomplete_name(t) is None}
    return [t for t in toks if t.family not in complete or _incomplete_name(t) is None]


def find_keys(obj: Any, key: str, path: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else k
            if k == key:
                yield p, v
            yield from find_keys(v, key, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from find_keys(v, key, f"{path}[{i}]")


# --------------------------------------------------------------------------
# Schema validation (baseline, not the point of this tool)
# --------------------------------------------------------------------------

SUPPORTED_SPEC_VERSIONS = ("1.6", "1.7")


def schema_validate(bom: dict) -> tuple[bool, list[str]]:
    """Validate against the schema of the BOM's own specVersion (1.6 or 1.7;
    CBOM support starts at 1.6)."""
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    spec = bom.get("specVersion")
    if spec not in SUPPORTED_SPEC_VERSIONS:
        return False, [f"$.specVersion: {spec!r} is not supported; this tool validates "
                       f"CycloneDX {' and '.join(SUPPORTED_SPEC_VERSIONS)}"]
    version = SchemaVersion.V1_6 if spec == "1.6" else SchemaVersion.V1_7
    errors = JsonStrictValidator(version).validate_str(json.dumps(bom), all_errors=True)
    if errors is None:
        return True, []
    msgs = []
    for e in errors:
        d = getattr(e, "data", None)
        where = getattr(d, "json_path", "$")
        msgs.append(f"{where}: {getattr(d, 'message', str(e))}")
    return False, msgs


# --------------------------------------------------------------------------
# Semantic checks
# --------------------------------------------------------------------------

def check_components(bom: dict) -> list[Finding]:
    out: list[Finding] = []
    algorithm_tokens: list[AlgToken] = []

    for path, c in iter_components(bom):
        loc = label(path, c)
        cp = crypto_props(c)
        at = asset_type(c)
        text = f"{c.get('name', '')} {c.get('description', '')}"

        # 1. cryptographic-asset without cryptoProperties
        if c.get("type") == "cryptographic-asset" and cp is None:
            out.append(Finding(
                "CBOM_ASSET_MISSING_CRYPTO_PROPERTIES", ERROR, loc,
                "Component type is 'cryptographic-asset' but it has no cryptoProperties; "
                "nothing about the asset (algorithm, protocol, certificate, key) is recorded."))

        if cp is None:
            continue

        # 2. assetType plausibility (heuristic -> warning)
        if at == "algorithm":
            hit = IMPLEMENTATION_WORDS.search(text)
            if hit:
                out.append(Finding(
                    "CBOM_ASSETTYPE_IMPLAUSIBLE", WARNING, loc,
                    f"assetType is 'algorithm' but name/description mentions '{hit.group(0)}', "
                    "which usually describes an implementation (HSM, module, device...), not an "
                    f"algorithm. {MODELLING_NOTE}"))
        elif at == "protocol":
            if not KNOWN_PROTOCOLS.search(text):
                out.append(Finding(
                    "CBOM_ASSETTYPE_IMPLAUSIBLE", WARNING, loc,
                    "assetType is 'protocol' but name/description does not match a recognised "
                    "protocol (TLS, RFC 3161, IKE, SSH, IPsec, X.509 path validation). "
                    f"{MODELLING_NOTE}"))

        # 3. nistQuantumSecurityLevel on non-algorithm
        if at != "algorithm":
            for kpath, _ in find_keys(cp, "nistQuantumSecurityLevel", "cryptoProperties"):
                out.append(Finding(
                    "CBOM_NIST_LEVEL_ON_NON_ALGORITHM", ERROR, loc,
                    f"{kpath} is set but assetType is '{at}'. NIST security categories are "
                    "properties of algorithm parameter sets, not of protocols, certificates or "
                    "key material."))
            continue

        tokens = algorithm_tokens_of(c)
        algorithm_tokens.extend(tokens)
        ap = cp.get("algorithmProperties") or {}

        # 4. declared level vs parameter set
        declared = ap.get("nistQuantumSecurityLevel")
        if isinstance(declared, int) and not isinstance(declared, bool):
            for tok in tokens:
                exp = expected_nist_level(tok)
                if exp is not None and exp != declared:
                    out.append(Finding(
                        "CBOM_NIST_LEVEL_MISMATCH", ERROR, loc,
                        f"'{tok.text}' is NIST security category {exp} "
                        f"({_fips_for(tok.family)}), but nistQuantumSecurityLevel is {declared}."))

        # 5. incomplete parameter-set names
        for tok in tokens:
            msg = _incomplete_name(tok)
            if msg:
                out.append(Finding("CBOM_PARAMETER_SET_NAME_INCOMPLETE", ERROR, loc, msg))

    # 6. no classical algorithm at all
    families = {t.family for t in algorithm_tokens}
    if not families & CLASSICAL_FAMILIES:
        found = ", ".join(sorted(families)) or "none recognised"
        out.append(Finding(
            "CBOM_NO_CLASSICAL_ALGORITHMS", ERROR, "components",
            "No classical algorithm (RSA, DSA, ECDSA, ECDH, Ed25519, X25519, DH, AES, 3DES, ChaCha20, "
            "SHA-1/2/3, MD5, HMAC) "
            f"is listed (found: {found}). The purpose of a migration inventory is to show what "
            "is quantum-vulnerable today; listing only post-quantum algorithms describes the "
            "target state, not the inventory."))
    return out


def _fips_for(family: str) -> str:
    return {"ML-KEM": "FIPS 203", "ML-DSA": "FIPS 204", "SLH-DSA": "FIPS 205"}.get(family, "")


def _incomplete_name(tok: AlgToken) -> Optional[str]:
    g = tok.groups
    if tok.family == "SLH-DSA":
        if not g.get("size"):
            return (f"'{tok.text}' has no parameter set. FIPS 205 names are "
                    "SLH-DSA-{SHA2|SHAKE}-{128|192|256}{s|f}, e.g. SLH-DSA-SHA2-128s.")
        if not g.get("hash"):
            sz = f"{g['size']}{(g.get('sf') or 's').lower()}"
            return (f"'{tok.text}' is missing the hash family. FIPS 205 defines both "
                    f"SLH-DSA-SHA2-{sz} and SLH-DSA-SHAKE-{sz}; they are different algorithms.")
        if not g.get("sf"):
            return (f"'{tok.text}' is missing the 's' (small) / 'f' (fast) suffix required by "
                    f"FIPS 205, e.g. SLH-DSA-{g['hash'].upper()}-{g['size']}s.")
    elif tok.family == "ML-KEM" and not tok.variant:
        return f"'{tok.text}' has no parameter set. FIPS 203 names are ML-KEM-512, ML-KEM-768, ML-KEM-1024."
    elif tok.family == "ML-DSA" and not tok.variant:
        return f"'{tok.text}' has no parameter set. FIPS 204 names are ML-DSA-44, ML-DSA-65, ML-DSA-87."
    elif tok.family == "SHA-2" and not tok.variant:
        return (f"'{tok.text}' names a family, not an algorithm. FIPS 180-4 names are "
                "SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256.")
    elif tok.family == "SHA-3" and not tok.variant:
        return (f"'{tok.text}' names a family, not an algorithm. FIPS 202 names are "
                "SHA3-224, SHA3-256, SHA3-384, SHA3-512.")
    return None


def _components_fingerprint(bom: dict) -> list[str]:
    return sorted(json.dumps(c, sort_keys=True) for _, c in iter_components(bom))


def _component_key(c: dict) -> str:
    ref = c.get("bom-ref")
    return f"ref:{ref}" if isinstance(ref, str) and ref else f"name:{c.get('name', '?')}"


def _component_label(c: dict) -> str:
    name, ref = c.get("name", "?"), c.get("bom-ref")
    return f"{name} ({ref})" if isinstance(ref, str) and ref and ref != name else name


def baseline_diff(bom: dict, base: dict) -> dict:
    """What changed since the baseline. Components are matched by bom-ref,
    or by name when there is none."""
    now = {_component_key(c): c for _, c in iter_components(bom)}
    before = {_component_key(c): c for _, c in iter_components(base)}

    def same(a: dict, b: dict) -> bool:
        return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)

    return {
        "added": sorted(_component_label(now[k]) for k in now.keys() - before.keys()),
        "removed": sorted(_component_label(before[k]) for k in before.keys() - now.keys()),
        "changed": sorted(_component_label(now[k]) for k in now.keys() & before.keys()
                          if not same(now[k], before[k])),
    }


def check_baseline(bom: dict, base: dict) -> list[Finding]:
    if _components_fingerprint(bom) == _components_fingerprint(base):
        return []
    out = []
    sn = bom.get("serialNumber")
    if sn == base.get("serialNumber"):
        out.append(Finding(
            "CBOM_SERIALNUMBER_NOT_REFRESHED", ERROR, "serialNumber",
            "Components differ from the baseline but serialNumber is "
            + (f"unchanged ({sn!r})." if sn else "missing in both.")
            + " A changed BOM must get a new serialNumber."))
    ts, bts = (bom.get("metadata") or {}).get("timestamp"), (base.get("metadata") or {}).get("timestamp")
    if ts == bts:
        out.append(Finding(
            "CBOM_TIMESTAMP_NOT_REFRESHED", ERROR, "metadata.timestamp",
            "Components differ from the baseline but metadata.timestamp is "
            + (f"unchanged ({ts!r})." if ts else "missing in both.")))
    return out


# --------------------------------------------------------------------------
# ACVP cross-check
# --------------------------------------------------------------------------

@dataclass
class Extracted:
    token: AlgToken
    field: str
    raw: str


def extract_from_report(report: Any) -> tuple[list[Extracted], str]:
    """Report formats are vendor-specific, so walk every string value and key.
    If any match comes from a field whose own name contains 'alg' (algorithm,
    algo, hashAlg, ...), only those are used; otherwise every match is used.
    Only the field's own name counts, not its parents: under 'algorithms[0]',
    a 'securityLevel' of 'AES-192 equivalent' is not an algorithm."""
    hits: list[Extracted] = []

    def walk(o: Any, path: str) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                p = f"{path}.{k}" if path else k
                for t in extract_algorithms(str(k)):
                    hits.append(Extracted(t, f"{p} (key)", str(k)))
                walk(v, p)
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{path}[{i}]")
        elif isinstance(o, str):
            for t in extract_algorithms(o):
                hits.append(Extracted(t, path, o))

    walk(report, "")

    def leaf(f: str) -> str:
        return re.sub(r"\[\d+\]", "", f.replace(" (key)", "")).rsplit(".", 1)[-1]

    alg_hits = [h for h in hits if "alg" in leaf(h.field).lower()]
    if alg_hits:
        return alg_hits, "fields whose name contains 'alg'"
    return hits, "all string values and keys (no 'alg'-named field found)"


def _same_algorithm(a: AlgToken, b: AlgToken) -> bool:
    if a.family != b.family:
        return False
    if a.variant is None or b.variant is None or a.variant == b.variant:
        return True
    if a.family == "SLH-DSA":
        # A part left out on one side ('SLH-DSA-128s' has no hash family) still
        # matches, and is reported as ALGORITHM_NAME_MISMATCH instead.
        ga, gb = a.groups, b.groups
        return ga["size"] == gb["size"] and all(
            not ga[k] or not gb[k] or ga[k].lower() == gb[k].lower() for k in ("hash", "sf"))
    return False


def check_acvp(bom: dict, report: Any) -> tuple[list[Finding], list[Extracted], str]:
    cbom: list[tuple[str, AlgToken]] = []
    for path, c in iter_components(bom):
        if asset_type(c) == "algorithm":
            # The family field ('RSASSA-PKCS1') is a category, not the name
            # the vendor uses, so it is left out of the spelling comparison.
            for t in algorithm_tokens_of(c, with_family=False):
                cbom.append((label(path, c), t))
    rep, strategy = extract_from_report(report)
    out: list[Finding] = []

    for loc, t in cbom:
        matches = [r for r in rep if _same_algorithm(t, r.token)]
        if not matches:
            out.append(Finding(
                "CBOM_ALGORITHM_NOT_TESTED", ERROR, loc,
                f"'{t.text}' is in the CBOM but no matching algorithm was found in the ACVP report."))
            continue
        exact = [r for r in matches
                 if r.token.spelling.lower() == t.spelling.lower()
                 and (r.token.variant is None or t.variant is None or r.token.variant == t.variant)]
        if not exact:
            srcs = "; ".join(sorted({f"'{r.token.text}' at {r.field}" for r in matches}))
            partial = any(r.token.variant and t.variant and r.token.variant != t.variant for r in matches)
            why = ("The report name leaves out part of the parameter set, so it does not say "
                   "which variant was tested." if partial else
                   "Same algorithm, different name; tools that match by string will miss it.")
            out.append(Finding(
                "ALGORITHM_NAME_MISMATCH", ERROR, loc,
                f"CBOM spells it '{t.text}', the ACVP report spells it differently: {srcs}. {why}"))

    seen = set()
    for r in rep:
        key = (r.token.ident, r.token.text.lower())
        if key in seen:
            continue
        seen.add(key)
        if not any(_same_algorithm(r.token, t) for _, t in cbom):
            out.append(Finding(
                "ACVP_ALGORITHM_NOT_IN_CBOM", ERROR, f"report {r.field}",
                f"'{r.token.text}' is in the ACVP report but not in the CBOM inventory."))
    return out, rep, strategy


# --------------------------------------------------------------------------
# CERT-In profile (--profile cert-in)
# --------------------------------------------------------------------------
# Minimum CBOM elements from CERT-In "Technical Guidelines on SBOM, QBOM & CBOM,
# AIBOM and HBOM" v2.0, mapped to CycloneDX fields. Elements that every
# schema-valid component already has (name, assetType) are not repeated here.
KEY_TYPES = {"private-key", "public-key", "secret-key", "key"}
CERTIN_ALGORITHM = [("primitive", "algorithmProperties.primitive"),
                    ("crypto functions", "algorithmProperties.cryptoFunctions"),
                    ("classical security level", "algorithmProperties.classicalSecurityLevel"),
                    ("OID", "oid")]
CERTIN_KEY = [("key ID", "relatedCryptoMaterialProperties.id"),
              ("key size", "relatedCryptoMaterialProperties.size"),
              ("creation date", "relatedCryptoMaterialProperties.creationDate"),
              ("activation date", "relatedCryptoMaterialProperties.activationDate")]
CERTIN_CERTIFICATE = [("subject name", "certificateProperties.subjectName"),
                      ("issuer name", "certificateProperties.issuerName"),
                      ("validity start", "certificateProperties.notValidBefore"),
                      ("validity end", "certificateProperties.notValidAfter"),
                      ("signature algorithm reference", "certificateProperties.signatureAlgorithmRef"),
                      ("certificate format", "certificateProperties.certificateFormat")]


def _get(obj: dict, dotted: str) -> Any:
    for part in dotted.split("."):
        obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


def check_certin(bom: dict) -> list[Finding]:
    out = []
    for path, c in iter_components(bom):
        cp = crypto_props(c)
        if cp is None:
            continue
        at = cp.get("assetType")
        required: list[tuple[str, str]] = []
        if at == "algorithm":
            required = list(CERTIN_ALGORITHM)
            if _get(cp, "algorithmProperties.primitive") in ("block-cipher", "ae"):
                required.append(("mode", "algorithmProperties.mode"))
        elif at == "related-crypto-material":
            if _get(cp, "relatedCryptoMaterialProperties.type") in KEY_TYPES | {None}:
                required = CERTIN_KEY
        elif at == "certificate":
            required = list(CERTIN_CERTIFICATE)
        missing = [label_ for label_, field_ in required if _get(cp, field_) in (None, "", [])]
        if at == "certificate" and not any(_get(cp, f"certificateProperties.{k}") for k in
                                           ("certificateExtension", "certificateFileExtension",
                                            "certificateExtensions")):
            missing.append("certificate extension")
        if missing:
            out.append(Finding(
                "CBOM_CERTIN_ELEMENT_MISSING", ERROR, label(path, c),
                f"Missing CERT-In CBOM minimum element(s) for a{'n' if at[0] in 'aeiou' else ''} "
                f"{at}: {', '.join(missing)}."))
    return out


# --------------------------------------------------------------------------
# Policy profiles (--profile weak, --profile cnsa2)
# --------------------------------------------------------------------------
# These judge the algorithms the CBOM lists, not whether the CBOM is correct,
# so they are opt-in. An algorithm whose size is not stated is only judged
# where the profile rejects every size but one (AES under CNSA 2.0).

PROFILES = ("cert-in", "weak", "cnsa2")
PUBLIC_KEY_CLASSICAL = {"RSA", "DSA", "ECDSA", "ECDH", "EdDSA", "X25519", "X448", "DH"}


def _size_in(tok: AlgToken) -> Optional[int]:
    m = re.search(r"(?<!\d)(\d{3,5})(?!\d)", tok.text)
    return int(m.group(1)) if m else None


def _weak(tok: AlgToken) -> Optional[tuple[str, str]]:
    """NIST SP 800-131A Rev. 2 and FIPS 186-5."""
    if tok.family == "MD5":
        return ERROR, "MD5 is not an approved hash function; collisions are practical."
    if tok.family == "3DES":
        return ERROR, "Triple DES encryption is disallowed after 2023 (NIST SP 800-131A Rev. 2)."
    if tok.family == "RSA":
        size = _size_in(tok)
        if size is not None and size < 2048:
            return ERROR, (f"RSA keys below 2048 bits are disallowed (NIST SP 800-131A Rev. 2); "
                           f"this one is {size}.")
    if tok.family == "SHA-1":
        return WARNING, ("SHA-1 is disallowed for digital signature generation and NIST retires it "
                         "completely by 31 December 2030.")
    if tok.family == "DSA":
        return WARNING, "FIPS 186-5 no longer approves DSA for generating signatures, only for verifying them."
    return None


CNSA2_ALLOWED = ("CNSA 2.0 allows AES-256, SHA-384/SHA-512, ML-KEM-1024, ML-DSA-87, "
                 "and LMS/XMSS for software and firmware signing.")


def _cnsa2(tok: AlgToken) -> Optional[tuple[str, str, str]]:
    """NSA CNSA 2.0 (September 2022). Returns (code, severity, message)."""
    f = tok.family
    if f in ("LMS", "XMSS", "HMAC"):
        return None
    if f == "AES":
        size = _size_in(tok)
        if size == 256:
            return None
        why = f"AES-{size} is not allowed." if size else "The AES key size is not stated."
        return "CBOM_CNSA2_NOT_ALLOWED", ERROR, f"{why} {CNSA2_ALLOWED}"
    if f == "SHA-2":
        if tok.variant in ("SHA2-384", "SHA2-512") or tok.variant is None:
            return None
        return "CBOM_CNSA2_NOT_ALLOWED", ERROR, f"Only SHA-384 and SHA-512 are allowed. {CNSA2_ALLOWED}"
    if f == "ML-KEM" and tok.variant == "1024" or f == "ML-DSA" and tok.variant == "87":
        return None
    if f in ("ML-KEM", "ML-DSA"):
        if tok.variant is None:
            return None
        return "CBOM_CNSA2_NOT_ALLOWED", ERROR, f"Only the level 5 parameter set is allowed. {CNSA2_ALLOWED}"
    if f in PUBLIC_KEY_CLASSICAL:
        return "CBOM_CNSA2_TRANSITIONAL", WARNING, (
            "Allowed only during the transition to CNSA 2.0; NSA plans for National Security "
            "Systems to finish the move by 2035, with earlier dates for many system types.")
    return "CBOM_CNSA2_NOT_ALLOWED", ERROR, f"Not part of CNSA 2.0. {CNSA2_ALLOWED}"


def check_policy(bom: dict, profile: str) -> list[Finding]:
    out = []
    for path, c in iter_components(bom):
        if asset_type(c) != "algorithm":
            continue
        for tok in algorithm_tokens_of(c):
            if profile == "weak":
                hit = _weak(tok)
                if hit:
                    out.append(Finding("CBOM_WEAK_ALGORITHM", hit[0], label(path, c), f"'{tok.text}': {hit[1]}"))
            elif profile == "cnsa2":
                res = _cnsa2(tok)
                if res:
                    out.append(Finding(res[0], res[1], label(path, c), f"'{tok.text}': {res[2]}"))
    return out


# --------------------------------------------------------------------------
# Inventory: what is quantum-vulnerable today
# --------------------------------------------------------------------------
SHOR_VULNERABLE = {"RSA", "DSA", "ECDSA", "ECDH", "EdDSA", "X25519", "X448", "DH"}


def _quantum_status(families: set[str]) -> str:
    vulnerable = families & SHOR_VULNERABLE
    pq = families & PQ_FAMILIES
    if vulnerable and pq:
        return "hybrid"
    if vulnerable:
        return "vulnerable"
    if pq:
        return "quantum-resistant"
    if families:
        return "symmetric/hash"
    return "unknown"


def _refs_in(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _refs_in(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _refs_in(v)


def inventory(bom: dict) -> list[dict]:
    """One row per crypto asset. Certificates, keys and protocols take their
    algorithms from the components their cryptoProperties reference."""
    comps = list(iter_components(bom))
    by_ref = {c["bom-ref"]: c for _, c in comps if isinstance(c.get("bom-ref"), str)}
    rows = []
    for path, c in comps:
        cp = crypto_props(c)
        if cp is None:
            continue
        at = cp.get("assetType")
        if at == "algorithm":
            toks = algorithm_tokens_of(c)
            via: list[str] = []
        else:
            refs = [r for r in _refs_in(cp) if r in by_ref and r != c.get("bom-ref")]
            toks = [t for r in refs for t in algorithm_tokens_of(by_ref[r])]
            via = [by_ref[r].get("name", r) for r in refs]
        ap = cp.get("algorithmProperties") or {}
        size = ap.get("parameterSetIdentifier") or _get(cp, "relatedCryptoMaterialProperties.size")
        rows.append({
            "location": path,
            "name": c.get("name", "?"),
            "asset_type": at,
            "algorithms": sorted({t.text for t in toks}),
            "via": via,
            "parameter_set_or_size": size,
            "quantum": _quantum_status({t.family for t in toks}),
        })
    return rows


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

class InputError(Exception):
    pass


def load_json(path: str, what: str) -> tuple[Any, str]:
    """Parsed value and the sha256 of the file's exact bytes."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
        return json.loads(raw.decode("utf-8-sig")), hashlib.sha256(raw).hexdigest()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise InputError(f"cannot read {what} '{path}': {e}") from e


def _profiles(profile: Any) -> list[str]:
    profiles = [profile] if isinstance(profile, str) else list(profile or [])
    unknown = [p for p in profiles if p not in PROFILES]
    if unknown:
        raise ValueError(f"unknown profile(s) {unknown}; known: {', '.join(PROFILES)}")
    return profiles


def check(bom: dict, acvp: Any = None, baseline: Optional[dict] = None,
          strict: bool = False, profile: Any = None,
          input_hashes: Optional[dict] = None) -> dict:
    """Run every check and return the result document (what --json prints,
    minus file names). Shared by the CLI and the web page. `profile` is one
    profile name or a list of them; `input_hashes` maps cbom/acvp/baseline to
    the sha256 of the exact input bytes, so the result names what it judged."""
    profiles = _profiles(profile)
    findings: list[Finding] = []
    schema_ok, schema_errors = schema_validate(bom)
    if not schema_ok:
        shown = schema_errors[:10]
        more = f" (+{len(schema_errors) - 10} more)" if len(schema_errors) > 10 else ""
        findings.append(Finding(
            "CBOM_SCHEMA_INVALID", ERROR, "$",
            f"Not valid CycloneDX {bom.get('specVersion')}: " + " | ".join(shown) + more))

    findings += check_components(bom)

    for p in profiles:
        findings += check_certin(bom) if p == "cert-in" else check_policy(bom, p)

    if baseline is not None:
        findings += check_baseline(bom, baseline)

    extracted: list[Extracted] = []
    strategy = None
    if acvp is not None:
        acvp_findings, extracted, strategy = check_acvp(bom, acvp)
        findings += acvp_findings

    if strict:
        for f in findings:
            if f.severity == WARNING:
                f.severity, f.promoted_by_strict = ERROR, True

    n_err = sum(f.severity == ERROR for f in findings)
    n_warn = sum(f.severity == WARNING for f in findings)
    doc: dict = {
        "tool": {"name": "cbom-check", "version": __version__},
    }
    if input_hashes:
        doc["inputs"] = {k: {"sha256": v} for k, v in input_hashes.items() if v}
    doc.update({
        "schema": {"version": bom.get("specVersion"), "valid": schema_ok,
                   "errors": schema_errors, "note": SCHEMA_NOTE},
        "findings": [asdict(f) for f in findings],
        "inventory": inventory(bom),
        "summary": {"errors": n_err, "warnings": n_warn, "strict": strict,
                    "profile": ",".join(profiles) or None, "profiles": profiles,
                    "exit_code": 1 if n_err else 0},
    })
    if baseline is not None:
        doc["baseline_diff"] = baseline_diff(bom, baseline)
    if acvp is not None:
        doc["acvp_extraction"] = {
            "strategy": strategy,
            "algorithms": [{"name": e.token.text, "raw_value": e.raw, "field": e.field}
                           for e in extracted]}
    return doc


def _load_cbom(path: str) -> tuple[dict, str]:
    bom, digest = load_json(path, "CBOM")
    if not isinstance(bom, dict):
        raise InputError(f"CBOM '{path}' top level is not a JSON object")
    return bom, digest


def run_bulk(paths: list[str], strict: bool, profiles: list[str], as_json: bool) -> int:
    results = []
    for path in paths:
        try:
            bom, digest = _load_cbom(path)
        except InputError as e:
            results.append({"cbom": path, "input_error": str(e), "summary": {"exit_code": 2}})
            continue
        results.append({"cbom": path, **check(bom, strict=strict, profile=profiles,
                                              input_hashes={"cbom": digest})})
    unreadable = sum(r["summary"]["exit_code"] == 2 for r in results)
    failed = sum(r["summary"]["exit_code"] == 1 for r in results)
    exit_code = 2 if unreadable else (1 if failed else 0)
    summary = {"files": len(results), "passed": len(results) - failed - unreadable,
               "failed": failed, "unreadable": unreadable, "exit_code": exit_code}
    if as_json:
        print(json.dumps({"tool": {"name": "cbom-check", "version": __version__},
                          "results": results, "summary": summary}, indent=2))
        return exit_code
    print(f"cbom_check (bulk): {len(results)} file(s)"
          + (f", profile(s): {', '.join(profiles)}" if profiles else "")
          + (" [--strict]" if strict else ""))
    for r in results:
        if "input_error" in r:
            print(f"  ERROR  {r['cbom']}: {r['input_error']}")
            continue
        s = r["summary"]
        verdict = "FAIL " if s["exit_code"] else "PASS "
        codes = sorted({f["code"] for f in r["findings"] if f["severity"] == ERROR})
        print(f"  {verdict} {s['errors']:>3} error(s) {s['warnings']:>3} warning(s)  {r['cbom']}"
              + (f"  [{', '.join(codes)}]" if codes else ""))
    print()
    print(f"  {failed + unreadable} of {len(results)} file(s) failed -> exit {exit_code}")
    return exit_code


def run(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Semantic checks for CycloneDX CBOMs.")
    ap.add_argument("cbom", nargs="+", help="CBOM file; several files run in bulk mode")
    ap.add_argument("--acvp", help="ACVP / CAVP test report (JSON, any vendor format)")
    ap.add_argument("--baseline", help="previous CBOM, to check serialNumber/timestamp refresh")
    ap.add_argument("--profile", action="append", choices=PROFILES, default=[],
                    help="extra requirements, repeatable: cert-in (CERT-In CBOM minimum "
                         "elements), weak (NIST SP 800-131A disallowed/deprecated), "
                         "cnsa2 (NSA CNSA 2.0)")
    ap.add_argument("--inventory", action="store_true",
                    help="print the quantum-vulnerability inventory table")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    if len(args.cbom) > 1:
        if args.acvp or args.baseline:
            print("INPUT_ERROR: --acvp and --baseline belong to one CBOM; "
                  "run them per file, not in bulk mode", file=sys.stderr)
            return 2
        return run_bulk(args.cbom, args.strict, args.profile, args.json)

    path = args.cbom[0]
    try:
        bom, digests = _load_cbom(path)
        hashes = {"cbom": digests}
        base = None
        if args.baseline:
            base, hashes["baseline"] = load_json(args.baseline, "baseline")
            if not isinstance(base, dict):
                raise InputError("baseline top level is not a JSON object")
        report = None
        if args.acvp:
            report, hashes["acvp"] = load_json(args.acvp, "ACVP report")
    except InputError as e:
        print(f"INPUT_ERROR: {e}", file=sys.stderr)
        return 2

    doc = check(bom, report, base, args.strict, args.profile, hashes)
    exit_code = doc["summary"]["exit_code"]

    if args.json:
        doc = {"cbom": path, **doc}
        if args.acvp:
            doc["acvp_extraction"] = {"report": args.acvp, **doc["acvp_extraction"]}
        print(json.dumps(doc, indent=2))
        return exit_code

    s = doc["summary"]
    print(f"cbom_check {__version__}: {path} (sha256 {hashes['cbom'][:16]}…)")
    print(f"  Schema (CycloneDX {doc['schema']['version']}): "
          f"{'PASS' if doc['schema']['valid'] else 'FAIL'}")
    print(f"  NOTE: {SCHEMA_NOTE}")
    if args.acvp:
        ex = doc["acvp_extraction"]
        print(f"  ACVP report: {args.acvp} -- algorithm names taken from {ex['strategy']}:")
        for e in ex["algorithms"]:
            raw = "" if e["raw_value"] == e["name"] else f" (in {e['raw_value']!r})"
            print(f"    - {e['name']!r}{raw} from {e['field']}")
    if "baseline_diff" in doc:
        d = doc["baseline_diff"]
        print(f"  Since baseline {args.baseline}: {len(d['added'])} added, "
              f"{len(d['removed'])} removed, {len(d['changed'])} changed")
        for kind, sign in (("added", "+"), ("removed", "-"), ("changed", "~")):
            for name in d[kind]:
                print(f"    {sign} {name}")
    print()
    if not doc["findings"]:
        print("  No semantic findings.")
    for f in doc["findings"]:
        tag = f["severity"].upper() + (" (strict)" if f["promoted_by_strict"] else "")
        print(f"  [{tag}] {f['code']}")
        print(f"      at:  {f['location']}")
        print(f"      why: {f['message']}")
    if args.inventory:
        print()
        print("  Inventory (quantum status per crypto asset):")
        for r in doc["inventory"]:
            algs = ", ".join(r["algorithms"]) or "-"
            via = f" via {', '.join(r['via'])}" if r["via"] else ""
            print(f"    {r['quantum']:<17} {r['asset_type'] or '?':<24} {r['name']}  [{algs}]{via}")
    print()
    print(f"  {s['errors']} error(s), {s['warnings']} warning(s)"
          f"{' [--strict: warnings are errors]' if args.strict else ''} -> exit {exit_code}")
    return exit_code


if __name__ == "__main__":
    sys.exit(run())
