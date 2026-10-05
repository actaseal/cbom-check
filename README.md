# cbom-check

Semantic checker for CycloneDX CBOMs (Cryptography Bills of Materials).

**Schema validation passing does NOT mean the CBOM is semantically correct.**
A CBOM can be perfectly valid CycloneDX 1.6 and still claim ML-KEM-768 is NIST
category 5, call an HSM an "algorithm", or list only post-quantum algorithms.
This tool checks what the CBOM *says*, not just its shape. Every failure has a
named reason code and a non-zero exit, so it can gate CI.

## Usage

```
pip install -r requirements.txt
python cbom_check.py <cbom.json> [--acvp <report.json>] [--baseline <previous_cbom.json>]
                     [--profile cert-in|weak|cnsa2 ...] [--inventory] [--strict] [--json]
python cbom_check.py <cbom.json> <cbom.json> ... [--profile ...] [--strict] [--json]   # bulk
```

Example:

```
$ python cbom_check.py fixtures/nist_level_mismatch.json
cbom_check 1.1.0: fixtures/nist_level_mismatch.json (sha256 269a0c42c03fdda0…)
  Schema (CycloneDX 1.6): PASS
  NOTE: Schema validation passing does NOT mean the CBOM is semantically correct. The schema checks shape; the checks below check meaning.

  [ERROR] CBOM_NIST_LEVEL_MISMATCH
      at:  components[4] 'ML-KEM-768' (bom-ref alg-mlkem)
      why: 'ML-KEM-768' is NIST security category 3 (FIPS 203), but nistQuantumSecurityLevel is 5.

  1 error(s), 0 warning(s) -> exit 1
$ echo $?
1
```

`--json` prints the same result as machine-readable JSON (schema result, findings,
ACVP extraction details, baseline diff, summary with `exit_code`). The result also names
the SHA-256 of every input file and the checker version (`inputs`, `tool`), so anyone can
re-run the same files and get the same result. That is not a timestamp: for proof of
*when* a CBOM passed, the result has to be sealed (ActaSeal does this).

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No errors. Warnings may be present unless `--strict`. |
| 1 | At least one error. With `--strict`, warnings count as errors. |
| 2 | Input could not be read or parsed (`INPUT_ERROR` on stderr). |

Actual runs against the bundled fixtures:

```
fixtures/clean.json --acvp fixtures/acvp_clean.json --baseline fixtures/baseline.json --strict -> exit 0
fixtures/assettype_implausible.json            -> exit 0  (warning only)
fixtures/assettype_implausible.json --strict   -> exit 1
fixtures/no_classical_algorithms.json          -> exit 1
fixtures/schema_invalid.json                   -> exit 1
fixtures/missing.json                          -> exit 2
```

## What is checked

| Reason code | Severity | Check |
|---|---|---|
| `CBOM_SCHEMA_INVALID` | error | Baseline only: CycloneDX 1.6 or 1.7 JSON schema, chosen by the BOM's `specVersion` (via `jsonschema` and the schema bundled in `cyclonedx-python-lib`). Passing this says nothing about the checks below. |
| `CBOM_ASSET_MISSING_CRYPTO_PROPERTIES` | error | Component `type` is `cryptographic-asset` but has no `cryptoProperties`. |
| `CBOM_ASSETTYPE_IMPLAUSIBLE` | warning (error with `--strict`) | Name/description mentions HSM, module, card, appliance, engine, device, chip, TPM and `assetType` is `algorithm`; or `assetType` is `protocol` but name/description does not match a real protocol (TLS, RFC 3161, IKE, SSH, IPsec, X.509 path validation). The modelling decision is yours; the tool only raises the question. |
| `CBOM_NIST_LEVEL_ON_NON_ALGORITHM` | error | `nistQuantumSecurityLevel` on a component whose `assetType` is not `algorithm`. |
| `CBOM_NIST_LEVEL_MISMATCH` | error | Declared level disagrees with the parameter set: ML-KEM-512/768/1024 = 1/3/5 (FIPS 203), ML-DSA-44/65/87 = 2/3/5 (FIPS 204), SLH-DSA-*-128/192/256{s,f} = 1/3/5 (FIPS 205). Parameter set is read from `name` plus `parameterSetIdentifier`. |
| `CBOM_PARAMETER_SET_NAME_INCOMPLETE` | error | Name is missing a part the FIPS canonical name requires: SLH-DSA without hash family (`SLH-DSA-128s` → `SLH-DSA-SHA2-128s` / `SLH-DSA-SHAKE-128s`) or without `s`/`f`; ML-KEM / ML-DSA / SLH-DSA with no parameter set; bare `SHA-2` / `SHA-3`. |
| `CBOM_NO_CLASSICAL_ALGORITHMS` | error | No classical algorithm (RSA, DSA, ECDSA, ECDH, Ed25519, X25519, DH, AES, 3DES, ChaCha20, SHA-1/2/3, MD5, HMAC). Names are read from `name` and `parameterSetIdentifier`; forms like `SHA256withRSA` and `X25519MLKEM768` are recognised. A migration inventory exists to show what is quantum-vulnerable today; listing only PQ algorithms is the target state, not the inventory. |
| `CBOM_SERIALNUMBER_NOT_REFRESHED` | error | With `--baseline`: components changed but `serialNumber` is identical. |
| `CBOM_TIMESTAMP_NOT_REFRESHED` | error | With `--baseline`: components changed but `metadata.timestamp` is identical. |
| `ACVP_ALGORITHM_NOT_IN_CBOM` | error | With `--acvp`: algorithm in the test report, not in the CBOM. |
| `CBOM_ALGORITHM_NOT_TESTED` | error | With `--acvp`: algorithm in the CBOM, not in the test report. |
| `ALGORITHM_NAME_MISMATCH` | error | With `--acvp`: same algorithm in both, spelled differently (e.g. `SHA-256` vs `SHA2-256`, `ECDH` vs `KAS-ECC`). Case is ignored. |
| `CBOM_CERTIN_ELEMENT_MISSING` | error | With `--profile cert-in`: an asset lacks a CERT-In CBOM minimum element. Algorithms: primitive, crypto functions, classical security level, OID, and mode for block ciphers / AE. Keys: ID, size, creation and activation date. Certificates: subject, issuer, validity, signature algorithm reference, format, extension. |
| `CBOM_WEAK_ALGORITHM` | error / warning | With `--profile weak` (NIST SP 800-131A Rev. 2, FIPS 186-5). Errors: MD5, Triple DES, RSA below 2048 bits. Warnings: SHA-1 (disallowed for signature generation, retired by 2030), DSA (verification only). |
| `CBOM_CNSA2_NOT_ALLOWED` | error | With `--profile cnsa2` (NSA CNSA 2.0): an algorithm outside AES-256, SHA-384/SHA-512, ML-KEM-1024, ML-DSA-87 and LMS/XMSS, e.g. AES-128, SHA-256, SHA-3, ML-KEM-768, SLH-DSA. AES without a stated key size counts as not allowed. |
| `CBOM_CNSA2_TRANSITIONAL` | warning (error with `--strict`) | With `--profile cnsa2`: a classical public-key algorithm (RSA, ECDSA, ECDH, EdDSA, X25519, DH, DSA), allowed only during the transition. |

Profiles combine: `--profile weak --profile cnsa2`. They judge which algorithms the CBOM
lists, not whether the CBOM is correct, so they are opt-in. Key sizes are read from the
algorithm name and `parameterSetIdentifier`; an RSA entry with no size is not judged.

The element list for `--profile cert-in` follows CERT-In's *Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM* v2.0 as summarised in published guides; check it against the official PDF before relying on it for a submission.

### Inventory

Every run also returns an inventory (`--inventory` prints it; `--json` and the web page always include it): one row per crypto asset with its quantum status:
- `vulnerable`: RSA, DSA, ECDSA, ECDH, EdDSA, X25519/X448 or DH, all broken by Shor's algorithm.
- `quantum-resistant`: ML-KEM, ML-DSA, SLH-DSA, LMS or XMSS.
- `hybrid`: both kinds in one asset.
- `symmetric/hash`: not broken by Shor.
- `unknown`: no algorithm recognised.

Certificates, keys and protocols take their status from the algorithm components they reference (e.g. `signatureAlgorithmRef`).

**ACVP reports** are vendor-specific, so the tool does not assume a format. It
walks the whole JSON (values and keys) looking for known algorithm name patterns.
If any match comes from a field whose own name contains `alg` (`algorithm`, `algo`,
`hashAlg`, ...), only those are used (parent names don't count, so a
`securityLevel: "AES-192 equivalent"` under `algorithms[0]` is ignored); otherwise every match is used. The output
lists every extracted name and the JSON field it came from, so you can see what
was compared.

### Changes since the previous CBOM

With `--baseline`, the result lists which components were added, removed or changed
(matched by `bom-ref`, or by name when there is none), alongside the serialNumber and
timestamp refresh checks.

### Bulk mode

Pass several CBOMs to check them in one run (e.g. `vendors/*.json`):

```
$ python cbom_check.py fixtures/clean.json fixtures/cnsa2_compliant.json fixtures/weak_algorithm.json --profile weak
cbom_check (bulk): 3 file(s), profile(s): weak
  PASS    0 error(s)   0 warning(s)  fixtures/clean.json
  PASS    0 error(s)   0 warning(s)  fixtures/cnsa2_compliant.json
  FAIL    1 error(s)   0 warning(s)  fixtures/weak_algorithm.json  [CBOM_WEAK_ALGORITHM]

  1 of 3 file(s) failed -> exit 1
```

The exit code is the worst file's (2 if any file could not be read). `--acvp` and
`--baseline` belong to one CBOM, so they are refused in bulk mode. The web page does the
same when several CBOMs are selected.

## What is not checked

- Whether the inventory is complete (the tool sees only the CBOM, not your code).
- Certificate contents, validity periods, or `classicalSecurityLevel`. Key sizes only through the
  `weak` and `cnsa2` profiles, and only where the size is in the algorithm name or `parameterSetIdentifier`.
- Whether an algorithm is *configured* safely (modes, padding, nonces).
- ACVP certificate authenticity; the report is only parsed for algorithm names.
- Algorithms outside the built-in name catalogue (see `_CATALOGUE` in `cbom_check.py`).
- XML CBOMs (JSON only).

## Limitation

`CBOM_ASSETTYPE_IMPLAUSIBLE` is a keyword heuristic and can be wrong; all other checks are deterministic.

## CI gate (GitHub Action)

```yaml
- uses: actaseal/cbom-check@v1   # or @main
  with:
    cbom: build/cbom.json
    acvp: reports/acvp.json        # optional
    baseline: previous/cbom.json   # optional
    profile: cert-in,cnsa2         # optional, comma-separated: cert-in, weak, cnsa2
    strict: "true"                 # optional
```

The job fails whenever the checker reports an error. Its log shows the findings and the inventory.

## Web version

`web/` builds a static page that runs the same `cbom_check.py` in the browser
through Pyodide (Python compiled to WebAssembly). Files are read locally and
never uploaded. Pyodide and every wheel are self-hosted, with versions and
hashes pinned, so the page makes no third-party requests.

```
python web/build.py        # writes web/dist/ (~16 MB), upload it to any static host
```

`.github/workflows/pages.yml` builds and deploys it to GitHub Pages on every
push to `main`.

## Tests

```
pip install -r requirements.txt pytest
pytest
```

`fixtures/` holds deliberately broken CBOMs, one per reason code, each otherwise
clean; the tests assert that exactly that code is reported and the exit code is
non-zero. `fixtures/clean.json` must exit 0, and one test asserts that a
schema-valid but semantically wrong CBOM passes the schema check and still fails
the tool.

## License

Apache-2.0
