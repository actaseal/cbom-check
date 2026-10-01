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
python cbom_check.py <cbom.json> [--acvp <report.json>] [--baseline <previous_cbom.json>] [--strict] [--json]
```

Example:

```
$ python cbom_check.py fixtures/nist_level_mismatch.json
cbom_check: fixtures/nist_level_mismatch.json
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
ACVP extraction details, summary with `exit_code`).

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
| `CBOM_SCHEMA_INVALID` | error | Baseline only: CycloneDX 1.6 JSON schema (via `jsonschema` and the schema bundled in `cyclonedx-python-lib`). Passing this says nothing about the checks below. |
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

**ACVP reports** are vendor-specific, so the tool does not assume a format. It
walks the whole JSON (values and keys) looking for known algorithm name patterns.
If any match comes from a field whose own name contains `alg` (`algorithm`, `algo`,
`hashAlg`, ...), only those are used (parent names don't count, so a
`securityLevel: "AES-192 equivalent"` under `algorithms[0]` is ignored); otherwise every match is used. The output
lists every extracted name and the JSON field it came from, so you can see what
was compared.

## What is not checked

- Whether the inventory is complete (the tool sees only the CBOM, not your code).
- Certificate contents, key lengths, validity periods, or `classicalSecurityLevel`.
- Whether an algorithm is *configured* safely (modes, padding, nonces).
- ACVP certificate authenticity; the report is only parsed for algorithm names.
- Algorithms outside the built-in name catalogue (see `_CATALOGUE` in `cbom_check.py`).
- XML CBOMs (JSON only).

## Limitation

`CBOM_ASSETTYPE_IMPLAUSIBLE` is a keyword heuristic and can be wrong; all other checks are deterministic.

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
