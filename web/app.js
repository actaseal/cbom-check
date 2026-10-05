// Runs cbom_check.py in the browser via Pyodide. Same code as the CLI;
// nothing is uploaded anywhere.
import { loadPyodide } from "./pyodide/pyodide.mjs";

const $ = (id) => document.getElementById(id);
// cbom holds one or more files (several = bulk mode); the others hold one.
const files = { cbom: [], acvp: [], baseline: [] };
let py = null;
let lastResult = null;

const GLUE = `
import json, sys
sys.path.insert(0, "/home/pyodide")
import cbom_check

def _load(text, what, must_be_object):
    try:
        value = json.loads(text.lstrip("\\ufeff"))
    except ValueError as e:
        raise ValueError(f"cannot parse {what}: {e}")
    if must_be_object and not isinstance(value, dict):
        raise ValueError(f"{what} top level is not a JSON object")
    return value

def web_check(cbom, acvp, baseline, strict, profiles_json, hashes_json):
    # Absent optional files arrive as a JS null, which is not None in Python.
    acvp = acvp if isinstance(acvp, str) else None
    baseline = baseline if isinstance(baseline, str) else None
    try:
        bom = _load(cbom, "CBOM", True)
        report = _load(acvp, "ACVP report", False) if acvp is not None else None
        base = _load(baseline, "baseline", True) if baseline is not None else None
    except ValueError as e:
        return json.dumps({"input_error": str(e), "summary": {"exit_code": 2}})
    return json.dumps(cbom_check.check(bom, report, base, strict, json.loads(profiles_json),
                                       json.loads(hashes_json)))
`;

async function boot() {
  const status = $("engine");
  try {
    const deps = await (await fetch("./deps.json")).json();
    py = await loadPyodide({ indexURL: new URL("./pyodide/", location.href).href });
    status.textContent = "Loading checker…";
    await py.loadPackage(deps.pyodide, { messageCallback: () => {} });
    await py.loadPackage(deps.wheels.map((w) => new URL(`./wheels/${w}`, location.href).href),
      { messageCallback: () => {} });
    const src = await (await fetch("./cbom_check.py")).text();
    py.FS.mkdirTree("/home/pyodide");
    py.FS.writeFile("/home/pyodide/cbom_check.py", src);
    py.runPython(GLUE);
    status.textContent = "Ready. Runs in your browser; files are not uploaded.";
    status.dataset.state = "ready";
  } catch (e) {
    status.textContent = `Could not load the checker: ${e.message}`;
    status.dataset.state = "error";
    console.error(e);
  }
  updateButton();
}

function updateButton() {
  $("run").disabled = !(py && files.cbom.length);
  const bulk = files.cbom.length > 1;
  $("bulk-note").hidden = !bulk;
  for (const k of ["acvp", "baseline"]) $(`drop-${k}`).classList.toggle("disabled", bulk);
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// The hash covers the file's exact bytes (a UTF-8 BOM included), the same
// bytes the CLI hashes, so both report the same sha256 for the same file.
async function readFile(file) {
  const bytes = await file.arrayBuffer();
  return { name: file.name, text: new TextDecoder("utf-8").decode(bytes), sha256: await sha256Hex(bytes) };
}

function bindDrop(kind, multiple) {
  const zone = $(`drop-${kind}`);
  const input = zone.querySelector("input");
  const name = zone.querySelector(".fname");
  const clear = zone.querySelector(".clear");
  const show = () => {
    const list = files[kind];
    name.textContent = list.length > 1 ? `${list.length} files: ${list.map((f) => f.name).join(", ")}`
      : (list[0]?.name ?? "");
    zone.classList.toggle("has-file", list.length > 0);
    updateButton();
  };
  const set = async (fileList) => {
    const picked = [...(fileList || [])].slice(0, multiple ? undefined : 1);
    files[kind] = await Promise.all(picked.map(readFile));
    if (!picked.length) input.value = "";
    show();
  };
  input.addEventListener("change", () => set(input.files));
  clear.addEventListener("click", (e) => { e.preventDefault(); set([]); });
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("over");
    if (e.dataTransfer.files.length) set(e.dataTransfer.files);
  });
  zone._set = (entry) => { files[kind] = [entry]; show(); };
}

function profiles() {
  return [...document.querySelectorAll("input[data-profile]")].filter((b) => b.checked)
    .map((b) => b.dataset.profile);
}

function checkOne(cbom, acvp, baseline) {
  const fn = py.globals.get("web_check");
  const hashes = { cbom: cbom.sha256 };
  if (acvp) hashes.acvp = acvp.sha256;
  if (baseline) hashes.baseline = baseline.sha256;
  const out = fn(cbom.text, acvp?.text, baseline?.text, $("strict").checked,
    JSON.stringify(profiles()), JSON.stringify(hashes));
  fn.destroy();
  return { cbom: cbom.name, ...JSON.parse(out) };
}

function run() {
  if (files.cbom.length === 1) {
    lastResult = checkOne(files.cbom[0], files.acvp[0], files.baseline[0]);
    render(lastResult);
    return;
  }
  const results = files.cbom.map((f) => checkOne(f, null, null));
  const code = (r) => r.summary.exit_code;
  const unreadable = results.filter((r) => code(r) === 2).length;
  const failed = results.filter((r) => code(r) === 1).length;
  lastResult = {
    tool: results.find((r) => r.tool)?.tool,
    results,
    summary: { files: results.length, passed: results.length - failed - unreadable, failed, unreadable,
      exit_code: unreadable ? 2 : failed ? 1 : 0 },
  };
  renderBulk(lastResult);
}

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v; else n.setAttribute(k, v);
  }
  for (const c of children) n.append(c);
  return n;
}

const PROFILE_NAMES = { "cert-in": "CERT-In profile", weak: "weak-algorithm profile", cnsa2: "CNSA 2.0 profile" };

function verdictLine(r) {
  const s = r.summary;
  const code = s.exit_code;
  return el("div", { class: `verdict ${code ? "fail" : "pass"}` },
    el("strong", {}, code ? "FAIL" : "PASS"),
    el("span", {}, `exit ${code} · ${s.errors} error(s), ${s.warnings} warning(s)` +
      (s.strict ? " · strict: warnings count as errors" : "") +
      (s.profiles || []).map((p) => ` · ${PROFILE_NAMES[p] || p}`).join("")));
}

// Everything about one checked CBOM, appended to `box`.
function renderDetail(box, r) {
  if (r.input_error) {
    box.append(el("div", { class: "verdict fail" },
      el("strong", {}, "Input error"), el("span", {}, `exit 2 · ${r.input_error}`)));
    return;
  }
  box.append(verdictLine(r));

  box.append(el("div", { class: `schema ${r.schema.valid ? "ok" : "bad"}` },
    el("div", {}, el("strong", {}, `CycloneDX ${r.schema.version ?? "?"} schema: `), r.schema.valid ? "PASS" : "FAIL"),
    el("p", { class: "note" }, r.schema.note)));

  if (r.baseline_diff) {
    const d = r.baseline_diff;
    const list = el("ul", { class: "diff" });
    for (const [kind, sign] of [["added", "+"], ["removed", "−"], ["changed", "~"]]) {
      for (const name of d[kind]) list.append(el("li", { class: `d-${kind}` }, `${sign} ${name}`));
    }
    if (!list.children.length) list.append(el("li", {}, "No component changed."));
    box.append(el("details", { class: "extract", open: "" },
      el("summary", {}, `Since the previous CBOM: ${d.added.length} added, ${d.removed.length} removed, ` +
        `${d.changed.length} changed`), list));
  }

  if (r.acvp_extraction) {
    const ex = r.acvp_extraction;
    const tbody = el("tbody");
    for (const a of ex.algorithms) {
      tbody.append(el("tr", {}, el("td", {}, a.name),
        el("td", {}, a.raw_value === a.name ? "" : a.raw_value), el("td", { class: "mono" }, a.field)));
    }
    if (!ex.algorithms.length) {
      tbody.append(el("tr", {}, el("td", { colspan: "3" }, "No known algorithm names found.")));
    }
    box.append(el("details", { class: "extract" },
      el("summary", {}, `ACVP report: ${ex.algorithms.length} algorithm name(s) taken from ${ex.strategy}`),
      el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, "Name"), el("th", {}, "In value"), el("th", {}, "Field"))),
        tbody))));
  }

  const list = el("div", { class: "findings" });
  if (!r.findings.length) list.append(el("p", { class: "empty" }, "No semantic findings."));
  for (const f of r.findings) {
    list.append(el("article", { class: `finding ${f.severity}` },
      el("header", {},
        el("span", { class: "sev" }, f.severity + (f.promoted_by_strict ? " (strict)" : "")),
        el("code", {}, f.code)),
      el("div", { class: "loc mono" }, f.location),
      el("p", {}, f.message)));
  }
  box.append(list);

  if (r.inventory && r.inventory.length) {
    const counts = {};
    for (const row of r.inventory) counts[row.quantum] = (counts[row.quantum] || 0) + 1;
    const tbody = el("tbody");
    for (const row of r.inventory) {
      tbody.append(el("tr", {},
        el("td", {}, el("span", { class: `q q-${row.quantum.replace(/[^a-z]/g, "")}` }, row.quantum)),
        el("td", {}, row.name),
        el("td", {}, row.asset_type || "?"),
        el("td", {}, (row.algorithms.join(", ") || "–") + (row.via.length ? ` (via ${row.via.join(", ")})` : "")),
        el("td", {}, row.parameter_set_or_size == null ? "" : String(row.parameter_set_or_size))));
    }
    const summary = Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(" · ");
    box.append(el("details", { class: "extract", open: "" },
      el("summary", {}, `Inventory: ${summary}`),
      el("p", { class: "hint" }, "Vulnerable = broken by a quantum computer running Shor's algorithm (RSA, ECC, DH). " +
        "Certificates, keys and protocols take their algorithms from the components they reference."),
      el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, "Quantum"), el("th", {}, "Asset"), el("th", {}, "Type"),
          el("th", {}, "Algorithms"), el("th", {}, "Param set / size"))),
        tbody))));
  }

  if (r.inputs) {
    const rows = Object.entries(r.inputs).map(([k, v]) =>
      el("tr", {}, el("td", {}, k), el("td", { class: "mono" }, v.sha256)));
    box.append(el("details", { class: "extract" },
      el("summary", {}, `Exact inputs (SHA-256) · ${r.tool.name} ${r.tool.version}`),
      el("p", { class: "hint" }, "The downloaded result names these hashes, so anyone can re-run the same files " +
        "and get the same result."),
      el("div", { class: "table-wrap" }, el("table", {}, el("tbody", {}, ...rows)))));
  }
}

function render(r) {
  const box = $("results");
  box.replaceChildren();
  box.hidden = false;
  renderDetail(box, r);
  box.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderBulk(doc) {
  const box = $("results");
  box.replaceChildren();
  box.hidden = false;
  const s = doc.summary;
  box.append(el("div", { class: `verdict ${s.exit_code ? "fail" : "pass"}` },
    el("strong", {}, s.exit_code ? "FAIL" : "PASS"),
    el("span", {}, `${s.files} CBOMs · ${s.passed} passed, ${s.failed} failed` +
      (s.unreadable ? `, ${s.unreadable} unreadable` : "") + ` · exit ${s.exit_code}`)));
  const tbody = el("tbody");
  for (const r of doc.results) {
    const code = r.summary.exit_code;
    const codes = [...new Set((r.findings || []).filter((f) => f.severity === "error").map((f) => f.code))];
    tbody.append(el("tr", {},
      el("td", {}, el("span", { class: `q ${code ? "q-vulnerable" : "q-quantumresistant"}` },
        code === 2 ? "ERROR" : code ? "FAIL" : "PASS")),
      el("td", {}, r.cbom),
      el("td", {}, r.input_error ? "–" : `${r.summary.errors} / ${r.summary.warnings}`),
      el("td", { class: "mono" }, r.input_error || codes.join(", "))));
  }
  box.append(el("div", { class: "table-wrap" }, el("table", {},
    el("thead", {}, el("tr", {}, el("th", {}, "Result"), el("th", {}, "File"), el("th", {}, "Errors / warnings"),
      el("th", {}, "Error codes"))),
    tbody)));
  for (const r of doc.results) {
    const d = el("details", { class: "file" }, el("summary", {}, r.cbom));
    const inner = el("div", { class: "file-detail" });
    renderDetail(inner, r);
    d.append(inner);
    box.append(d);
  }
  box.scrollIntoView({ behavior: "smooth", block: "start" });
}

function download() {
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: "application/json" });
  const a = el("a", { href: URL.createObjectURL(blob), download: "cbom-check-result.json" });
  a.click();
  URL.revokeObjectURL(a.href);
}

bindDrop("cbom", true);
bindDrop("acvp", false);
bindDrop("baseline", false);
$("run").addEventListener("click", () => {
  try { run(); $("dl").hidden = false; } catch (e) { alert(e.message); console.error(e); }
});
$("dl").addEventListener("click", download);
document.querySelectorAll("[data-sample]").forEach((b) => b.addEventListener("click", async () => {
  const name = b.dataset.sample;
  const bytes = await (await fetch(`./samples/${name}`)).arrayBuffer();
  $("drop-cbom")._set({ name, text: new TextDecoder("utf-8").decode(bytes), sha256: await sha256Hex(bytes) });
  if (py) { run(); $("dl").hidden = false; }
}));
boot();
