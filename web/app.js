// Runs cbom_check.py in the browser via Pyodide. Same code as the CLI;
// nothing is uploaded anywhere.
import { loadPyodide } from "./pyodide/pyodide.mjs";

const $ = (id) => document.getElementById(id);
const files = { cbom: null, acvp: null, baseline: null };
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

def web_check(cbom, acvp, baseline, strict):
    # Absent optional files arrive as a JS null, which is not None in Python.
    acvp = acvp if isinstance(acvp, str) else None
    baseline = baseline if isinstance(baseline, str) else None
    try:
        bom = _load(cbom, "CBOM", True)
        report = _load(acvp, "ACVP report", False) if acvp is not None else None
        base = _load(baseline, "baseline", True) if baseline is not None else None
    except ValueError as e:
        return json.dumps({"input_error": str(e), "summary": {"exit_code": 2}})
    return json.dumps(cbom_check.check(bom, report, base, strict))
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
  $("run").disabled = !(py && files.cbom);
}

function bindDrop(kind) {
  const zone = $(`drop-${kind}`);
  const input = zone.querySelector("input");
  const name = zone.querySelector(".fname");
  const clear = zone.querySelector(".clear");
  const set = async (file) => {
    files[kind] = file ? { name: file.name, text: await file.text() } : null;
    name.textContent = file ? file.name : "";
    zone.classList.toggle("has-file", !!file);
    if (!file) input.value = "";
    updateButton();
  };
  input.addEventListener("change", () => set(input.files[0] || null));
  clear.addEventListener("click", (e) => { e.preventDefault(); set(null); });
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("over");
    if (e.dataTransfer.files[0]) set(e.dataTransfer.files[0]);
  });
  zone._set = (name_, text) => {
    files[kind] = { name: name_, text };
    name.textContent = name_;
    zone.classList.add("has-file");
    updateButton();
  };
}

function run() {
  const fn = py.globals.get("web_check");
  const out = fn(files.cbom.text, files.acvp?.text, files.baseline?.text, $("strict").checked);
  fn.destroy();
  lastResult = JSON.parse(out);
  render(lastResult);
}

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v; else n.setAttribute(k, v);
  }
  for (const c of children) n.append(c);
  return n;
}

function render(r) {
  const box = $("results");
  box.replaceChildren();
  box.hidden = false;
  const code = r.summary.exit_code;

  if (r.input_error) {
    box.append(el("div", { class: "verdict fail" },
      el("strong", {}, "Input error"), el("span", {}, `exit 2 · ${r.input_error}`)));
    box.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }

  const s = r.summary;
  box.append(el("div", { class: `verdict ${code ? "fail" : "pass"}` },
    el("strong", {}, code ? "FAIL" : "PASS"),
    el("span", {}, `exit ${code} · ${s.errors} error(s), ${s.warnings} warning(s)` +
      (s.strict ? " · strict: warnings count as errors" : ""))));

  box.append(el("div", { class: `schema ${r.schema.valid ? "ok" : "bad"}` },
    el("div", {}, el("strong", {}, "CycloneDX 1.6 schema: "), r.schema.valid ? "PASS" : "FAIL"),
    el("p", { class: "note" }, r.schema.note)));

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
  box.scrollIntoView({ behavior: "smooth", block: "start" });
}

function download() {
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: "application/json" });
  const a = el("a", { href: URL.createObjectURL(blob), download: "cbom-check-result.json" });
  a.click();
  URL.revokeObjectURL(a.href);
}

for (const k of Object.keys(files)) bindDrop(k);
$("run").addEventListener("click", () => {
  try { run(); $("dl").hidden = false; } catch (e) { alert(e.message); console.error(e); }
});
$("dl").addEventListener("click", download);
document.querySelectorAll("[data-sample]").forEach((b) => b.addEventListener("click", async () => {
  const name = b.dataset.sample;
  const text = await (await fetch(`./samples/${name}`)).text();
  $("drop-cbom")._set(name, text);
  if (py) { run(); $("dl").hidden = false; }
}));
boot();
