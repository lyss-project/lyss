// In-browser LYSS audit: the LYSS engine (Python) runs on Pyodide, served from this site.
// The configuration stays in the page: no request carries it, and the site's
// Content-Security-Policy (connect-src 'self') forbids any other server anyway.
// Every text from the configuration or the results is inserted with textContent, never as HTML.
const PYODIDE_VERSION = "314.0.7";   // files in py/, pinned by tools/build_web_audit.py
const PY = new URL("py/", document.baseURI).href;
const MAX_BYTES = 5 * 1024 * 1024;

const PLATFORMS = {
  arista_eos: "Arista EOS", aruba_aoscx: "HPE Aruba AOS-CX", zyxel_gs1900: "Zyxel GS1900", cisco_ios: "Cisco IOS / IOS-XE", cisco_sb: "Cisco Small Business / Business",
  hp_procurve: "HPE Aruba AOS-S", huawei_vrp: "Huawei S series (VRP)", juniper_junos: "Juniper EX (Junos)", mikrotik: "MikroTik RouterOS", sonic: "SONiC",
};
const EXAMPLES = ["mikrotik.rsc", "cisco_ios.cfg", "zyxel_gs1900.txt", "arista_eos.cfg", "aruba_aoscx.cfg", "huawei_vrp.cfg", "juniper_junos.cfg", "sonic.json", "hp_procurve.cfg", "cisco_sb.cfg"];
const VERDICTS = {
  fail: ["Failed", "Non conforme"], unknown: ["Unknown", "Inconnu"],
  pass: ["Passed", "Conforme"], not_applicable: ["Not applicable", "Non applicable"],
};

const $ = (id) => document.getElementById(id);
const form = $("audit-form"), config = $("config"), state = $("state"), status = $("status");
const results = $("results"), runButton = $("run");
let engine = null, exampleIndex = 0;

// a bilingual text: <span class="en">…</span><span class="fr">…</span> (lang.js / style.css switch them)
function bi(en, fr, tag = "span") {
  const wrap = document.createElement(tag);
  for (const [cls, text] of [["en", en], ["fr", fr]]) {
    const s = document.createElement("span");
    s.className = cls;
    s.textContent = text;
    wrap.appendChild(s);
  }
  return wrap;
}

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function say(en, fr, kind = "") {
  status.className = "msg" + (kind ? " msg-" + kind : "");
  status.replaceChildren(...bi(en, fr).childNodes);
}

async function load() {
  say("Loading LYSS in your browser (about 14 MB the first time)…",
      "Chargement de LYSS dans votre navigateur (environ 14 Mo la première fois)…", "busy");
  const { loadPyodide } = await import("./py/pyodide.mjs");
  const pyodide = await loadPyodide({ indexURL: PY, stdout: () => {}, stderr: () => {} });
  await pyodide.loadPackage("pyyaml", { messageCallback: () => {}, errorCallback: () => {} });
  const bundle = await fetch(PY + "lyss-web.zip", { cache: "no-cache" });
  if (!bundle.ok) throw new Error("lyss-web.zip: HTTP " + bundle.status);
  pyodide.unpackArchive(await bundle.arrayBuffer(), "zip", { extractDir: "/lyss" });
  pyodide.runPython("import os, sys\nos.environ['LYSS_HOME'] = '/lyss/home'\nsys.path.insert(0, '/lyss')");
  const browser = pyodide.pyimport("lyss.browser");
  return {
    run: (text, vendor, level, stateText) => JSON.parse(browser.run(text, vendor, level, stateText)),
    example: (name) => pyodide.FS.readFile("/lyss/examples/" + name, { encoding: "utf8" }),
  };
}

function boot() {
  if (!engine) {
    engine = load().then(
      (e) => { say("LYSS is ready.", "LYSS est prêt.", "ok"); return e; },
      (err) => {
        engine = null;
        console.error(err);
        say("LYSS could not start in this browser (" + err.message + "). Use a recent Chrome, Edge, Firefox or Safari, or the command line: pip install lyss.",
            "LYSS n'a pas pu démarrer dans ce navigateur (" + err.message + "). Utilisez un Chrome, Edge, Firefox ou Safari récent, ou la ligne de commande : pip install lyss.", "error");
        throw err;
      });
  }
  return engine;
}

// start downloading as soon as the visitor shows interest, not on every page view
for (const node of [config, $("example"), $("file")]) {
  node.addEventListener("focus", () => boot().catch(() => {}), { once: true });
}

function readFile(file) {
  return new Promise((resolve, reject) => {
    if (file.size > MAX_BYTES) { reject(new Error("too large")); return; }
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

// one configuration file, plus optionally its <name>.state.txt (same convention as lyss audit)
async function takeFiles(files) {
  const list = Array.from(files || []);
  if (!list.length) return;
  try {
    const stateFile = list.find((f) => /\.state\.txt$/i.test(f.name));
    const configFile = list.find((f) => f !== stateFile);
    if (configFile) config.value = await readFile(configFile);
    if (stateFile) { state.value = await readFile(stateFile); state.closest("details").open = true; }
    say("File loaded: " + (configFile || stateFile).name + ". Nothing has been sent.",
        "Fichier chargé : " + (configFile || stateFile).name + ". Rien n'a été envoyé.", "ok");
    boot().catch(() => {});
  } catch (err) {
    say("This file could not be read (" + err.message + ", 5 MB maximum).",
        "Ce fichier n'a pas pu être lu (" + err.message + ", 5 Mo maximum).", "error");
  }
}

$("file").addEventListener("change", (ev) => { takeFiles(ev.target.files); ev.target.value = ""; });
config.addEventListener("dragover", (ev) => { ev.preventDefault(); config.classList.add("drop"); });
config.addEventListener("dragleave", () => config.classList.remove("drop"));
config.addEventListener("drop", (ev) => {
  ev.preventDefault();
  config.classList.remove("drop");
  takeFiles(ev.dataTransfer.files);
});

$("example").addEventListener("click", async () => {
  let e;
  try { e = await boot(); } catch { return; }
  const name = EXAMPLES[exampleIndex++ % EXAMPLES.length];
  config.value = e.example(name);
  state.value = "";
  $("vendor").value = "auto";
  say("Example loaded: a fictitious " + PLATFORMS[name.split(".")[0]] + " configuration. Click Audit.",
      "Exemple chargé : une configuration " + PLATFORMS[name.split(".")[0]] + " fictive. Cliquez sur Auditer.", "ok");
});

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!config.value.trim()) {
    say("Paste a configuration first, open a file or try an example.",
        "Collez d'abord une configuration, ouvrez un fichier ou essayez un exemple.", "error");
    config.focus();
    return;
  }
  runButton.disabled = true;
  try {
    const e = await boot();
    say("Auditing…", "Audit en cours…", "busy");
    await new Promise((r) => setTimeout(r, 30));   // let the message paint
    const result = e.run(config.value, $("vendor").value, Number($("level").value), state.value);
    if (!result.ok) {
      const messages = {
        unrecognised: ["The platform was not recognised from this text. Choose it in the Platform list.",
                       "La plateforme n'a pas été reconnue dans ce texte. Choisissez-la dans la liste Plateforme."],
        empty: ["The configuration is empty.", "La configuration est vide."],
        vendor: ["Unknown platform.", "Plateforme inconnue."],
      }[result.error] || [result.error, result.error];
      say(messages[0], messages[1], "error");
      results.hidden = true;
      return;
    }
    render(result);
    say("Done. Nothing left your browser.", "Terminé. Rien n'a quitté votre navigateur.", "ok");
    results.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    if (engine) {
      console.error(err);
      say("The audit failed: " + err.message, "L'audit a échoué : " + err.message, "error");
    }
  } finally {
    runButton.disabled = false;
  }
});

function render(r) {
  const s = r.summary;
  const head = el("div", "result-head");
  const title = el("div");
  title.appendChild(bi("Result", "Résultat", "h2"));
  const platform = el("p", "small");
  platform.append(PLATFORMS[r.vendor] || r.vendor);
  if (r.support === "preview") platform.append(bi(" · preview: verdicts may still change", " · préversion : les verdicts peuvent encore changer"));
  if (r.detected) platform.append(bi(" · detected automatically", " · détectée automatiquement"));
  platform.append(" · LYSS " + r.version + " · spec " + r.spec_version);
  title.appendChild(platform);
  const level = el("span", "lvl " + (s.achieved_level ? "l-ok" : "l0"));
  level.append(bi("Level " + s.achieved_level, "Niveau " + s.achieved_level));
  head.append(title, level);

  const counts = el("div", "counts");
  for (const [key, n] of [["fail", s.fail], ["unknown", s.unknown], ["pass", s.pass]]) {
    const c = el("span", "count count-" + key);
    c.append(el("strong", "", String(n)), bi(VERDICTS[key][0], VERDICTS[key][1]));
    counts.appendChild(c);
  }

  const groups = el("div", "findings");
  for (const verdict of ["fail", "unknown", "pass", "not_applicable"]) {
    const items = r.findings.filter((f) => f.verdict === verdict);
    if (!items.length) continue;
    groups.appendChild(bi(VERDICTS[verdict][0] + " (" + items.length + ")",
                          VERDICTS[verdict][1] + " (" + items.length + ")", "h3"));
    for (const f of items) groups.appendChild(finding(f));
  }

  const explain = bi(
    "Unknown means the configuration alone cannot decide: LYSS never guesses. Add the device state above, or let LYSS read the switch itself (read-only) with the full tool.",
    "Inconnu signifie que la configuration seule ne permet pas de décider : LYSS ne devine jamais. Ajoutez l'état de l'équipement ci-dessus, ou laissez LYSS lire le switch lui-même (lecture seule) avec l'outil complet.", "p");
  explain.className = "small";
  results.replaceChildren(head, counts, explain, groups);
  results.hidden = false;
}

function finding(f) {
  const d = el("details", "finding f-" + f.verdict);
  d.open = f.verdict === "fail";
  const sum = el("summary");
  sum.append(el("span", "pill pill-" + f.verdict, { fail: "FAIL", unknown: "?", pass: "PASS", not_applicable: "N/A" }[f.verdict]),
             el("code", "", f.control_id.replace(/^LYSS-/, "")), el("span", "f-title", f.title),
             el("span", "f-level", "L" + f.level + (f.advisory ? " · advisory" : "")));
  d.appendChild(sum);
  const body = el("div", "f-body");
  if (f.evidence && f.evidence.length) {
    body.appendChild(bi("Evidence", "Preuve", "h4"));
    const ul = el("ul", "evidence");
    for (const line of f.evidence) ul.appendChild(el("li", "", line));
    body.appendChild(ul);
  }
  if (f.note) body.appendChild(el("p", "f-note", f.note));
  if (f.remediation && f.verdict !== "pass") {
    body.appendChild(bi("Fix", "Correction", "h4"));
    body.appendChild(el("pre", "fix", f.remediation));
  }
  d.appendChild(body);
  return d;
}
