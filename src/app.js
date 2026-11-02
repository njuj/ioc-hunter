import { CATEGORIES, count, defang, extract, lookups, toCSV, toJSON } from "./extract.js";
import { SAMPLE } from "./sample.js";

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const $ = (selector) => document.querySelector(selector);

const input = $("#input");
const results = $("#results");
const summary = $("#summary");
const stats = $("#stats");
const optDefang = $("#opt-defang");
const optPrivate = $("#opt-private");
let current = extract("");

// Every piece of pasted text reaches the DOM through text nodes — never innerHTML.
// This page parses hostile input by design, so it must not become an XSS vector itself.
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (name.startsWith("on")) node.addEventListener(name.slice(2), value);
    else node.setAttribute(name, value);
  }
  node.append(...children.filter((c) => c !== null));
  return node;
}

const shown = (key, value) => (optDefang.checked ? defang(value, key) : value);

function render() {
  const started = performance.now();
  current = extract(input.value, { includePrivate: optPrivate.checked });
  const elapsed = performance.now() - started;
  const total = count(current);

  summary.replaceChildren();
  results.replaceChildren();
  for (const { key, label } of CATEGORIES) {
    const items = current[key];
    if (!items.length) continue;
    summary.append(el("a", { class: "chip", href: `#cat-${key}` }, `${label} `, el("b", {}, String(items.length))));

    const list = el("ul", { class: "ioc-list" });
    for (const item of items) {
      const pivots = lookups(key, item.value).map(([name, url]) =>
        el("a", { class: "lookup", href: url, target: "_blank", rel: "noopener noreferrer" }, name));
      list.append(el("li", {},
        el("code", {}, shown(key, item.value)),
        item.note ? el("span", { class: "note" }, item.note) : null,
        pivots.length ? el("span", { class: "lookups" }, ...pivots) : null));
    }
    const copy = el("button", { type: "button", class: "ghost", "data-label": "copy" }, "copy");
    copy.addEventListener("click", () => copyText(items.map((i) => shown(key, i.value)).join("\n"), copy));
    results.append(el("section", { class: "card", id: `cat-${key}` },
      el("header", {}, el("h3", {}, label, el("span", { class: "count" }, String(items.length))), copy),
      list));
  }

  stats.textContent = total
    ? `${total} indicator${total === 1 ? "" : "s"} · ${elapsed.toFixed(1)} ms · 0 bytes sent`
    : "";
  summary.hidden = total === 0;
  $("#empty").hidden = total > 0;
  $("#exports").hidden = total === 0;
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    flash(button, "copied ✓");
  } catch {
    flash(button, "blocked");
  }
}

function flash(button, message) {
  button.textContent = message;
  setTimeout(() => { button.textContent = button.dataset.label; }, 1200);
}

function download(filename, mime, text) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const link = el("a", { href: url, download: filename });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function loadFile(file) {
  if (!file) return;
  if (file.size > MAX_FILE_BYTES) {
    stats.textContent = `${file.name} is larger than 5 MB`;
    return;
  }
  input.value = await file.text();
  render();
}

function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

input.addEventListener("input", debounce(render, 120));
optDefang.addEventListener("change", render);
optPrivate.addEventListener("change", render);

$("#sample").addEventListener("click", () => { input.value = SAMPLE; render(); input.focus(); });
$("#clear").addEventListener("click", () => { input.value = ""; render(); input.focus(); });
$("#open").addEventListener("click", () => $("#file").click());
$("#file").addEventListener("change", (e) => loadFile(e.target.files[0]));

const stamp = () => new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
$("#dl-json").addEventListener("click", () =>
  download(`iocs-${stamp()}.json`, "application/json", toJSON(current, { defanged: optDefang.checked })));
$("#dl-csv").addEventListener("click", () =>
  download(`iocs-${stamp()}.csv`, "text/csv", toCSV(current, { defanged: optDefang.checked })));
$("#copy-all").addEventListener("click", (e) => {
  const lines = CATEGORIES.flatMap(({ key }) => current[key].map((i) => shown(key, i.value)));
  copyText(lines.join("\n"), e.currentTarget);
});

const panel = $("#input-panel");
panel.addEventListener("dragover", (e) => { e.preventDefault(); panel.classList.add("drop-active"); });
panel.addEventListener("dragleave", () => panel.classList.remove("drop-active"));
panel.addEventListener("drop", (e) => {
  e.preventDefault();
  panel.classList.remove("drop-active");
  loadFile(e.dataTransfer.files[0]);
});

render();
