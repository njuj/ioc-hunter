// Score extract() on ESET's public malware-ioc reports (158 READMEs with machine-readable ground truth):
//   git clone --depth 1 https://github.com/eset/malware-ioc ../eset
//   node scripts/eset-eval.mjs src/extract.js ../eset [--show]
// Hashes: samples.{md5,sha1,sha256} that also appear in the README. Network: every token ESET defanged with [.]
// (they defang all of theirs), so a domain, IP or URL found there is one they meant as an indicator.
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [lib, dir, flag] = process.argv.slice(2);
const { extract } = await import(pathToFileURL(resolve(lib)).href);

const IP = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const tally = { hash: [0, 0], domain: [0, 0], ip: [0, 0], url: [0, 0] };   // [found, total]
const missed = { hash: [], domain: [], ip: [], url: [] };
const extraDomains = new Map();
let noisy = 0;

for (const name of readdirSync(dir)) {
  const readme = join(dir, name, "README.adoc");
  if (!existsSync(readme)) continue;
  const raw = readFileSync(readme, "utf8");
  const text = raw;
  const unescaped = raw.replace(/\+\+/g, "");
  const r = extract(text, { includePrivate: true });
  const vals = (k) => new Set((r[k] || []).map((i) => i.value.toLowerCase()));
  const hashes = new Set([...vals("md5"), ...vals("sha1"), ...vals("sha256")]);
  const domains = vals("domains"), ips = vals("ipv4"), urls = vals("urls");
  const hosts = new Set([...urls].map((u) => { try { return new URL(u).hostname; } catch { return ""; } }));

  // hashes
  const low = unescaped.toLowerCase();
  for (const f of ["samples.md5", "samples.sha1", "samples.sha256"]) {
    const p = join(dir, name, f);
    if (!existsSync(p)) continue;
    for (const h of readFileSync(p, "utf8").split(/\s+/).map((s) => s.trim().toLowerCase()).filter(Boolean)) {
      if (!low.includes(h)) continue;
      tally.hash[1]++;
      if (hashes.has(h)) tally.hash[0]++; else missed.hash.push(`${name}: ${h}`);
    }
  }

  // defanged network tokens
  const truth = new Set();
  for (const m of unescaped.matchAll(/(?:h(?:xx|tt)ps?(?:\[:\]|:)\/\/)?[\w.-]*\[\.\][\w.\-\[\]]*(?:[/:][^\s`|<>"'\]]*)?/gi)) {
    let t = m[0].replace(/\[\.\]/g, ".").replace(/\[:\]/g, ":").replace(/^hxxp/i, "http").replace(/[.,;:)\]]+$/, "").replace(/^\./, "").replace(/\+$/, "");
    if (!t || truth.has(t)) continue;
    truth.add(t);
    const lt = t.toLowerCase();
    if (/^https?:\/\//.test(lt)) {
      tally.url[1]++;
      // a URL counts when extracted as a URL (path kept) - compare without trailing slash
      const ok = [...urls].some((u) => u.replace(/\/$/, "") === lt.replace(/\/$/, ""));
      if (ok) tally.url[0]++; else missed.url.push(`${name}: ${t}`);
    } else if (IP.test(lt.split(":")[0])) {
      tally.ip[1]++;
      if (ips.has(lt.split(":")[0])) tally.ip[0]++; else missed.ip.push(`${name}: ${t}`);
    } else if (/[a-z]/.test(lt) && !lt.includes("/")) {
      const host = lt.split(":")[0];
      tally.domain[1]++;
      if (domains.has(host) || hosts.has(host)) tally.domain[0]++; else missed.domain.push(`${name}: ${t}`);
    }
  }
  const truthHosts = new Set([...truth].map((t) => t.toLowerCase().replace(/^https?:\/\//, "").split(/[/:]/)[0]));
  for (const d of domains) {
    if (truthHosts.has(d) || [...truthHosts].some((h) => h.endsWith("." + d) || d.endsWith("." + h))) continue;
    noisy++;
    extraDomains.set(d, (extraDomains.get(d) || 0) + 1);
  }
}

const pct = ([a, b]) => `${a}/${b} (${b ? (100 * a / b).toFixed(1) : "-"}%)`;
console.log(`hashes  ${pct(tally.hash)}\ndomains ${pct(tally.domain)}\nIPs     ${pct(tally.ip)}\nURLs    ${pct(tally.url)}`);
console.log(`domains reported that ESET did not defang: ${noisy} (${extraDomains.size} distinct)`);
if (flag === "--show") {
  for (const k of Object.keys(missed)) {
    console.log(`\n-- missed ${k} (${missed[k].length})`);
    for (const m of missed[k].slice(0, 25)) console.log("  ", m);
  }
  console.log("\n-- top undefanged domains");
  console.log([...extraDomains].sort((a, b) => b[1] - a[1]).slice(0, 60).map(([d, n]) => `${d}:${n}`).join("  "));
}
