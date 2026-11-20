// Pure extraction logic — no DOM, so the exact same module runs (and is tested) in Node and the browser.
import { TLD_LIST } from "./tlds.js";

export const CATEGORIES = [
  { key: "urls", label: "URLs" },
  { key: "domains", label: "Domains" },
  { key: "ipv4", label: "IPv4" },
  { key: "ipv6", label: "IPv6" },
  { key: "cidr", label: "IP ranges" },
  { key: "emails", label: "E-mails" },
  { key: "sha512", label: "SHA-512" },
  { key: "sha256", label: "SHA-256" },
  { key: "sha1", label: "SHA-1" },
  { key: "md5", label: "MD5" },
  { key: "files", label: "File names" },
  { key: "cves", label: "CVEs" },
  { key: "attack", label: "MITRE ATT&CK" },
  { key: "bitcoin", label: "Bitcoin" },
  { key: "paths", label: "File paths" },
  { key: "registry", label: "Registry keys" },
];

// Every TLD in the IANA root zone, plus .onion (special-use, not in the root).
export const TLDS = new Set([...TLD_LIST.trim().split(/\s+/), "onion"]);

// Without a defang or URL / e-mail around it, a name must end in a TLD that real indicators use: every
// two-letter country code plus these. The rest of the root zone (.name, .group, .read, .data ...) collides
// with code ("self.name", "m.group(1)") far more often than it shows up in reports undefanged.
export const COMMON_TLDS = new Set([...[...TLDS].filter((t) => t.length === 2), ...(
  "com net org info biz xyz top club online site website space tech store shop link click fun icu rest bar buzz " +
  "cam monster cyou sbs lol cloud host digital network email news blog world today page onion live app dev gov " +
  "edu mil int pro mobi asia vip win bid loan men date review trade party science stream download racing work " +
  "kim ink xin lat bond cfd quest beauty pics best guru life services support center solutions systems tools " +
  "software company agency global center press social chat"
).split(" ")]);

// TLDs that are also file extensions: "invoice.zip" or "setup.py" is a file unless the text says otherwise
// (defanged, or the host of a URL / e-mail). Three labels or more ("cdn.evil.zip") stays a domain.
// Not .ai or .pl: Illustrator and Perl files are rarer in reports than .ai and Polish domains (totokupdate.ai).
export const FILE_TLDS = new Set("zip mov app one sh py so md rs ps cab dot".split(" "));

// File types worth reporting by name in a report (droppers, documents, archives, scripts).
const FILE_EXT = "exe|dll|sys|scr|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|hta|lnk|msi|msix|iso|img|vhdx?|docx?|docm|" +
  "xlsx?|xlsm|xlsb|pptx?|pptm|pdf|rtf|one|zip|rar|7z|jar|apk|dmg|so|py|sh|elf|cpl|ocx|chm|scf|url|xll";

const FILE_EXT_RX = new RegExp(`^(?:${FILE_EXT})$`, "i");

// Reference sites that appear in nearly every report's footnotes: hidden, URLs to them too.
const REFERENCE = new Set((
  "welivesecurity.com eset.com esetstatic.com mitre.org misp-project.org snort.org suricata-ids.org " +
  "emergingthreats.net nist.gov cisa.gov cve.org first.org ietf.org rfc-editor.org w3.org virustotal.com " +
  "abuse.ch urlscan.io shodan.io abuseipdb.com otx.alienvault.com wikipedia.org mandiant.com crowdstrike.com paloaltonetworks.com securelist.com kaspersky.com " +
  "sophos.com talosintelligence.com proofpoint.com recordedfuture.com sentinelone.com trendmicro.com " +
  "checkpoint.com bleepingcomputer.com thehackernews.com therecord.media plusvic.github.io eset.sk"
).split(" "));
// Platforms attackers also host on: only the bare site is hidden. Subdomains and URLs with a path are kept,
// because raw.githubusercontent.com/... or drive.google.com/... can be the payload.
const PLATFORM = new Set((
  "github.com google.com microsoft.com apple.com amazon.com cloudflare.com dropbox.com discord.com " +
  "telegram.org t.me office.com live.com outlook.com bing.com yandex.ru mozilla.org python.org pypi.org " +
  "npmjs.com docker.com twitter.com x.com linkedin.com facebook.com youtube.com instagram.com"
).split(" "));

const RX = {
  urls: /\b(?:https?|ftp):\/\/[^\s"'<>()[\]{}|\\^`]+/gi,
  emails: /\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi,
  // a v4 address followed by /prefix is a range, reported under cidr
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b(?!\/(?:3[0-2]|[12]?\d)(?![\w/-]|\.\w))/g,
  ipv6: /(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:]|\/\d)/gi,
  cidr: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(?:3[0-2]|[12]?\d)(?![\w/-]|\.\w)|(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\/(?:12[0-8]|1[01]\d|[1-9]?\d)(?![\w/-]|\.\w)/gi,
  // subdomain labels may contain "_" (dl_dir.qq.com); the registrable name and TLD may not
  domains: /\b(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)(?:[a-z]{2,24}|xn--[a-z0-9]{2,59})\b(?![-_])/gi,
  sha512: /\b[a-f0-9]{128}\b/gi,
  sha256: /\b[a-f0-9]{64}\b/gi,
  sha1: /\b[a-f0-9]{40}\b/gi,
  md5: /\b[a-f0-9]{32}\b/gi,
  files: new RegExp(`(?<![\\w\\\\/.%@$-])[\\w][\\w.-]{0,120}\\.(?:${FILE_EXT})\\b(?![\\\\/.-]?\\w)`, "gi"),
  cves: /\bCVE-\d{4}-\d{4,7}\b/gi,
  attack: /\bT[1-9]\d{3}(?:\.\d{3})?\b/g,
  bitcoin: /\b(?:bc1[ac-hj-np-z02-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
  paths: /\b[a-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\s]+/gi,
  registry: /\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HK(?:LM|CU|CR|U))\\[\w\\.{}-]+/g,
};

const TRAILING_PUNCTUATION = /[.,;:!?)\]'"]+$/;
const TRIMMED = new Set(["urls", "paths", "registry"]);
const LOWERCASED = new Set(["domains", "emails", "md5", "sha1", "sha256", "sha512", "ipv6", "cidr"]);
const HIDDEN_SCOPES = new Set(["private", "loopback", "link-local", "cgnat", "reserved"]);
const DEFANGABLE = new Set(["urls", "domains", "ipv4", "ipv6", "cidr", "emails"]);
const DEFANG_MARK = /\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}/i;

/** Undo common defanging so the extractor sees the real indicator: hxxp, [.], (dot), [at], [:]// … */
export function refang(text) {
  return text
    // AsciiDoc passthrough (`++[++.++]++`, `++http://…++`) and Markdown escapes (`\[.\]`) wrap the brackets
    .replace(/\+\+/g, "")                      // shortcut: also turns "C++" into "C", harmless for extraction
    .replace(/`\+|\+`/g, "`")
    .replace(/\\([[\]().:@])/g, "$1")
    .replace(/\bh(?:xx|XX|\*\*)p(s?)(?=:|\[:\])/g, "http$1")
    .replace(/\[:\]\/\/|\[:\/\/\]/g, "://")
    .replace(/\[:\]/g, ":")
    .replace(/ ?(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}) ?/gi, ".")
    .replace(/ ?(?:\[@\]|\(@\)|\[at\]|\(at\)) ?/gi, "@");
}

/** Make an indicator safe to paste into tickets and chat (not clickable, not auto-linked). */
export function defang(value, key) {
  if (!DEFANGABLE.has(key)) return value;
  if (key === "ipv6" || (key === "cidr" && value.includes(":"))) return value.replace(/:/g, "[:]");
  return value.replace(/^http/i, "hxxp").replace(/\./g, "[.]").replace(/@/g, "[@]");
}

export function ipScope(ip) {
  const [a, b, c] = ip.split(".").map(Number);
  if (a === 127) return "loopback";
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
  if (a === 169 && b === 254) return "link-local";
  if (a === 100 && b >= 64 && b <= 127) return "cgnat";
  if (a === 0 || a >= 224) return "reserved";
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) {
    return "documentation";
  }
  return "public";
}

/** 8 groups of 16 bits, or null when `s` is not an IPv6 address. */
export function ipv6Groups(s) {
  const halves = s.toLowerCase().split("::");
  if (halves.length > 2) return null;
  const part = (h) => (h ? h.split(":") : []);
  const head = part(halves[0]), tail = halves.length === 2 ? part(halves[1]) : [];
  const groups = [...head, ...tail];
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  if (halves.length === 1 ? groups.length !== 8 : groups.length > 7) return null;
  if (groups.length < 2) return null;                                   // "::", "26::" (timestamps), "::1"
  const fill = Array(8 - groups.length).fill(0);
  return [...head.map((g) => parseInt(g, 16)), ...(halves.length === 2 ? fill : []), ...tail.map((g) => parseInt(g, 16))];
}

export function ipv6Scope(ip) {
  const g = ipv6Groups(ip);
  if (g.slice(0, 7).every((x) => x === 0)) return g[7] === 1 ? "loopback" : "reserved";
  if ((g[0] & 0xffc0) === 0xfe80) return "link-local";
  if ((g[0] & 0xfe00) === 0xfc00) return "private";                      // unique local fc00::/7
  if (g[0] === 0x2001 && g[1] === 0x0db8) return "documentation";
  if ((g[0] & 0xff00) === 0xff00) return "reserved";                     // multicast
  return "public";
}

const scopeOf = (key, value) => {
  const ip = value.split("/")[0];
  return key === "ipv6" || (key === "cidr" && ip.includes(":")) ? ipv6Scope(ip) : ipScope(ip);
};

function hostOf(key, value) {
  if (key === "domains") return value;
  if (key === "emails") return value.slice(value.lastIndexOf("@") + 1);
  if (key === "urls") {
    try { return new URL(value).hostname.toLowerCase(); } catch { return ""; }
  }
  return "";
}

const under = (host, set) => {
  for (let i = host.indexOf("."), h = host; i !== -1; h = host.slice(i + 1), i = host.indexOf(".", i + 1)) {
    if (set.has(h)) return true;
  }
  return set.has(host);
};

/** Reference site or the bare page of a big platform: report noise, not an indicator. */
export function wellKnown(key, value) {
  const host = hostOf(key, value);
  if (!host) return false;
  if (under(host, REFERENCE)) return true;
  const bare = host.replace(/^www\./, "");
  if (!PLATFORM.has(bare)) return false;
  if (key !== "urls") return true;
  // the Dukes used a Google search URL (?#q=...) as a dead drop: anything after the host makes it an indicator
  try { const u = new URL(value); return u.pathname.length <= 1 && !u.search && !u.hash; } catch { return false; }
}

function v4num(ip) {
  return ip.split(".").reduce((n, o) => n * 256 + Number(o), 0);
}

/** Allow-list text → entries: one per line or separated by commas, `#` starts a comment. */
export function allowEntries(text) {
  if (Array.isArray(text)) return text.filter(Boolean);
  return String(text || "").replace(/#.*$/gm, "").split(/[\s,;]+/).filter(Boolean);
}

/** Parse an allow-list (domains, IPs, IPv4 ranges) into a matcher, or null when it is empty. */
export function allowMatcher(entries) {
  const domains = new Set(), exact = new Set(), ranges = [];
  for (const raw of allowEntries(entries)) {
    const e = refang(raw.trim().toLowerCase()).replace(/^\*\./, "");
    if (!e) continue;
    const m = e.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/);
    if (m && Number(m[2]) <= 32) {
      const bits = Number(m[2]);
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      ranges.push([(v4num(m[1]) & mask) >>> 0, mask]);
    } else if (/^[\d.]+$/.test(e) || e.includes(":")) exact.add(e);
    else domains.add(e);
  }
  if (!domains.size && !exact.size && !ranges.length) return null;
  return (key, value) => {
    const v = value.toLowerCase();
    if (exact.has(v)) return true;
    if (key === "ipv4") return ranges.some(([net, mask]) => ((v4num(v) & mask) >>> 0) === net);
    const host = hostOf(key, v);
    return Boolean(host) && under(host, domains);
  };
}

/**
 * Extract indicators from free text.
 * Options: includePrivate (private/reserved IPs), includeKnown (reference sites), allow (allow-list text or array).
 * @returns {Record<string, {value: string, note?: string}[]>} one array per category, deduplicated, in order of
 *   appearance; a non-enumerable `hidden` property counts what was left out: {private, known, allowed}
 */
export function extract(input, { includePrivate = false, includeKnown = false, allow = null } = {}) {
  const text = refang(input);
  const out = Object.fromEntries(CATEGORIES.map(({ key }) => [key, []]));
  const seen = Object.fromEntries(CATEGORIES.map(({ key }) => [key, new Set()]));
  const hidden = { private: 0, known: 0, allowed: 0 };
  const allowed = allowMatcher(allow);

  // what the author defanged was meant as an indicator (decides "setup.zip": file or domain)
  const defanged = new Set();
  for (const m of input.replace(/\+\+/g, "").replace(/`\+|\+`/g, "`").matchAll(/[\w.\-[\](){}\\:/]+/g)) {
    if (DEFANG_MARK.test(m[0])) defanged.add(refang(m[0]).replace(/[.:\])]+$/, "").toLowerCase());
  }
  const hostsInContext = new Set();

  const add = (key, value, note) => {
    if (seen[key].has(value)) return;
    seen[key].add(value);
    if (allowed && allowed(key, value)) { hidden.allowed++; return; }
    if (!includeKnown && wellKnown(key, value) && !defanged.has(hostOf(key, value)) && !defanged.has(value)) {
      hidden.known++;
      return;
    }
    out[key].push(note ? { value, note } : { value });
  };

  for (const [key, rx] of Object.entries(RX)) {
    for (const match of text.matchAll(rx)) {
      let value = TRIMMED.has(key) ? match[0].replace(TRAILING_PUNCTUATION, "") : match[0];
      let note;
      if (LOWERCASED.has(key)) value = value.toLowerCase();
      if (key === "cves") value = value.toUpperCase();
      if (key === "urls" || key === "emails") hostsInContext.add(hostOf(key, value.toLowerCase()));
      if (key === "domains") {
        const labels = value.split(".");
        const tld = labels[labels.length - 1];
        if (!TLDS.has(tld)) continue;
        if (!defanged.has(value) && !hostsInContext.has(value)) {
          // cdn.evil.zip is a domain, report.pdf.zip a file name
          const fileLike = FILE_TLDS.has(tld) && (labels.length === 2 || FILE_EXT_RX.test(labels[labels.length - 2]));
          if (fileLike || (!COMMON_TLDS.has(tld) && !FILE_TLDS.has(tld))) continue;
          if (text[match.index + match[0].length] === "(") continue;                 // logger.info(...)
          if (/^(?:self|this|cls)\./.test(value)) continue;                         // self.host, this.id
        }
        if (text[match.index - 1] === "/" && text[match.index - 2] !== "/") continue;   // Win64/Agent.BT: a detection name
      }
      if (key === "files") {
        const lower = value.toLowerCase();
        if (seen.domains.has(lower) || hostsInContext.has(lower)) continue;   // "cdn.evil.zip" is a domain
        if (/^[A-Z][a-z]+\.js$/.test(value)) continue;                         // Node.js, Vue.js: product names
        const ext = value.slice(value.lastIndexOf(".") + 1);
        if (ext !== ext.toLowerCase() && ext !== ext.toUpperCase()) continue;  // cmd.Cmd
        if (/^(?:self|this|cls)\./.test(value) || text[match.index + match[0].length] === "(") continue;
      }
      if (key === "ipv6" || key === "cidr") {
        const ip = value.split("/")[0];
        if (ip.includes(":") && !ipv6Groups(ip)) continue;
      }
      if (key === "ipv4" || key === "ipv6" || key === "cidr") {
        const scope = scopeOf(key, value);
        if (HIDDEN_SCOPES.has(scope) && !includePrivate) {
          if (!seen[key].has(value)) { seen[key].add(value); hidden.private++; }
          continue;
        }
        if (scope !== "public") note = scope;
      }
      add(key, value, note);
    }
  }
  Object.defineProperty(out, "hidden", { value: hidden, enumerable: false });
  return out;
}

export function count(results) {
  return Object.values(results).reduce((n, items) => n + items.length, 0);
}

// A cell starting with = + - @ is executed as a formula by Excel/Sheets: neutralise it (CSV injection).
function csvCell(raw) {
  const s = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCSV(results, { defanged = false } = {}) {
  const rows = [["type", "value", "note"]];
  for (const { key } of CATEGORIES) {
    for (const item of results[key]) rows.push([key, defanged ? defang(item.value, key) : item.value, item.note ?? ""]);
  }
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

export function toJSON(results, { defanged = false } = {}) {
  const data = {};
  for (const { key } of CATEGORIES) {
    if (results[key].length) {
      data[key] = results[key].map((item) => ({ ...item, value: defanged ? defang(item.value, key) : item.value }));
    }
  }
  return JSON.stringify({ generator: "ioc-hunter", defanged, indicators: data }, null, 2);
}

const HIVES = { HKLM: "HKEY_LOCAL_MACHINE", HKCU: "HKEY_CURRENT_USER", HKCR: "HKEY_CLASSES_ROOT", HKU: "HKEY_USERS" };
const quote = (s) => `'${s.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;

/** STIX 2.1 pattern for one indicator, or null when STIX has no object for it (Bitcoin). */
export function stixPattern(key, value) {
  switch (key) {
    case "urls": return `[url:value = ${quote(value)}]`;
    case "domains": return `[domain-name:value = ${quote(value)}]`;
    case "ipv4": return `[ipv4-addr:value = ${quote(value)}]`;
    case "ipv6": return `[ipv6-addr:value = ${quote(value)}]`;
    case "cidr": return `[${value.includes(":") ? "ipv6" : "ipv4"}-addr:value = ${quote(value)}]`;
    case "emails": return `[email-addr:value = ${quote(value)}]`;
    case "md5": return `[file:hashes.MD5 = ${quote(value)}]`;
    case "sha1": return `[file:hashes.'SHA-1' = ${quote(value)}]`;
    case "sha256": return `[file:hashes.'SHA-256' = ${quote(value)}]`;
    case "sha512": return `[file:hashes.'SHA-512' = ${quote(value)}]`;
    case "files": return `[file:name = ${quote(value)}]`;
    case "paths": {
      const i = value.lastIndexOf("\\");
      return `[file:name = ${quote(value.slice(i + 1))} AND file:parent_directory_ref.path = ${quote(value.slice(0, i))}]`;
    }
    case "registry": {
      const [hive, ...rest] = value.split("\\");
      return `[windows-registry-key:key = ${quote([HIVES[hive.toUpperCase()] || hive, ...rest].join("\\"))}]`;
    }
    default: return null;
  }
}

/**
 * A STIX 2.1 bundle: one indicator per network / file indicator, a vulnerability per CVE and an
 * attack-pattern per ATT&CK technique. `now` and `uuid` are injectable for tests.
 */
export function toSTIX(results, { now = new Date(), uuid = () => crypto.randomUUID() } = {}) {
  const ts = now.toISOString();
  const common = (type) => ({ type, spec_version: "2.1", id: `${type}--${uuid()}`, created: ts, modified: ts });
  const objects = [];
  for (const { key, label } of CATEGORIES) {
    for (const { value, note } of results[key]) {
      if (key === "cves") {
        objects.push({ ...common("vulnerability"), name: value,
          external_references: [{ source_name: "cve", external_id: value }] });
      } else if (key === "attack") {
        objects.push({ ...common("attack-pattern"), name: value,
          external_references: [{ source_name: "mitre-attack", external_id: value,
            url: `https://attack.mitre.org/techniques/${value.replace(".", "/")}/` }] });
      } else {
        const pattern = stixPattern(key, value);
        if (!pattern) continue;
        objects.push({ ...common("indicator"), name: value, description: `${label} extracted by ioc-hunter` +
          (note ? ` (${note})` : ""), indicator_types: ["malicious-activity"], pattern, pattern_type: "stix",
          pattern_version: "2.1", valid_from: ts });
      }
    }
  }
  return JSON.stringify({ type: "bundle", id: `bundle--${uuid()}`, objects }, null, 2);
}

/** Third-party pivots for an indicator: [label, url] pairs. Opened only on an explicit click. */
export function lookups(key, value) {
  const q = encodeURIComponent(value);
  switch (key) {
    case "ipv4": case "ipv6":
      return [["VirusTotal", `https://www.virustotal.com/gui/ip-address/${q}`],
        ["AbuseIPDB", `https://www.abuseipdb.com/check/${q}`], ["Shodan", `https://www.shodan.io/host/${q}`]];
    case "domains":
      return [["VirusTotal", `https://www.virustotal.com/gui/domain/${q}`], ["urlscan", `https://urlscan.io/domain/${q}`]];
    case "urls":
      return [["VirusTotal", `https://www.virustotal.com/gui/search/${q}`]];
    case "md5": case "sha1": case "sha256":
      return [["VirusTotal", `https://www.virustotal.com/gui/file/${q}`]];
    case "sha512": case "files":
      return [["VirusTotal", `https://www.virustotal.com/gui/search/${q}`]];
    case "cves":
      return [["NVD", `https://nvd.nist.gov/vuln/detail/${q}`]];
    case "attack":
      return [["MITRE", `https://attack.mitre.org/techniques/${value.replace(".", "/")}/`]];
    default:
      return [];
  }
}
