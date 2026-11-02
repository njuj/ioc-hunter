// Pure extraction logic — no DOM, so the exact same module runs (and is tested) in Node and the browser.

export const CATEGORIES = [
  { key: "urls", label: "URLs" },
  { key: "domains", label: "Domains" },
  { key: "ipv4", label: "IPv4" },
  { key: "emails", label: "E-mails" },
  { key: "sha256", label: "SHA-256" },
  { key: "sha1", label: "SHA-1" },
  { key: "md5", label: "MD5" },
  { key: "cves", label: "CVEs" },
  { key: "attack", label: "MITRE ATT&CK" },
  { key: "bitcoin", label: "Bitcoin" },
  { key: "paths", label: "File paths" },
  { key: "registry", label: "Registry keys" },
];

// Real TLDs only, so "update.exe" or "gate.php" are never reported as domains.
export const TLDS = new Set((
  "com net org io co info biz xyz top club online site me us uk de fr nl ru cn br in jp kr ir su tk ml ga cf gq pw " +
  "cc tv ws app dev ai gov edu mil int eu ca au es it pl ua kz by sa ae eg tr vn id th my sg hk tw ph pk ng za ke ar " +
  "mx cl pe ve ch at be se no dk fi pt gr cz ro hu il nz live store shop link click space tech fun icu rest bar buzz " +
  "cam monster cyou sbs lol cloud host website digital network email news blog world today page onion"
).split(" "));

const RX = {
  urls: /\b(?:https?|ftp):\/\/[^\s"'<>()[\]{}|\\^`]+/gi,
  emails: /\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi,
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
  domains: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi,
  sha256: /\b[a-f0-9]{64}\b/gi,
  sha1: /\b[a-f0-9]{40}\b/gi,
  md5: /\b[a-f0-9]{32}\b/gi,
  cves: /\bCVE-\d{4}-\d{4,7}\b/gi,
  attack: /\bT[1-9]\d{3}(?:\.\d{3})?\b/g,
  bitcoin: /\b(?:bc1[ac-hj-np-z02-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
  paths: /\b[a-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\s]+/gi,
  registry: /\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HK(?:LM|CU|CR|U))\\[\w\\.{}-]+/g,
};

const TRAILING_PUNCTUATION = /[.,;:!?)\]'"]+$/;
const TRIMMED = new Set(["urls", "paths", "registry"]);
const LOWERCASED = new Set(["domains", "emails", "md5", "sha1", "sha256"]);
const HIDDEN_SCOPES = new Set(["private", "loopback", "link-local", "cgnat", "reserved"]);
const DEFANGABLE = new Set(["urls", "domains", "ipv4", "emails"]);

/** Undo common defanging so the extractor sees the real indicator: hxxp, [.], (dot), [at], [:]// … */
export function refang(text) {
  return text
    .replace(/\bh(?:xx|XX|\*\*)p(s?)(?=:|\[:\])/g, "http$1")
    .replace(/\[:\]\/\/|\[:\/\/\]/g, "://")
    .replace(/ ?(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}) ?/gi, ".")
    .replace(/ ?(?:\[@\]|\(@\)|\[at\]|\(at\)) ?/gi, "@");
}

/** Make an indicator safe to paste into tickets and chat (not clickable, not auto-linked). */
export function defang(value, key) {
  if (!DEFANGABLE.has(key)) return value;
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

/**
 * Extract indicators from free text.
 * @returns {Record<string, {value: string, note?: string}[]>} one array per category, deduplicated, in order of appearance
 */
export function extract(input, { includePrivate = false } = {}) {
  const text = refang(input);
  const out = Object.fromEntries(CATEGORIES.map(({ key }) => [key, []]));
  const seen = Object.fromEntries(CATEGORIES.map(({ key }) => [key, new Set()]));

  for (const [key, rx] of Object.entries(RX)) {
    for (const match of text.matchAll(rx)) {
      let value = TRIMMED.has(key) ? match[0].replace(TRAILING_PUNCTUATION, "") : match[0];
      let note;
      if (LOWERCASED.has(key)) value = value.toLowerCase();
      if (key === "cves") value = value.toUpperCase();
      if (key === "domains" && !TLDS.has(value.slice(value.lastIndexOf(".") + 1))) continue;
      if (key === "ipv4") {
        const scope = ipScope(value);
        if (HIDDEN_SCOPES.has(scope) && !includePrivate) continue;
        if (scope !== "public") note = scope;
      }
      if (seen[key].has(value)) continue;
      seen[key].add(value);
      out[key].push(note ? { value, note } : { value });
    }
  }
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

/** Third-party pivots for an indicator: [label, url] pairs. Opened only on an explicit click. */
export function lookups(key, value) {
  const q = encodeURIComponent(value);
  switch (key) {
    case "ipv4":
      return [["VirusTotal", `https://www.virustotal.com/gui/ip-address/${q}`],
        ["AbuseIPDB", `https://www.abuseipdb.com/check/${q}`], ["Shodan", `https://www.shodan.io/host/${q}`]];
    case "domains":
      return [["VirusTotal", `https://www.virustotal.com/gui/domain/${q}`], ["urlscan", `https://urlscan.io/domain/${q}`]];
    case "urls":
      return [["VirusTotal", `https://www.virustotal.com/gui/search/${q}`]];
    case "md5": case "sha1": case "sha256":
      return [["VirusTotal", `https://www.virustotal.com/gui/file/${q}`]];
    case "cves":
      return [["NVD", `https://nvd.nist.gov/vuln/detail/${q}`]];
    case "attack":
      return [["MITRE", `https://attack.mitre.org/techniques/${value.replace(".", "/")}/`]];
    default:
      return [];
  }
}
