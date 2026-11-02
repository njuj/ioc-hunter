import assert from "node:assert/strict";
import { test } from "node:test";

import { count, defang, extract, ipScope, lookups, refang, toCSV, toJSON } from "../src/extract.js";
import { SAMPLE } from "../src/sample.js";

const values = (items) => items.map((i) => i.value);

test("refang handles the usual conventions", () => {
  assert.equal(refang("hxxps://evil[.]example[.]com"), "https://evil.example.com");
  assert.equal(refang("hXXp[:]//a(.)b{.}c"), "http://a.b.c");
  assert.equal(refang("ops [at] example [dot] org"), "ops@example.org");
  assert.equal(refang("1.2.3[.]4 and x(@)y.io"), "1.2.3.4 and x@y.io");
});

test("defang round-trips through refang", () => {
  for (const [value, key] of [["https://a.example.com/x.php", "urls"], ["mail@a.example.org", "emails"], ["203.0.113.9", "ipv4"]]) {
    assert.ok(!defang(value, key).includes("://") || defang(value, key).startsWith("hxxp"));
    assert.equal(refang(defang(value, key)), value);
  }
  assert.equal(defang("a4c1e9f02b7d3e8c6f5a1b0d9e2c7f43", "md5"), "a4c1e9f02b7d3e8c6f5a1b0d9e2c7f43");
});

test("full sample report", () => {
  const r = extract(SAMPLE);
  assert.deepEqual(values(r.urls), ["https://cdn-update.example.net/api/v2/gate.php"]);
  assert.deepEqual(values(r.domains), ["invoices-secure.example.com", "cdn-update.example.net", "darkleak.example.org"]);
  assert.deepEqual(values(r.emails), ["billing@invoices-secure.example.com", "support@darkleak.example.org"]);
  assert.deepEqual(r.ipv4, [{ value: "203.0.113.45", note: "documentation" }, { value: "198.51.100.23", note: "documentation" }]);
  assert.equal(r.sha256.length, 1);
  assert.equal(r.sha1.length, 1);
  assert.equal(r.md5.length, 1);
  assert.deepEqual(values(r.cves), ["CVE-2024-3400", "CVE-2023-4966"]);
  assert.deepEqual(values(r.attack), ["T1566.001", "T1059.001", "T1547.001"]);
  assert.deepEqual(values(r.bitcoin), ["bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"]);
  assert.deepEqual(values(r.paths), ["C:\\Users\\Public\\Libraries\\svchost32.exe"]);
  assert.deepEqual(values(r.registry), ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"]);
});

test("filenames are not domains", () => {
  assert.deepEqual(extract("ran update.exe, payload.dll and gate.php from evil.example.com").domains,
    [{ value: "evil.example.com" }]);
});

test("hash lengths never bleed into each other", () => {
  const sha256 = "a".repeat(64);
  const r = extract(`${sha256} ${"b".repeat(40)} ${"c".repeat(32)} ${"d".repeat(33)}`);
  assert.deepEqual([r.sha256.length, r.sha1.length, r.md5.length], [1, 1, 1]);
});

test("private ranges are hidden unless asked for", () => {
  const text = "10.1.1.1 172.20.0.5 192.168.1.1 127.0.0.1 169.254.9.9 100.64.0.1 8.8.8.8";
  assert.deepEqual(values(extract(text).ipv4), ["8.8.8.8"]);
  assert.equal(extract(text, { includePrivate: true }).ipv4.length, 7);
  assert.equal(ipScope("172.32.0.1"), "public");
  assert.equal(ipScope("239.1.1.1"), "reserved");
});

test("dedupes case-insensitively and keeps first-seen order", () => {
  const r = extract("B.EXAMPLE.COM a.example.com b.example.com A4C1E9F02B7D3E8C6F5A1B0D9E2C7F43 a4c1e9f02b7d3e8c6f5a1b0d9e2c7f43");
  assert.deepEqual(values(r.domains), ["b.example.com", "a.example.com"]);
  assert.equal(r.md5.length, 1);
});

test("trailing punctuation is trimmed from urls and paths", () => {
  const r = extract("see (https://a.example.com/x?y=1). Then C:\\Temp\\a.dll, C:\\Temp\\b.dll.");
  assert.deepEqual(values(r.urls), ["https://a.example.com/x?y=1"]);
  assert.deepEqual(values(r.paths), ["C:\\Temp\\a.dll", "C:\\Temp\\b.dll"]);
});

test("ipv4 rejects out-of-range octets", () => {
  assert.equal(extract("999.1.1.1 1.2.3 256.256.256.256").ipv4.length, 0);
});

test("csv export escapes quotes and blocks formula injection", () => {
  const results = extract("");
  results.urls.push({ value: '=HYPERLINK("http://x")' });
  results.domains.push({ value: "a.example.com", note: 'say "hi", ok' });
  const csv = toCSV(results, { defanged: true });
  assert.ok(csv.startsWith("type,value,note\r\n"));
  assert.ok(csv.includes(`urls,"'=HYPERLINK(""http://x"")",`));
  assert.ok(csv.includes(`domains,a[.]example[.]com,"say ""hi"", ok"`));
});

test("json export only lists non-empty categories", () => {
  const doc = JSON.parse(toJSON(extract("evil.example.com 8.8.8.8"), { defanged: true }));
  assert.deepEqual(Object.keys(doc.indicators), ["domains", "ipv4"]);
  assert.equal(doc.indicators.ipv4[0].value, "8[.]8[.]8[.]8");
});

test("lookups are url-encoded and type-specific", () => {
  assert.equal(lookups("attack", "T1059.001")[0][1], "https://attack.mitre.org/techniques/T1059/001/");
  assert.ok(lookups("urls", "http://a.example.com/?q=1&x=2")[0][1].endsWith("http%3A%2F%2Fa.example.com%2F%3Fq%3D1%26x%3D2"));
  assert.deepEqual(lookups("paths", "C:\\x"), []);
});

test("count", () => {
  // 1 url + 3 domains + 2 ips + 2 emails + 3 hashes + 2 cves + 3 techniques + 1 btc + 1 path + 1 key
  assert.equal(count(extract(SAMPLE)), 19);
});
