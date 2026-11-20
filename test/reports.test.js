// Cases taken from real vendor reports (ESET malware-ioc) and from code, where 0.1 got it wrong.
import assert from "node:assert/strict";
import { test } from "node:test";

import { allowEntries, allowMatcher, extract, ipv6Groups, ipv6Scope, refang, stixPattern, toSTIX, wellKnown } from "../src/extract.js";

const values = (items) => items.map((i) => i.value);

test("refang sees through AsciiDoc and Markdown escapes", () => {
  assert.equal(refang("litanq++[++.++]++ru"), "litanq.ru");                    // AsciiDoc ++passthrough++
  assert.equal(refang("`+http://noname[.]onion+`"), "`http://noname.onion`"); // single-plus passthrough
  assert.equal(refang("evil\\[.\\]example\\[.\\]com"), "evil.example.com");   // Markdown \[.\]
  assert.equal(refang("1.2.3.4[:]443"), "1.2.3.4:443");
  const r = extract("|`38.54.57++[++.++]++17` |`++http://20.3323sf[.]com/zz.php++`");
  assert.deepEqual(values(r.ipv4), ["38.54.57.17"]);
  assert.deepEqual(values(r.urls), ["http://20.3323sf.com/zz.php"]);
});

test("every IANA TLD counts when the author defanged it or it is a URL host", () => {
  const r = extract("d16ss6sn-80.euw.devtunnels[.]ms balacimed.mine[.]nu update[.]xn--6frz82g hxxp://evil[.]bond/x");
  assert.deepEqual(values(r.domains), ["d16ss6sn-80.euw.devtunnels.ms", "balacimed.mine.nu", "update.xn--6frz82g", "evil.bond"]);
});

test("plain text needs a common TLD, and code is not a domain", () => {
  const code = "name = self.name; m.group(1); f.read(); logger.info('x'); self.host = cfg.data; os.name";
  assert.deepEqual(extract(code).domains, []);
  assert.deepEqual(values(extract("C2 at update-check.top and cdn.evil.zip").domains), ["update-check.top", "cdn.evil.zip"]);
  assert.deepEqual(values(extract("subdomain dl_dir.qq.com").domains), ["dl_dir.qq.com"]);
});

test("detection names are not domains", () => {
  const r = extract("|`rev.exe` | WinGo/Agent.BT | Win64/VulnDriver.Baidu.D | Linux/SSHDoor.CA | PowerShell/Pterodo.GA");
  assert.deepEqual(r.domains, []);
  assert.deepEqual(values(r.files), ["rev.exe"]);
});

test("file names vs domains with a file-extension TLD", () => {
  const r = extract("dropped invoice.zip, setup.py and run.sh; contacted invoice[.]zip and cdn.evil.mov; Node.js; self.url");
  assert.deepEqual(values(r.files), ["setup.py", "run.sh"]);
  assert.deepEqual(values(r.domains), ["invoice.zip", "cdn.evil.mov"]);
  assert.deepEqual(values(extract("store.appupdate.ai totokupdate.ai partnerls.pl").domains),
    ["store.appupdate.ai", "totokupdate.ai", "partnerls.pl"]);
  assert.deepEqual(extract("C:\\Windows\\evil.dll and /tmp/x.so and http://a.example.com/b.exe").files, []);
});

test("ipv6: validation, scope and ranges", () => {
  assert.equal(ipv6Groups("2001:db8::1").length, 8);
  for (const bad of ["12:30:45", "26::", "::", "1:2:3:4:5:6:7:8:9", "2001:db8:::1", "00:1a:2b:3c:4d:5e"]) {
    assert.equal(ipv6Groups(bad), null, bad);
  }
  assert.equal(ipv6Scope("fe80::1:2"), "link-local");
  assert.equal(ipv6Scope("fd12:3456::1"), "private");
  assert.equal(ipv6Scope("2a03:2880:f12f::1"), "public");
  const r = extract("C2 2a03:2880:f12f:83:face:b00c:0:25de, LAN fe80::1:2, range 2a03:2880::/32 and 45.13.0.0/16. Time 10:30:45");
  assert.deepEqual(values(r.ipv6), ["2a03:2880:f12f:83:face:b00c:0:25de"]);
  assert.deepEqual(values(r.cidr), ["2a03:2880::/32", "45.13.0.0/16"]);
  assert.deepEqual(r.ipv4, []);
  assert.equal(extract("fe80::1:2", { includePrivate: true }).ipv6[0].note, "link-local");
  assert.deepEqual(values(extract("http://1.2.3.4/1.php").ipv4), ["1.2.3.4"]);    // a path, not a prefix
});

test("sha512", () => {
  const r = extract(`${"e".repeat(128)} ${"f".repeat(64)}`);
  assert.deepEqual([r.sha512.length, r.sha256.length, r.sha1.length], [1, 1, 0]);
});

test("well-known reference sites are hidden, platform URLs and defanged ones are not", () => {
  assert.ok(wellKnown("domains", "www.welivesecurity.com"));
  assert.ok(wellKnown("urls", "https://attack.mitre.org/techniques/T1059/"));
  assert.ok(wellKnown("domains", "github.com"));
  assert.ok(!wellKnown("urls", "https://github.com/evil/loader/releases"));
  assert.ok(!wellKnown("domains", "evil.s3.amazonaws.com"));
  const r = extract("see https://www.welivesecurity.com/a and github.com; C2 hxxps://twitter[.]com/np8j7ovqdl and t[.]me");
  assert.deepEqual(values(r.urls), ["https://twitter.com/np8j7ovqdl"]);
  assert.deepEqual(values(r.domains), ["t.me"]);
  assert.equal(r.hidden.known, 4);  // the welivesecurity URL and domain, github.com, bare twitter.com
  assert.equal(extract("github.com", { includeKnown: true }).domains.length, 1);
});

test("allow-list: domains with subdomains, IPs and IPv4 ranges", () => {
  const allow = "corp.example.com\n10.0.0.0/8, 198.51.100.7\n# comment words are not entries";
  const r = extract("mail.corp.example.com evil.example.com 198.51.100.7 198.51.100.8 10.1.2.3 a@corp.example.com",
    { allow, includePrivate: true });
  assert.deepEqual(values(r.domains), ["evil.example.com"]);
  assert.deepEqual(values(r.ipv4), ["198.51.100.8"]);
  assert.deepEqual(r.emails, []);
  assert.equal(r.hidden.allowed, 5);
  assert.equal(allowMatcher("# only a comment"), null);
  assert.deepEqual(allowEntries("a.com, b.com # x y\n#z\n1.2.3.4"), ["a.com", "b.com", "1.2.3.4"]);
});

test("STIX patterns", () => {
  assert.equal(stixPattern("sha256", "ab"), "[file:hashes.'SHA-256' = 'ab']");
  assert.equal(stixPattern("cidr", "10.0.0.0/8"), "[ipv4-addr:value = '10.0.0.0/8']");
  assert.equal(stixPattern("registry", "HKCU\\Software\\Run"),
    "[windows-registry-key:key = 'HKEY_CURRENT_USER\\\\Software\\\\Run']");
  assert.equal(stixPattern("paths", "C:\\Users\\a.exe"),
    "[file:name = 'a.exe' AND file:parent_directory_ref.path = 'C:\\\\Users']");
  assert.equal(stixPattern("urls", "http://x/'a"), "[url:value = 'http://x/\\'a']");
  assert.equal(stixPattern("bitcoin", "bc1q"), null);
});

test("STIX bundle", () => {
  let n = 0;
  const uuid = () => `00000000-0000-4000-8000-${String(++n).padStart(12, "0")}`;
  const doc = JSON.parse(toSTIX(extract("evil.example.com CVE-2024-3400 T1059.001 bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"),
    { now: new Date("2026-11-21T00:00:00Z"), uuid }));
  assert.equal(doc.type, "bundle");
  assert.deepEqual(doc.objects.map((o) => o.type), ["indicator", "vulnerability", "attack-pattern"]);
  const [ind, vuln, ap] = doc.objects;
  assert.equal(ind.id, "indicator--00000000-0000-4000-8000-000000000001");
  assert.equal(ind.pattern, "[domain-name:value = 'evil.example.com']");
  assert.equal(ind.valid_from, "2026-11-21T00:00:00.000Z");
  assert.equal(ind.spec_version, "2.1");
  assert.deepEqual(vuln.external_references, [{ source_name: "cve", external_id: "CVE-2024-3400" }]);
  assert.equal(ap.external_references[0].external_id, "T1059.001");
});
