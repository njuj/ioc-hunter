// Fictional incident write-up. Every indicator lives in reserved space (example.* domains,
// TEST-NET IPs, BIP-173 example address, made-up hashes), so the demo never points at anyone real.
export const SAMPLE = `INCIDENT REPORT  IR-2026-0412  (fictional, demo data)
=====================================================

Initial access (T1566.001): spear-phishing mail from billing[@]invoices-secure[.]example[.]com
with attachment "Invoice_8841.pdf.exe".

  SHA256  3b8f1c0e9d2a47f6b5c4e3d2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a392
  SHA1    7c2e9a4f1b3d5e6f8a0b2c4d6e8f0a1b3c5d7e9f
  MD5     a4c1e9f02b7d3e8c6f5a1b0d9e2c7f43

Execution (T1059.001): the dropper ran an encoded PowerShell stage that beaconed to
hxxps://cdn-update[.]example[.]net/api/v2/gate.php every 60s, primary C2 203.0.113[.]45:8443,
fallback 198.51.100.23. Lateral movement from the beachhead 10.0.4.17 to 10.0.4.22 over SMB.

Persistence (T1547.001):
  HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater
  -> C:\\Users\\Public\\Libraries\\svchost32.exe

The edge firewall was unpatched for CVE-2024-3400; cve-2023-4966 was also reachable.
The ransom note demanded payment to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh and
negotiation via support(at)darkleak(dot)example(dot)org.
`;
