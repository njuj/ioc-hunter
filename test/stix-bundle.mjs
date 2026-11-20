// Prints a STIX 2.1 bundle with every kind of object ioc-hunter exports, for the OASIS validator in CI:
//   node test/stix-bundle.mjs > bundle.json && stix2_validator bundle.json
import { extract, toSTIX } from "../src/extract.js";
import { SAMPLE } from "../src/sample.js";

const extra = `
SHA512 ${"ab".repeat(64)}
Loader written to HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil and C:\\ProgramData\\it's here\\run.exe
URL with a quote: https://evil.example.com/a'b?c=1
`;
process.stdout.write(toSTIX(extract(SAMPLE + extra)) + "\n");
