import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { openAs01FromRawTxJson, openAs01Payload } from "../lib/as01-node.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const phrase = readFileSync(path.join(repoRoot, "fixtures/example-phrase.txt"), "utf8").trim();
const payload = readFileSync(path.join(repoRoot, "fixtures/example-payload.txt"), "utf8").trim();
const expected = readFileSync(path.join(repoRoot, "fixtures/expected-plaintext.txt"), "utf8").trimEnd();
const rawTx = JSON.parse(readFileSync(path.join(repoRoot, "fixtures/example-raw-tx.json"), "utf8"));

const directPayload = openAs01Payload(payload, phrase);
if (directPayload !== expected) {
  throw new Error("Direct payload recovery did not match the expected plaintext.");
}

const directRawTx = openAs01FromRawTxJson(rawTx, phrase);
if (directRawTx !== expected) {
  throw new Error("Raw transaction recovery did not match the expected plaintext.");
}

const cliOutput = execFileSync(
  process.execPath,
  [
    path.join(repoRoot, "cli/recover.mjs"),
    "--raw-tx-file",
    path.join(repoRoot, "fixtures/example-raw-tx.json"),
    "--phrase-file",
    path.join(repoRoot, "fixtures/example-phrase.txt"),
  ],
  {
    cwd: repoRoot,
    encoding: "utf8",
  },
).trimEnd();

if (cliOutput !== expected) {
  throw new Error("CLI raw transaction recovery did not match the expected plaintext.");
}

process.stdout.write(`${JSON.stringify({
  expected,
  directPayload,
  directRawTx,
  cliOutput,
  payloadMode: directPayload === expected,
  rawTxMode: directRawTx === expected,
  cliMode: cliOutput === expected,
}, null, 2)}\n`);
