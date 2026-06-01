import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const suspiciousPatterns = [
  /BEGIN [A-Z ]*PRIVATE KEY/,
  /sk_live_/,
  /rk_live_/,
  /DATABASE_URL=/,
  /postgresql:\/\//,
  /AWS_SECRET_ACCESS_KEY/,
  /STRIPE_SECRET_KEY/,
  /walletPrivateKey/i,
  /seedPhrase/i,
];

const matches = [];

walk(repoRoot);

if (matches.length > 0) {
  process.stderr.write(`${JSON.stringify({ clean: false, matches }, null, 2)}\n`);
  process.exit(1);
}

process.stdout.write(`${JSON.stringify({ clean: true, scannedRoot: repoRoot }, null, 2)}\n`);

function walk(currentPath) {
  for (const entry of readdirSync(currentPath)) {
    const absolutePath = path.join(currentPath, entry);
    const relativePath = path.relative(repoRoot, absolutePath);
    const stat = statSync(absolutePath);

    if (stat.isDirectory()) {
      walk(absolutePath);
      continue;
    }

    if (relativePath === "scripts/verify-secret-scan.mjs") {
      continue;
    }

    const contents = readFileSync(absolutePath, "utf8");
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(contents)) {
        matches.push({
          file: relativePath,
          pattern: String(pattern),
        });
      }
    }
  }
}
