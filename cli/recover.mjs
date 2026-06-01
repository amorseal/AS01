#!/usr/bin/env node

// Reference CLI for the public recovery package.
// Maps directly to SPEC.md sections 5, 8, 9, and 11.

import { readFile } from "node:fs/promises";

import {
  findAmorSealPayloadInWitnessItems,
  sanitizeSingleLine,
} from "../lib/as01-core.mjs";
import {
  openAs01FromRawTxJson,
  openAs01FromTxid,
  openAs01Payload,
} from "../lib/as01-node.mjs";

try {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    printHelp();
    process.exit(0);
  }

  const phrase = await readPhraseArg(args);
  const plaintext = await recover(args, phrase);
  process.stdout.write(`${plaintext}\n`);
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}

async function recover(args, phrase) {
  const modes = [args.payload, args["payload-file"], args["raw-tx-file"], args["witness-file"], args.txid].filter(Boolean);
  if (modes.length !== 1) {
    throw new Error("Use exactly one recovery input: --payload, --payload-file, --raw-tx-file, --witness-file, or --txid.");
  }

  if (args.payload) {
    return openAs01Payload(sanitizeSingleLine(args.payload, "payload"), phrase);
  }

  if (args["payload-file"]) {
    const payloadText = await readFile(args["payload-file"], "utf8");
    return openAs01Payload(sanitizeSingleLine(payloadText, "payload-file"), phrase);
  }

  if (args["raw-tx-file"]) {
    return openAs01FromRawTxJson(await readJsonFile(args["raw-tx-file"], "raw transaction file"), phrase);
  }

  if (args["witness-file"]) {
    const parsed = await readJsonFile(args["witness-file"], "witness file");
    if (!Array.isArray(parsed)) {
      throw new Error("Witness file must be a JSON array.");
    }
    const payload = findAmorSealPayloadInWitnessItems(parsed);
    if (!payload) {
      throw new Error("No Amor Seal AS01 payload was found in the supplied witness data.");
    }
    return openAs01Payload(payload, phrase);
  }

  return openAs01FromTxid(args.txid, phrase);
}

async function readPhraseArg(args) {
  if (args.phrase && args["phrase-file"]) {
    throw new Error("Use either --phrase or --phrase-file, not both.");
  }

  if (args.phrase) {
    return args.phrase;
  }

  if (args["phrase-file"]) {
    const phraseText = await readFile(args["phrase-file"], "utf8");
    return sanitizeSingleLine(phraseText, "phrase-file");
  }

  throw new Error("Missing required phrase input. Use --phrase or --phrase-file.");
}

async function readJsonFile(filePath, label) {
  let text;
  try {
    text = await readFile(filePath, "utf8");
  } catch {
    throw new Error(`Unable to read ${label}.`);
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`The ${label} is not valid JSON.`);
  }
}

function parseArgs(argv) {
  const args = {};

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];

    if (token === "--help") {
      args.help = true;
      continue;
    }

    if (!token.startsWith("--")) {
      throw new Error(`Unexpected argument: ${token}`);
    }

    const key = token.slice(2);
    const value = argv[index + 1];

    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for --${key}`);
    }

    args[key] = value;
    index += 1;
  }

  return args;
}

function printHelp() {
  process.stdout.write(`Amor Seal AS01 recovery CLI

Usage:
  node cli/recover.mjs --payload-file fixtures/example-payload.txt --phrase-file fixtures/example-phrase.txt
  node cli/recover.mjs --raw-tx-file fixtures/example-raw-tx.json --phrase \"meadow velvet harbor lantern silver walnut\"
  node cli/recover.mjs --txid <64-hex-txid> --phrase \"...\"
`);
}
