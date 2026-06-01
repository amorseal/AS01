// SPEC.md sections 6, 7, 9
// Node-side decryption helpers for the standalone CLI and verification scripts.

import { brotliDecompressSync } from "node:zlib";
import { createDecipheriv, pbkdf2Sync } from "node:crypto";

import {
  AUTH_TAG_LENGTH,
  COMPRESSION_TAG_BROTLI,
  COMPRESSION_TAG_NONE,
  KEY_LENGTH,
  NONCE_LENGTH,
  PBKDF2_ITERATIONS,
  SALT_LENGTH,
  decodeBase64Url,
  extractWitnessItemsFromRawTxJson,
  fetchRawTxByTxid,
  findAmorSealPayloadInWitnessItems,
  normalizeOpeningPhrase,
  unpackEnvelope,
} from "./as01-core.mjs";

export function openAs01Payload(payload, openingPhrase) {
  const envelopeBytes = typeof payload === "string" ? decodeBase64Url(payload) : new Uint8Array(payload);
  const envelope = unpackEnvelope(envelopeBytes);
  const normalizedPhrase = normalizeOpeningPhrase(openingPhrase);
  const key = deriveKey(normalizedPhrase, envelope.salt);
  const decryptedBytes = decryptPayload(envelope, key);
  const plaintextBytes = decompressPayload(decryptedBytes, envelope.compressionTag);
  return new TextDecoder().decode(plaintextBytes);
}

export function openAs01FromRawTxJson(rawTxJson, openingPhrase) {
  const witnessItems = extractWitnessItemsFromRawTxJson(rawTxJson);
  const payload = findAmorSealPayloadInWitnessItems(witnessItems);

  if (!payload) {
    throw new Error("No Amor Seal AS01 payload was found in the supplied raw transaction witness data.");
  }

  return openAs01Payload(payload, openingPhrase);
}

export async function openAs01FromTxid(txid, openingPhrase) {
  const fetched = await fetchRawTxByTxid(txid);
  if (!fetched.rawTxJson) {
    throw new Error(`Unable to fetch transaction for txid recovery. ${fetched.error ?? ""}`.trim());
  }
  return openAs01FromRawTxJson(fetched.rawTxJson, openingPhrase);
}

function deriveKey(phrase, salt) {
  if (salt.byteLength !== SALT_LENGTH) {
    throw new Error(`AS01 salt must be exactly ${SALT_LENGTH} bytes.`);
  }

  return new Uint8Array(
    pbkdf2Sync(
      phrase,
      Buffer.from(salt),
      PBKDF2_ITERATIONS,
      KEY_LENGTH,
      "sha256",
    ),
  );
}

function decryptPayload(envelope, key) {
  if (key.byteLength !== KEY_LENGTH) {
    throw new Error(`AS01 key must be exactly ${KEY_LENGTH} bytes.`);
  }

  if (envelope.nonce.byteLength !== NONCE_LENGTH) {
    throw new Error(`AS01 nonce must be exactly ${NONCE_LENGTH} bytes.`);
  }

  if (envelope.authTag.byteLength !== AUTH_TAG_LENGTH) {
    throw new Error(`AS01 auth tag must be exactly ${AUTH_TAG_LENGTH} bytes.`);
  }

  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      Buffer.from(key),
      Buffer.from(envelope.nonce),
    );
    decipher.setAuthTag(Buffer.from(envelope.authTag));

    return new Uint8Array(Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext)),
      decipher.final(),
    ]));
  } catch {
    throw new Error("The phrase did not unlock this letter.");
  }
}

function decompressPayload(input, compressionTag) {
  if (compressionTag === COMPRESSION_TAG_NONE) {
    return input;
  }

  if (compressionTag !== COMPRESSION_TAG_BROTLI) {
    throw new Error("AS01 payload uses an unsupported compression tag.");
  }

  try {
    return new Uint8Array(brotliDecompressSync(Buffer.from(input)));
  } catch {
    throw new Error("The phrase did not unlock this letter.");
  }
}
