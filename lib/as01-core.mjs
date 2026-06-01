// SPEC.md sections 3, 5, 8, 11
// Shared parsing and extraction logic for standalone AS01 recovery.

export const MAGIC = "AS01";
export const VERSION = 0x01;
export const ALGORITHM_TAG = 0x01;
export const KDF_TAG = 0x01;
export const COMPRESSION_TAG_NONE = 0x00;
export const COMPRESSION_TAG_BROTLI = 0x01;
export const SALT_LENGTH = 16;
export const NONCE_LENGTH = 12;
export const AUTH_TAG_LENGTH = 16;
export const KEY_LENGTH = 32;
export const PBKDF2_ITERATIONS = 600000;
export const OPENING_PHRASE_WORD_COUNT = 6;
export const AMORSEAL_MARKER_TEXT = "amorseal";

const AMORSEAL_MARKER_BYTES = new TextEncoder().encode(AMORSEAL_MARKER_TEXT);
const AS01_MAGIC_BYTES = new TextEncoder().encode(MAGIC);

export const TX_FETCH_PROVIDERS = [
  {
    name: "blockstream-public",
    buildUrl: (txid) => `https://blockstream.info/api/tx/${txid}`,
    parseResponse: (responseJson) => responseJson,
  },
  {
    name: "blockchair-public",
    buildUrl: (txid) => `https://api.blockchair.com/bitcoin/dashboards/transaction/${txid}`,
    parseResponse: (responseJson, txid) => responseJson?.data?.[txid]?.decoded_raw_transaction ?? null,
  },
];

const TXID_REGEX = /^[0-9a-f]{64}$/i;

export function sanitizeSingleLine(value, label) {
  const trimmed = String(value ?? "").trim();
  if (!trimmed) {
    throw new Error(`The ${label} value is empty.`);
  }
  return trimmed;
}

// SPEC.md section 3.3
export function normalizeOpeningPhrase(value) {
  const normalized = sanitizeSingleLine(value, "opening phrase")
    .normalize("NFC")
    .trim()
    .replace(/\s+/g, " ")
    .toLowerCase();

  if (normalized.split(" ").length !== OPENING_PHRASE_WORD_COUNT) {
    throw new Error(`Opening phrase must contain exactly ${OPENING_PHRASE_WORD_COUNT} words.`);
  }

  return normalized;
}

// SPEC.md sections 5.1 and 5.2
export function unpackEnvelope(envelopeBytes) {
  if (envelopeBytes.byteLength < 14 + SALT_LENGTH + NONCE_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error("AS01 payload is truncated.");
  }

  const magic = new TextDecoder().decode(envelopeBytes.subarray(0, 4));
  if (magic !== MAGIC) {
    throw new Error("AS01 payload magic is invalid.");
  }

  const version = envelopeBytes[4];
  if (version !== VERSION) {
    throw new Error(`Unsupported AS01 version: 0x${version.toString(16)}.`);
  }

  if (
    envelopeBytes[5] !== ALGORITHM_TAG
    || envelopeBytes[6] !== KDF_TAG
    || (envelopeBytes[7] !== COMPRESSION_TAG_NONE && envelopeBytes[7] !== COMPRESSION_TAG_BROTLI)
  ) {
    throw new Error("AS01 payload uses an unsupported algorithm profile.");
  }

  const saltLength = envelopeBytes[8];
  const nonceLength = envelopeBytes[9];

  if (saltLength !== SALT_LENGTH || nonceLength !== NONCE_LENGTH) {
    throw new Error("AS01 payload declares unsupported salt or nonce lengths.");
  }

  const ciphertextLength = new DataView(
    envelopeBytes.buffer,
    envelopeBytes.byteOffset + 10,
    4,
  ).getUint32(0, false);
  const expectedLength = 14 + saltLength + nonceLength + ciphertextLength + AUTH_TAG_LENGTH;

  if (envelopeBytes.byteLength !== expectedLength) {
    throw new Error(envelopeBytes.byteLength < expectedLength
      ? "AS01 payload is truncated."
      : "AS01 payload contains trailing data.");
  }

  let offset = 14;
  const salt = envelopeBytes.slice(offset, offset + saltLength);
  offset += saltLength;
  const nonce = envelopeBytes.slice(offset, offset + nonceLength);
  offset += nonceLength;
  const ciphertext = envelopeBytes.slice(offset, offset + ciphertextLength);
  offset += ciphertextLength;
  const authTag = envelopeBytes.slice(offset, offset + AUTH_TAG_LENGTH);

  return {
    compressionTag: envelopeBytes[7],
    salt,
    nonce,
    ciphertext,
    authTag,
  };
}

export function decodeBase64Url(input) {
  if (!/^[A-Za-z0-9\-_]+$/.test(input)) {
    throw new Error("Invalid AS01 base64url payload.");
  }

  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const paddingLength = (4 - (base64.length % 4 || 4)) % 4;
  const padded = `${base64}${"=".repeat(paddingLength)}`;

  try {
    const binary = atobCompat(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    throw new Error("Invalid AS01 base64url payload.");
  }
}

export function encodeBase64Url(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoaCompat(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

// SPEC.md sections 8 and 9
export function findAs01PayloadInRawTxJson(rawTxJson) {
  const witnessItems = extractWitnessItemsFromRawTxJson(rawTxJson);
  return findAmorSealPayloadInWitnessItems(witnessItems);
}

export function extractWitnessItemsFromRawTxJson(rawTxJson) {
  const items = collectWitnessItems(rawTxJson);
  if (items.length === 0) {
    throw new Error("No witness items were found in the supplied raw transaction JSON.");
  }
  return items;
}

export function findAmorSealPayloadInWitnessItems(witnessItems) {
  const normalizedItems = witnessItems.map((item) => normalizeWitnessItem(item));

  for (let index = 0; index < normalizedItems.length; index += 1) {
    const current = normalizedItems[index];

    if (bytesEqual(current, AMORSEAL_MARKER_BYTES)) {
      const separatePayload = extractPayloadFromSeparateWitnessItems(normalizedItems, index);
      if (separatePayload) {
        return separatePayload;
      }
    }

    const inlinePayload = extractPayloadFromInlineWitnessItem(current);
    if (inlinePayload) {
      return inlinePayload;
    }
  }

  return null;
}

export function validateBitcoinTxid(txid) {
  const normalized = sanitizeSingleLine(txid, "txid").toLowerCase();
  if (!TXID_REGEX.test(normalized)) {
    throw new Error("Transaction id must be 64 hexadecimal characters.");
  }
  return normalized;
}

// SPEC.md section 11
export async function fetchRawTxByTxid(txid, fetchImpl = globalThis.fetch) {
  const normalizedTxid = validateBitcoinTxid(txid);

  if (typeof fetchImpl !== "function") {
    return {
      txid: normalizedTxid,
      providerName: null,
      rawTxJson: null,
      error: "No fetch implementation is available.",
    };
  }

  const errors = [];

  for (const provider of TX_FETCH_PROVIDERS) {
    try {
      const response = await fetchImpl(provider.buildUrl(normalizedTxid), {
        method: "GET",
        headers: {
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const responseJson = await response.json();
      const parsed = provider.parseResponse(responseJson, normalizedTxid);
      if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.vin)) {
        throw new Error("Provider did not return usable transaction JSON.");
      }

      return {
        txid: normalizedTxid,
        providerName: provider.name,
        rawTxJson: parsed,
        error: null,
      };
    } catch (error) {
      errors.push(`${provider.name}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return {
    txid: normalizedTxid,
    providerName: null,
    rawTxJson: null,
    error: errors.join(" | "),
  };
}

function collectWitnessItems(input) {
  if (input instanceof Uint8Array || typeof input === "string") {
    return [input];
  }

  if (Array.isArray(input)) {
    if (input.every((entry) => typeof entry === "string" || entry instanceof Uint8Array)) {
      return input;
    }

    return input.flatMap((entry) => collectWitnessItems(entry));
  }

  if (!input || typeof input !== "object") {
    return [];
  }

  const directKeys = ["txinwitness", "witness", "witnessItems", "witness_items"];
  const directMatches = [];

  for (const key of directKeys) {
    if (key in input) {
      directMatches.push(...collectWitnessItems(input[key]));
    }
  }

  if (directMatches.length > 0) {
    return directMatches;
  }

  if (Array.isArray(input.vin)) {
    return input.vin.flatMap((entry) => collectWitnessItems(entry));
  }

  return [];
}

function extractPayloadFromSeparateWitnessItems(items, markerIndex) {
  let nextIndex = markerIndex + 1;
  if (nextIndex >= items.length) {
    return null;
  }

  if (items[nextIndex].byteLength === 1) {
    nextIndex += 1;
  }

  for (let index = nextIndex; index < items.length; index += 1) {
    const candidate = extractEnvelopeFromBytes(items[index]);
    if (candidate) {
      return candidate;
    }
  }

  return null;
}

function extractPayloadFromInlineWitnessItem(item) {
  const markerOffset = indexOfBytes(item, AMORSEAL_MARKER_BYTES);

  if (markerOffset === -1) {
    return extractEnvelopeFromBytes(item);
  }

  const afterMarker = item.slice(markerOffset + AMORSEAL_MARKER_BYTES.byteLength);
  return extractEnvelopeFromBytes(afterMarker) ?? extractEnvelopeFromBytes(item);
}

function extractEnvelopeFromBytes(input) {
  const magicOffset = indexOfBytes(input, AS01_MAGIC_BYTES);
  if (magicOffset === -1) {
    return null;
  }

  if (input.byteLength < magicOffset + 14) {
    return null;
  }

  const saltLength = input[magicOffset + 8];
  const nonceLength = input[magicOffset + 9];
  const ciphertextLength = new DataView(
    input.buffer,
    input.byteOffset + magicOffset + 10,
    4,
  ).getUint32(0, false);
  const totalLength = 14 + saltLength + nonceLength + ciphertextLength + AUTH_TAG_LENGTH;

  if (input.byteLength < magicOffset + totalLength) {
    return null;
  }

  return input.slice(magicOffset, magicOffset + totalLength);
}

function normalizeWitnessItem(item) {
  if (item instanceof Uint8Array) {
    return item;
  }

  const trimmed = String(item).trim();
  if (!trimmed) {
    return new Uint8Array();
  }

  if (trimmed.toLowerCase() === AMORSEAL_MARKER_TEXT) {
    return AMORSEAL_MARKER_BYTES.slice();
  }

  if (/^(?:0x)?[0-9a-fA-F]+$/.test(trimmed) && trimmed.replace(/^0x/, "").length % 2 === 0) {
    return Uint8Array.from(hexToBytes(trimmed.replace(/^0x/, "")));
  }

  if (/^[A-Za-z0-9\-_]+$/.test(trimmed)) {
    const decoded = tryDecodeBase64(trimmed, true);
    if (decoded) {
      return decoded;
    }
  }

  if (/^[A-Za-z0-9+/=]+$/.test(trimmed)) {
    const decoded = tryDecodeBase64(trimmed, false);
    if (decoded) {
      return decoded;
    }
  }

  return new TextEncoder().encode(trimmed);
}

function tryDecodeBase64(value, isUrlSafe) {
  try {
    const normalized = isUrlSafe ? value.replace(/-/g, "+").replace(/_/g, "/") : value;
    const paddingLength = (4 - (normalized.length % 4 || 4)) % 4;
    const padded = `${normalized}${"=".repeat(paddingLength)}`;
    const binary = atobCompat(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }

    const roundtrip = isUrlSafe
      ? encodeBase64Url(bytes)
      : btoaCompat(binary).replace(/=+$/u, "");
    const expected = value.replace(/=+$/u, "");
    return roundtrip === expected ? bytes : null;
  } catch {
    return null;
  }
}

function hexToBytes(hex) {
  const bytes = [];
  for (let index = 0; index < hex.length; index += 2) {
    bytes.push(Number.parseInt(hex.slice(index, index + 2), 16));
  }
  return bytes;
}

function indexOfBytes(input, target) {
  if (target.byteLength === 0 || input.byteLength < target.byteLength) {
    return -1;
  }

  for (let start = 0; start <= input.byteLength - target.byteLength; start += 1) {
    let matches = true;
    for (let offset = 0; offset < target.byteLength; offset += 1) {
      if (input[start + offset] !== target[offset]) {
        matches = false;
        break;
      }
    }
    if (matches) {
      return start;
    }
  }
  return -1;
}

function bytesEqual(left, right) {
  if (left.byteLength !== right.byteLength) {
    return false;
  }

  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }

  return true;
}

function atobCompat(value) {
  if (typeof atob === "function") {
    return atob(value);
  }
  return Buffer.from(value, "base64").toString("binary");
}

function btoaCompat(value) {
  if (typeof btoa === "function") {
    return btoa(value);
  }
  return Buffer.from(value, "binary").toString("base64");
}
