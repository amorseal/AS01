const MAGIC = "AS01";
const VERSION = 0x01;
const ALGORITHM_TAG = 0x01;
const KDF_TAG = 0x01;
const COMPRESSION_TAG_NONE = 0x00;
const COMPRESSION_TAG_BROTLI = 0x01;
const SALT_LENGTH = 16;
const NONCE_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 600_000;
const AMORSEAL_MARKER_TEXT = "amorseal";
const AMORSEAL_MARKER_BYTES = new TextEncoder().encode(AMORSEAL_MARKER_TEXT);
const AS01_MAGIC_BYTES = new TextEncoder().encode(MAGIC);
const TXID_REGEX = /^[0-9a-f]{64}$/i;
const TX_FETCH_PROVIDERS = [
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

const modeInput = document.getElementById("mode");
const payloadLabel = document.getElementById("payload-label");
const payloadInput = document.getElementById("payload");
const phraseInput = document.getElementById("phrase");
const openButton = document.getElementById("open-button");
const statusNode = document.getElementById("status");
const errorNode = document.getElementById("error");
const outputNode = document.getElementById("output");
const outputTextNode = document.getElementById("output-text");

modeInput?.addEventListener("change", () => {
  updateModeCopy();
});

openButton?.addEventListener("click", () => {
  void recoverPayload();
});

updateModeCopy();

async function recoverPayload() {
  clearOutput();
  openButton.disabled = true;
  setStatus("Opening locally...");

  try {
    // SPEC.md section 9: resolve either raw payload bytes or payload bytes extracted
    // from raw witness data / txid-fetched transaction JSON.
    const payload = await resolveRecoveryPayload();
    const phrase = phraseInput.value;
    const envelopeBytes = typeof payload === "string" ? decodeBase64Url(payload) : payload;
    // SPEC.md sections 5 and 6: parse the AS01 envelope, normalize the phrase,
    // derive the AES-256-GCM key via PBKDF2-HMAC-SHA256, then decrypt.
    const envelope = unpackEnvelope(envelopeBytes);
    const normalizedPhrase = normalizeOpeningPhrase(phrase);
    const key = await deriveKey(normalizedPhrase, envelope.salt);
    const plaintextBytes = await decryptAndInflate(envelope, key);
    const plaintext = new TextDecoder().decode(plaintextBytes);
    outputTextNode.textContent = plaintext;
    outputNode.hidden = false;
    setStatus("Recovered locally in this browser.");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const generic = (
      message.includes("phrase did not unlock this letter")
      || message.includes("payload is corrupted")
      || message.includes("authentication failed")
      || /brotli/i.test(message)
    )
      ? message
      : message.startsWith("Unable to fetch transaction")
        ? message
      : `Unable to open: ${message}`;
    setError(generic);
  } finally {
    openButton.disabled = false;
  }
}

async function resolveRecoveryPayload() {
  const mode = modeInput?.value ?? "payload";

  if (mode === "raw-json") {
    const rawText = sanitizeSingleLine(payloadInput.value, "raw transaction JSON / witness JSON");
    let parsed;

    try {
      parsed = JSON.parse(rawText);
    } catch {
      throw new Error("Raw transaction / witness JSON is invalid.");
    }

    if (Array.isArray(parsed)) {
      const payload = findAmorSealPayloadInWitnessItems(parsed);
      if (!payload) {
        throw new Error("No Amor Seal AS01 payload was found in the supplied witness data.");
      }
      return payload;
    }

    const payload = findAs01PayloadInRawTxJson(parsed);
    if (!payload) {
      throw new Error("No Amor Seal AS01 payload was found in the supplied raw transaction.");
    }
    return payload;
  }

  if (mode === "txid") {
    const txid = validateTxid(sanitizeSingleLine(payloadInput.value, "Bitcoin txid"));
    const fetched = await fetchRawTxByTxid(txid);

    if (!fetched.rawTxJson) {
      throw new Error("Unable to fetch transaction in this browser. Paste raw transaction JSON instead.");
    }

    const payload = findAs01PayloadInRawTxJson(fetched.rawTxJson);
    if (!payload) {
      throw new Error("No Amor Seal AS01 payload was found in the fetched transaction witness data.");
    }

    return payload;
  }

  return sanitizeSingleLine(payloadInput.value, "payload");
}

async function decryptAndInflate(envelope, key) {
  const ciphertextPlusTag = concatBytes(envelope.ciphertext, envelope.authTag);
  let decrypted;

  try {
    decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: envelope.nonce,
        tagLength: AUTH_TAG_LENGTH * 8,
      },
      key,
      ciphertextPlusTag,
    );
  } catch {
    throw new Error("The phrase did not unlock this letter.");
  }

  return decompressPayload(new Uint8Array(decrypted), envelope.compressionTag);
}

async function deriveKey(phrase, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(phrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    {
      name: "AES-GCM",
      length: KEY_LENGTH * 8,
    },
    false,
    ["decrypt"],
  );
}

async function decompressPayload(input, compressionTag) {
  if (compressionTag === COMPRESSION_TAG_NONE) {
    return input;
  }

  if (compressionTag !== COMPRESSION_TAG_BROTLI) {
    throw new Error("AS01 payload uses an unsupported compression tag.");
  }

  if (window.AmorSealBrotliDecoder && typeof window.AmorSealBrotliDecoder.decompress === "function") {
    try {
      return window.AmorSealBrotliDecoder.decompress(input);
    } catch {
      throw new Error("The phrase did not unlock this letter.");
    }
  }

  throw new Error("Browser offline recovery requires a browser-compatible Brotli decoder.");
}

function unpackEnvelope(envelopeBytes) {
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

  const ciphertextLength = new DataView(envelopeBytes.buffer, envelopeBytes.byteOffset + 10, 4).getUint32(0, false);
  const expectedLength = 14 + saltLength + nonceLength + ciphertextLength + AUTH_TAG_LENGTH;

  if (envelopeBytes.byteLength !== expectedLength) {
    throw new Error(envelopeBytes.byteLength < expectedLength ? "AS01 payload is truncated." : "AS01 payload contains trailing data.");
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

function findAs01PayloadInRawTxJson(rawTxJson) {
  const witnessItems = extractWitnessItemsFromRawTxJson(rawTxJson);
  return findAmorSealPayloadInWitnessItems(witnessItems);
}

async function fetchRawTxByTxid(txid) {
  const errors = [];

  for (const provider of TX_FETCH_PROVIDERS) {
    try {
      const response = await fetch(provider.buildUrl(txid), {
        method: "GET",
        headers: {
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const responseJson = await response.json();
      const parsed = provider.parseResponse(responseJson, txid);

      if (!parsed || typeof parsed !== "object") {
        throw new Error("Provider did not return usable transaction JSON.");
      }

      return {
        txid,
        providerName: provider.name,
        rawTxJson: parsed,
      };
    } catch (error) {
      errors.push(`${provider.name}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return {
    txid,
    providerName: null,
    rawTxJson: null,
    error: errors.join(" | "),
  };
}

function extractWitnessItemsFromRawTxJson(rawTxJson) {
  const items = collectWitnessItems(rawTxJson);

  if (items.length === 0) {
    throw new Error("No witness items were found in the supplied raw transaction JSON.");
  }

  return items;
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

function findAmorSealPayloadInWitnessItems(witnessItems) {
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
  const ciphertextLength = new DataView(input.buffer, input.byteOffset + magicOffset + 10, 4).getUint32(0, false);
  const totalLength = 14 + saltLength + nonceLength + ciphertextLength + AUTH_TAG_LENGTH;

  if (input.byteLength < magicOffset + totalLength) {
    return null;
  }

  return input.slice(magicOffset, magicOffset + totalLength);
}

function decodeBase64Url(input) {
  if (!/^[A-Za-z0-9\-_]+$/.test(input)) {
    throw new Error("Invalid AS01 base64url payload.");
  }

  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const paddingLength = (4 - (base64.length % 4 || 4)) % 4;
  const padded = `${base64}${"=".repeat(paddingLength)}`;

  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);

    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }

    return bytes;
  } catch {
    throw new Error("Invalid AS01 base64url payload.");
  }
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
    const hex = trimmed.replace(/^0x/, "");
    return Uint8Array.from(hexToBytes(hex));
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
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);

    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }

    const roundtrip = isUrlSafe
      ? encodeBase64Url(bytes)
      : btoa(binary).replace(/=+$/u, "");
    const expected = isUrlSafe ? value.replace(/=+$/u, "") : value.replace(/=+$/u, "");

    return roundtrip === expected ? bytes : null;
  } catch {
    return null;
  }
}

function encodeBase64Url(bytes) {
  let binary = "";

  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function hexToBytes(hex) {
  const bytes = [];

  for (let index = 0; index < hex.length; index += 2) {
    bytes.push(Number.parseInt(hex.slice(index, index + 2), 16));
  }

  return bytes;
}

function normalizeOpeningPhrase(input) {
  const normalized = input.normalize("NFC").trim().replace(/\s+/g, " ").toLowerCase();

  if (!normalized) {
    throw new Error("Opening phrase is required.");
  }

  return normalized;
}

function validateTxid(input) {
  const normalized = input.trim().toLowerCase();

  if (!TXID_REGEX.test(normalized)) {
    throw new Error("Transaction id must be 64 hexadecimal characters.");
  }

  return normalized;
}

function sanitizeSingleLine(input, label) {
  const trimmed = input.trim();

  if (!trimmed) {
    throw new Error(`A non-empty ${label} is required.`);
  }

  return trimmed;
}

function concatBytes(left, right) {
  const output = new Uint8Array(left.byteLength + right.byteLength);
  output.set(left, 0);
  output.set(right, left.byteLength);
  return output;
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

function clearOutput() {
  statusNode.hidden = true;
  statusNode.textContent = "";
  errorNode.hidden = true;
  errorNode.textContent = "";
  outputNode.hidden = true;
  outputTextNode.textContent = "";
}

function setStatus(message) {
  statusNode.hidden = false;
  statusNode.textContent = message;
  errorNode.hidden = true;
  errorNode.textContent = "";
}

function setError(message) {
  errorNode.hidden = false;
  errorNode.textContent = message;
  statusNode.hidden = true;
  statusNode.textContent = "";
  outputNode.hidden = true;
  outputTextNode.textContent = "";
}

function updateModeCopy() {
  const mode = modeInput?.value ?? "payload";

  if (mode === "txid") {
    payloadLabel.textContent = "Bitcoin txid";
    payloadInput.placeholder = "Paste the 64-character Bitcoin transaction id here.";
    return;
  }

  if (mode === "raw-json") {
    payloadLabel.textContent = "Raw transaction JSON / witness JSON";
    payloadInput.placeholder = "{\n  \"vin\": [\n    { \"txinwitness\": [\"amorseal\", \"01\", \"...\"] }\n  ]\n}";
    return;
  }

  payloadLabel.textContent = "AS01 payload";
  payloadInput.placeholder = "Paste the AS01 base64url payload here.";
}
