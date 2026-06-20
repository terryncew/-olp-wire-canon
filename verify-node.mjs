import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MAX_SAFE = Number.MAX_SAFE_INTEGER;

function asciiJsonString(value) {
  return JSON.stringify(value).replace(/[^\x00-\x7f]/g, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`
  );
}

export function canonical(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return asciiJsonString(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Math.abs(value) > MAX_SAFE) {
      throw new Error("non-interoperable number");
    }
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.some((key) => /[^\x00-\x7f]/.test(key))) {
      throw new Error("non-ASCII object key");
    }
    return `{${keys.sort().map((key) =>
      `${asciiJsonString(key)}:${canonical(value[key])}`
    ).join(",")}}`;
  }
  throw new Error(`unsupported type: ${typeof value}`);
}

export function verify(receipt) {
  const body = structuredClone(receipt);
  const signature = body.signature;
  const payloadHash = body.payload_hash;
  delete body.signature;
  delete body.payload_hash;

  if (body.canonicalization_id !== "olp-canonical-json-int-v1") {
    throw new Error("unsupported canonicalization profile");
  }
  if (signature.algorithm !== "Ed25519") {
    throw new Error("unsupported signature algorithm");
  }
  const payload = Buffer.from(canonical(body), "ascii");
  const actualHash = crypto.createHash("sha256").update(payload).digest("hex");
  if (actualHash !== payloadHash) throw new Error("payload hash mismatch");

  const publicKey = Buffer.from(signature.public_key, "hex");
  const signatureBytes = Buffer.from(signature.value, "hex");
  if (publicKey.length !== 32 || signatureBytes.length !== 64) {
    throw new Error("invalid Ed25519 encoding length");
  }
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const key = crypto.createPublicKey({
    key: Buffer.concat([spkiPrefix, publicKey]),
    format: "der",
    type: "spki",
  });
  if (!crypto.verify(null, payload, key, signatureBytes)) {
    throw new Error("invalid Ed25519 signature");
  }
  return payloadHash;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const paths = process.argv.slice(2);
  if (paths.length === 0) throw new Error("usage: node verify-node.mjs RECEIPT.json [...]");
  for (const receiptPath of paths) {
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    const payloadHash = verify(receipt);
    console.log(`verified ${receipt.kind} ${payloadHash}`);
  }
}
