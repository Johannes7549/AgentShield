/**
 * Ed25519 signatures over the AgentShield v1 signing input.
 * The seed stays with the caller. This module never sends it.
 */

import { createHash, createPrivateKey, createPublicKey, sign as edSign } from "node:crypto";

const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function signingInput(timestamp: number, nonce: string, body: Buffer): string {
  const digest = createHash("sha256").update(body).digest("hex");
  return `${timestamp}.${nonce}.${digest}`;
}

export function sign(seed: Buffer, timestamp: number, nonce: string, body: Buffer): string {
  if (!NONCE_PATTERN.test(nonce)) {
    throw new Error("nonce is invalid");
  }
  const message = Buffer.from(signingInput(timestamp, nonce, body), "ascii");
  return edSign(null, message, privateKey(seed)).toString("base64url");
}

export function publicKey(seed: Buffer): string {
  const exported = createPublicKey(privateKey(seed)).export({ format: "der", type: "spki" });
  const der = Buffer.isBuffer(exported) ? exported : Buffer.from(exported);
  return der.subarray(der.length - 32).toString("base64url");
}

function privateKey(seed: Buffer) {
  if (seed.length !== 32) {
    throw new Error("seed must be 32 bytes");
  }
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}
