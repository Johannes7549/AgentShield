import { createHash } from "crypto";
import { hash, verify, Algorithm } from "@node-rs/argon2";

const options = {
  algorithm: Algorithm.Argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

export async function hashPassword(password: string): Promise<string> {
  const encoded = await hash(password, options);
  if (encoded.length < 60 || !encoded.startsWith("$argon2id$")) {
    throw new Error("password hash is invalid");
  }
  return encoded;
}

export async function verifyPassword(encoded: string, password: string): Promise<boolean> {
  if (!encoded.startsWith("$argon2id$")) {
    return false;
  }
  return verify(encoded, password, options);
}

export function hashSessionToken(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}
