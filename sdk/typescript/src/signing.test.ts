import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { publicKey, sign, signingInput } from "./signing.js";

const SEED = Buffer.alloc(32, 0x42);
const BODY = Buffer.from('{"tool":"tickets.read"}');

test("signing input and signature match the Go vector", () => {
  const digest = createHash("sha256").update(BODY).digest("hex");
  assert.equal(signingInput(1_700_000_000, "nonce-value-123456", BODY), `1700000000.nonce-value-123456.${digest}`);
  assert.equal(
    signingInput(1_700_000_000, "nonce-value-123456", BODY),
    "1700000000.nonce-value-123456.c64754e077ed2605c1a851045e3a42681df935f7482c6819446c8744f857cc28",
  );
  assert.equal(
    sign(SEED, 1_700_000_000, "nonce-value-123456", BODY),
    "fuxPrL6xKqaUrNI4eHSNfcIoPltHnPttEXvZdJL_tG2kYJ8L1Sy90OJNWpWczTkYrN9-y_oP9sCeloHIF2zoBA",
  );
  assert.equal(publicKey(SEED), "IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI");
});

test("a short nonce is rejected", () => {
  assert.throws(() => sign(SEED, 1, "short", BODY), /nonce is invalid/);
});
