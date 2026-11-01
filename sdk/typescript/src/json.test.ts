import assert from "node:assert/strict";
import test from "node:test";

import { encodeJson } from "./json.js";

test("encodeJson matches the Python SDK byte string", () => {
  const encoded = encodeJson({ q: 'a"b', z: [1, true, null], n: "é", e: "😀" });
  assert.equal(
    encoded.toString("utf8"),
    '{"e":"\\ud83d\\ude00","n":"\\u00e9","q":"a\\"b","z":[1,true,null]}',
  );
});
