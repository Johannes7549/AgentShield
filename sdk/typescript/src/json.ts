/** JSON encoding that matches the Python SDK byte for byte on the same value. */

export function encodeJson(value: unknown): Buffer {
  return Buffer.from(stringify(value), "utf8");
}

function stringify(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error("value must use integers");
    }
    return String(value);
  }
  if (typeof value === "string") {
    return quote(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stringify(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0,
    );
    return `{${entries.map(([key, item]) => `${quote(key)}:${stringify(item)}`).join(",")}}`;
  }
  throw new Error("value must be a JSON object, array, string, integer, boolean, or null");
}

function quote(value: string): string {
  let out = '"';
  for (const symbol of value) {
    const codePoint = symbol.codePointAt(0);
    if (codePoint === undefined) {
      continue;
    }
    if (symbol === '"') {
      out += '\\"';
    } else if (symbol === "\\") {
      out += "\\\\";
    } else if (symbol === "\b") {
      out += "\\b";
    } else if (symbol === "\f") {
      out += "\\f";
    } else if (symbol === "\n") {
      out += "\\n";
    } else if (symbol === "\r") {
      out += "\\r";
    } else if (symbol === "\t") {
      out += "\\t";
    } else if (codePoint < 0x20 || codePoint === 0x7f || codePoint > 0x7e) {
      out += escapeCodePoint(codePoint);
    } else {
      out += symbol;
    }
  }
  return `${out}"`;
}

function escapeCodePoint(codePoint: number): string {
  if (codePoint > 0xffff) {
    const adjusted = codePoint - 0x10000;
    const high = 0xd800 + (adjusted >> 10);
    const low = 0xdc00 + (adjusted & 0x3ff);
    return `${unit(high)}${unit(low)}`;
  }
  return unit(codePoint);
}

function unit(codePoint: number): string {
  return `\\u${codePoint.toString(16).padStart(4, "0")}`;
}
