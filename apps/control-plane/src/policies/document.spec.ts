import { canonicalJson, documentHash, validatePolicyDocument } from "./document";

const canonical =
  '{"permissions":{"allowed":["sample.echo"],"approval_required":["email.send"],"denied":["database.export"]}}';

describe("policy documents", () => {
  it("canonicalizes to the same bytes as the gateway", () => {
    const document = validatePolicyDocument({
      permissions: {
        denied: ["database.export"],
        allowed: ["sample.echo"],
        approval_required: ["email.send"],
      },
    });
    expect(canonicalJson(document)).toBe(canonical);
    expect(documentHash(document)).toHaveLength(64);
  });

  it("rejects an action that appears in two lists", () => {
    expect(() =>
      validatePolicyDocument({
        permissions: {
          allowed: ["tickets.read"],
          denied: ["tickets.read"],
          approval_required: [],
        },
      }),
    ).toThrow(/both/);
  });

  it("rejects a resource rule that grants a new action", () => {
    expect(() =>
      validatePolicyDocument({
        permissions: { allowed: [], denied: [], approval_required: [] },
        resource_rules: [{ effect: "allow", action: "tickets.read", resource: "ticket-1" }],
      }),
    ).toThrow(/narrow/);
  });

  it("rejects secret fields", () => {
    expect(() =>
      validatePolicyDocument({
        permissions: { allowed: [], denied: [], approval_required: [] },
        private_key: "no",
      }),
    ).toThrow(/unknown field/);
  });
});
