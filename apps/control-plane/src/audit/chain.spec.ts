import { auditEventHash, occurredAt } from "./chain";

describe("audit chain", () => {
  it("matches the gateway hash for an approval decision", () => {
    const link = auditEventHash({
      prevHash: "0".repeat(64),
      eventId: "11111111-1111-4111-8111-111111111111",
      organizationId: "22222222-2222-4222-8222-222222222222",
      eventType: "approval.decided",
      occurredAt: "2026-11-02T12:00:00.000000000Z",
      payload: {
        decision: "approved",
        approval_id: "33333333-3333-4333-8333-333333333333",
      },
    });
    expect(link.payload).toBe(
      '{"approval_id":"33333333-3333-4333-8333-333333333333","decision":"approved"}',
    );
    expect(link.eventHash).toBe("1e32b77235a3c79d4539a33599dbed607617605e2e2bc8f032978324c2d76df6");
  });

  it("formats timestamps with the gateway nanosecond suffix", () => {
    expect(occurredAt(new Date("2026-11-02T12:00:00.000Z"))).toBe("2026-11-02T12:00:00.000000000Z");
  });
});
