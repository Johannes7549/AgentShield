import { rejectsSelfApproval } from "./self-approval";

describe("self approval", () => {
  it("rejects an approver whose id is the agent id", () => {
    const agent = "11111111-1111-4111-8111-111111111111";
    expect(rejectsSelfApproval(agent, agent)).toBe(true);
    expect(rejectsSelfApproval(agent, "22222222-2222-4222-8222-222222222222")).toBe(false);
  });
});
