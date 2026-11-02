export function rejectsSelfApproval(agentId: string, userId: string): boolean {
  return agentId !== "" && agentId === userId;
}
