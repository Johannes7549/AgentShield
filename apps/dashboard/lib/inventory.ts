export interface ConsoleArea {
  id: string;
  name: string;
  phase: string;
  status: string;
}

export interface ServiceStatus {
  name: string;
  address: string;
  readiness: string;
}

export const areas: ConsoleArea[] = [
  {
    id: "overview",
    name: "Overview",
    phase: "Phase 6",
    status: "No live posture counts are connected. This page does not invent metrics.",
  },
  {
    id: "agents",
    name: "Agents",
    phase: "Phase 1",
    status: "The control plane registers agents. This console does not call it.",
  },
  {
    id: "runtime",
    name: "Runtime Activity",
    phase: "Phase 1",
    status: "The gateway authorizes signed tool calls. This console does not stream them.",
  },
  {
    id: "policies",
    name: "Security Policies",
    phase: "Phase 1",
    status: "Policies are evaluated in the gateway. This console does not edit them.",
  },
  {
    id: "incidents",
    name: "Incidents",
    phase: "Phase 4",
    status: "Incident storage exists in the schema. Detection rules are not running.",
  },
  {
    id: "approvals",
    name: "Approval Requests",
    phase: "Phase 3",
    status: "The gateway records require_approval. Human approval is not executable yet.",
  },
  {
    id: "chaos",
    name: "Chaos Experiments",
    phase: "Phase 5",
    status: "Scenario catalog is documentation only. Experiments cannot be launched.",
  },
  {
    id: "audit",
    name: "Audit Logs",
    phase: "Phase 1",
    status: "The gateway appends hash-chain events. This console has no event reader.",
  },
  {
    id: "analytics",
    name: "Analytics",
    phase: "Phase 6",
    status: "Analytical storage is intentionally not deployed.",
  },
  {
    id: "settings",
    name: "Settings",
    phase: "Phase 6",
    status: "Organization and user administration are not implemented.",
  },
];

export const services: ServiceStatus[] = [
  {
    name: "Control plane",
    address: "127.0.0.1:8080",
    readiness: "Not ready in this console. Management routes exist on the control plane.",
  },
  {
    name: "Gateway",
    address: "127.0.0.1:8081",
    readiness: "Not ready in this console. Authorization runs in the gateway when its dependencies answer.",
  },
  {
    name: "Intelligence",
    address: "127.0.0.1:8082",
    readiness: "Not ready. Content analysis is not implemented.",
  },
  {
    name: "Dashboard",
    address: "127.0.0.1:3000",
    readiness: "Shell only. It does not display live security data.",
  },
];
