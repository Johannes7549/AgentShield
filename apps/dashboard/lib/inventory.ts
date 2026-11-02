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
    status: "Live counts load from the control plane after sign-in. Empty means no rows, not a guessed number.",
  },
  {
    id: "agents",
    name: "Agents",
    phase: "Phase 1",
    status: "Agent rows load from the control plane after sign-in.",
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
    status: "Open incidents load from the control plane after sign-in.",
  },
  {
    id: "approvals",
    name: "Approval Requests",
    phase: "Phase 3",
    status: "Humans can approve or reject a pending request. This console does not call that API.",
  },
  {
    id: "chaos",
    name: "Chaos Experiments",
    phase: "Phase 5",
    status: "An owner or admin can run a catalog scenario from the API. This console does not launch experiments.",
  },
  {
    id: "audit",
    name: "Audit Logs",
    phase: "Phase 1",
    status: "Audit links load from the control plane. An operator can export a head-hash copy.",
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
