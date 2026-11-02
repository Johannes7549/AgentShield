export const SERVICE_VERSION = "0.1.0";

export function liveHealth() {
  return {
    status: "ok" as const,
    service: "dashboard" as const,
    version: SERVICE_VERSION,
    mode: "phase_6_console" as const,
  };
}
