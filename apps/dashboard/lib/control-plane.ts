const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL ?? "http://127.0.0.1:8080";

export function controlPlaneBase(): string {
  return CONTROL_PLANE_URL.replace(/\/$/, "");
}

export async function controlPlaneFetch(path: string, token: string, init?: RequestInit): Promise<Response> {
  return fetch(`${controlPlaneBase()}${path}`, {
    ...init,
    headers: {
      ...(init?.headers ?? {}),
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    cache: "no-store",
  });
}
