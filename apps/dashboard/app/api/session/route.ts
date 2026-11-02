import { NextResponse } from "next/server";
import { controlPlaneBase } from "../../../lib/control-plane";

export async function POST(request: Request): Promise<Response> {
  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") {
    return NextResponse.json({ error: { code: "validation_failed", message: "request body is invalid" } }, { status: 400 });
  }
  const response = await fetch(`${controlPlaneBase()}/api/v1/sessions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({ error: { code: "internal_error", message: "internal error" } }));
  if (!response.ok) {
    return NextResponse.json(payload, { status: response.status });
  }
  const result = NextResponse.json({ organization_id: payload.organization_id, expires_at: payload.expires_at });
  result.cookies.set("agentshield_session", payload.token, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    secure: false,
  });
  return result;
}

export async function DELETE(): Promise<Response> {
  const result = NextResponse.json({ status: "ok" });
  result.cookies.set("agentshield_session", "", { httpOnly: true, path: "/", maxAge: 0 });
  return result;
}
