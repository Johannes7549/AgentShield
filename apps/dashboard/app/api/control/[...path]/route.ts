import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { controlPlaneFetch } from "../../../../lib/control-plane";

async function proxy(request: Request, path: string[]): Promise<Response> {
  const jar = await cookies();
  const token = jar.get("agentshield_session")?.value ?? process.env.CONTROL_PLANE_TOKEN;
  if (!token) {
    return NextResponse.json({ error: { code: "unauthenticated", message: "sign in required" } }, { status: 401 });
  }
  const url = new URL(request.url);
  const target = `/api/${path.join("/")}${url.search}`;
  const response = await controlPlaneFetch(target, token, {
    method: request.method,
    body: request.method === "GET" || request.method === "HEAD" ? undefined : await request.text(),
  });
  const text = await response.text();
  return new NextResponse(text, {
    status: response.status,
    headers: { "Content-Type": response.headers.get("Content-Type") ?? "application/json" },
  });
}

export async function GET(request: Request, context: { params: Promise<{ path: string[] }> }): Promise<Response> {
  const { path } = await context.params;
  return proxy(request, path);
}

export async function POST(request: Request, context: { params: Promise<{ path: string[] }> }): Promise<Response> {
  const { path } = await context.params;
  return proxy(request, path);
}
