import { NextResponse } from "next/server";
import { liveHealth } from "../../../lib/health";

export function GET() {
  return NextResponse.json(liveHealth());
}
