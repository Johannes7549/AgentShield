import { execFile } from "child_process";
import { existsSync } from "fs";
import path from "path";
import { promisify } from "util";

const exec = promisify(execFile);

export interface ChaosRun {
  status: "passed" | "failed" | "error";
  reason: string;
}

export interface ChaosRunner {
  run(scenarioId: string): Promise<ChaosRun>;
}

export const CHAOS_RUNNER = Symbol("CHAOS_RUNNER");

export class GoChaosRunner implements ChaosRunner {
  async run(scenarioId: string): Promise<ChaosRun> {
    const root = path.resolve(__dirname, "../../../..");
    const bundled = path.join(root, ".tools", "go", "bin", process.platform === "win32" ? "go.exe" : "go");
    const go = process.env.AGENTSHIELD_GO || (existsSync(bundled) ? bundled : "go");
    try {
      const { stdout } = await exec(go, ["run", "./cmd/chaos-harness", scenarioId], {
        cwd: path.join(root, "runtime", "gateway"),
        timeout: 60_000,
        env: { ...process.env, GOTOOLCHAIN: "local" },
      });
      const parsed = JSON.parse(stdout) as { status?: string; reason?: string };
      if (parsed.status !== "passed" && parsed.status !== "failed" && parsed.status !== "error") {
        return { status: "error", reason: "runner unavailable" };
      }
      const reason = typeof parsed.reason === "string" && parsed.reason.length > 0 ? parsed.reason : "missing result";
      return { status: parsed.status, reason };
    } catch {
      return { status: "error", reason: "runner unavailable" };
    }
  }
}
