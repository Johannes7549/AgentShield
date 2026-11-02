import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { liveHealth } from "./health";
import { areas, services } from "./inventory";

describe("dashboard foundation", () => {
  it("describes a phase 6 console", () => {
    const body = liveHealth();
    assert.equal(body.status, "ok");
    assert.equal(body.service, "dashboard");
    assert.equal(body.mode, "phase_6_console");
  });

  it("does not claim the gateway is ready", () => {
    const gateway = services.find((service) => service.name === "Gateway");
    assert.ok(gateway);
    assert.match(gateway.readiness, /not ready/i);
  });

  it("lists the ten console areas", () => {
    assert.equal(areas.length, 10);
    assert.deepEqual(
      areas.map((area) => area.name),
      [
        "Overview",
        "Agents",
        "Runtime Activity",
        "Security Policies",
        "Incidents",
        "Approval Requests",
        "Chaos Experiments",
        "Audit Logs",
        "Analytics",
        "Settings",
      ],
    );
  });
});
