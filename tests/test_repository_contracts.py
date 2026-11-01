import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "infrastructure" / "docker" / "postgres" / "migrations" / "0001_init.sql"
GENESIS = "0" * 64

REQUIRED_TABLES = [
    "users",
    "organizations",
    "memberships",
    "agents",
    "agent_credentials",
    "agent_permissions",
    "security_policies",
    "policy_versions",
    "executions",
    "tool_invocations",
    "authorization_decisions",
    "approval_requests",
    "security_incidents",
    "security_events",
    "audit_chain",
    "audit_chain_heads",
    "anomaly_alerts",
    "reliability_metrics",
    "chaos_scenarios",
    "chaos_executions",
    "schema_migrations",
]

CONTROL_PLANE_PATHS = [
    "/api/v1/agents",
    "/api/v1/agents/{agentId}/revoke",
    "/api/v1/policies",
    "/api/v1/policies/{policyId}",
    "/api/v1/approvals",
    "/api/v1/approvals/{approvalId}/approve",
    "/api/v1/approvals/{approvalId}/reject",
    "/api/v1/events",
    "/api/v1/incidents",
    "/api/v1/audit",
    "/api/v1/chaos/experiments",
    "/api/v1/chaos/experiments/{experimentId}",
]

GATEWAY_PATHS = [
    "/api/v1/runtime/authorize",
    "/api/v1/runtime/execute",
]


class RepositoryContractTests(unittest.TestCase):
    def test_required_documents_exist(self) -> None:
        for relative in [
            "docs/ARCHITECTURE.md",
            "docs/SECURITY_MODEL.md",
            "docs/DEVELOPMENT_ROADMAP.md",
            "docs/adr/0001-service-boundaries.md",
            "docs/adr/0002-policy-engine.md",
            "docs/adr/0003-agent-identity.md",
            "docs/adr/0004-authorization-decisions.md",
            "docs/adr/0005-audit-hash-chain.md",
            "docs/adr/0006-data-stores.md",
            "docs/adr/0007-api-contracts.md",
            "README.md",
            "LICENSE",
            "CONTRIBUTING.md",
        ]:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_migration_creates_required_tables(self) -> None:
        sql = MIGRATION.read_text(encoding="utf-8").lower()
        for table in REQUIRED_TABLES:
            self.assertIn(f"create table {table} (", sql)
        self.assertIn("agentshield_reject_mutation", sql)
        self.assertIn(GENESIS, sql)
        self.assertNotIn("private_key", sql)

    def test_genesis_hash_matches_the_go_constant(self) -> None:
        chain_path = ROOT / "runtime" / "gateway" / "internal" / "auditchain" / "chain.go"
        go_source = chain_path.read_text(encoding="utf-8")
        self.assertIn(GENESIS, go_source)

    def test_compose_starts_local_data_services_only(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        for service in ("postgres:", "redis:", "nats:", "minio:"):
            self.assertIn(service, compose)
        self.assertNotIn("clickhouse", compose.lower())
        self.assertIn("127.0.0.1:", compose)

    def test_openapi_contains_the_phase_contract(self) -> None:
        control = (ROOT / "docs" / "api" / "control-plane.openapi.yaml").read_text(encoding="utf-8")
        gateway = (ROOT / "docs" / "api" / "gateway.openapi.yaml").read_text(encoding="utf-8")
        for path in CONTROL_PLANE_PATHS:
            self.assertIn(path, control)
        for path in GATEWAY_PATHS:
            self.assertIn(path, gateway)
        self.assertIn("Not implemented", control)
        self.assertIn("Not implemented", gateway)

    def test_example_policy_lists_are_disjoint(self) -> None:
        example_path = ROOT / "docs" / "examples" / "customer-support-policy.json"
        document = json.loads(example_path.read_text(encoding="utf-8"))
        permissions = document["permissions"]
        allowed = set(permissions["allowed"])
        denied = set(permissions["denied"])
        approval = set(permissions["approval_required"])
        self.assertTrue(allowed.isdisjoint(denied))
        self.assertTrue(allowed.isdisjoint(approval))
        self.assertTrue(denied.isdisjoint(approval))
        self.assertIn("database.export", denied)
        self.assertIn("payment.refund", approval)
        schema_path = ROOT / "docs" / "schemas" / "policy.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertIn("permissions", schema["required"])


if __name__ == "__main__":
    unittest.main()
