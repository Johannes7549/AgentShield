-- Application role and organization RLS. The Compose owner still owns tables
-- and bypasses RLS so migrations and bootstrap keep working. Production
-- processes must connect as agentshield_app and set app.organization_id.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agentshield_app') THEN
    CREATE ROLE agentshield_app LOGIN PASSWORD 'agentshield-app';
  END IF;
END
$$;

GRANT CONNECT ON DATABASE agentshield TO agentshield_app;
GRANT USAGE ON SCHEMA public TO agentshield_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO agentshield_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO agentshield_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO agentshield_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO agentshield_app;

CREATE OR REPLACE FUNCTION agentshield_current_organization()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('app.organization_id', true), '')::uuid;
$$;

REVOKE ALL ON FUNCTION agentshield_current_organization() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agentshield_current_organization() TO agentshield_app;

-- SECURITY DEFINER lookup so the gateway can authenticate before it knows the organization.
CREATE OR REPLACE FUNCTION agentshield_lookup_agent(p_agent_id uuid)
RETURNS TABLE (
  organization_id uuid,
  agent_status text,
  public_key bytea,
  credential_status text,
  not_before timestamptz,
  not_after timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  RETURN QUERY
  SELECT a.organization_id, a.status, c.public_key, c.status, c.not_before, c.not_after
  FROM agents a
  LEFT JOIN agent_credentials c
    ON c.agent_id = a.id AND c.organization_id = a.organization_id
  WHERE a.id = p_agent_id
  ORDER BY c.created_at DESC NULLS LAST;
END;
$$;

REVOKE ALL ON FUNCTION agentshield_lookup_agent(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agentshield_lookup_agent(uuid) TO agentshield_app;

-- Tenant tables. Owner connections bypass RLS. agentshield_app does not.
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_invocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE anomaly_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE reliability_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE chaos_executions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS memberships_org ON memberships;
CREATE POLICY memberships_org ON memberships
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS user_sessions_org ON user_sessions;
CREATE POLICY user_sessions_org ON user_sessions
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS agents_org ON agents;
CREATE POLICY agents_org ON agents
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS agent_credentials_org ON agent_credentials;
CREATE POLICY agent_credentials_org ON agent_credentials
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS security_policies_org ON security_policies;
CREATE POLICY security_policies_org ON security_policies
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS policy_versions_org ON policy_versions;
CREATE POLICY policy_versions_org ON policy_versions
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS agent_permissions_org ON agent_permissions;
CREATE POLICY agent_permissions_org ON agent_permissions
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS executions_org ON executions;
CREATE POLICY executions_org ON executions
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS tool_invocations_org ON tool_invocations;
CREATE POLICY tool_invocations_org ON tool_invocations
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS authorization_decisions_org ON authorization_decisions;
CREATE POLICY authorization_decisions_org ON authorization_decisions
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS approval_requests_org ON approval_requests;
CREATE POLICY approval_requests_org ON approval_requests
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS security_incidents_org ON security_incidents;
CREATE POLICY security_incidents_org ON security_incidents
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS security_events_org ON security_events;
CREATE POLICY security_events_org ON security_events
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS audit_chain_org ON audit_chain;
CREATE POLICY audit_chain_org ON audit_chain
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS audit_chain_heads_org ON audit_chain_heads;
CREATE POLICY audit_chain_heads_org ON audit_chain_heads
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS anomaly_alerts_org ON anomaly_alerts;
CREATE POLICY anomaly_alerts_org ON anomaly_alerts
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS reliability_metrics_org ON reliability_metrics;
CREATE POLICY reliability_metrics_org ON reliability_metrics
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

DROP POLICY IF EXISTS chaos_executions_org ON chaos_executions;
CREATE POLICY chaos_executions_org ON chaos_executions
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

CREATE TABLE IF NOT EXISTS audit_head_exports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  sequence bigint NOT NULL,
  head_hash text NOT NULL,
  exported_at timestamptz NOT NULL DEFAULT now(),
  destination text NOT NULL,
  CONSTRAINT audit_head_exports_hash_ck CHECK (head_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT audit_head_exports_sequence_ck CHECK (sequence >= 0),
  CONSTRAINT audit_head_exports_destination_ck CHECK (char_length(btrim(destination)) BETWEEN 1 AND 256)
);

CREATE INDEX IF NOT EXISTS audit_head_exports_org_exported_idx
  ON audit_head_exports (organization_id, exported_at DESC);

ALTER TABLE audit_head_exports ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_head_exports_org ON audit_head_exports;
CREATE POLICY audit_head_exports_org ON audit_head_exports
  USING (organization_id = agentshield_current_organization())
  WITH CHECK (organization_id = agentshield_current_organization());

GRANT SELECT, INSERT ON audit_head_exports TO agentshield_app;

-- Session authentication must resolve a token before the organization GUC is set.
CREATE OR REPLACE FUNCTION agentshield_resolve_session(p_token_hash bytea)
RETURNS TABLE (
  user_id uuid,
  organization_id uuid,
  role text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  RETURN QUERY
  SELECT s.user_id, s.organization_id, m.role::text
  FROM user_sessions s
  JOIN memberships m ON m.user_id = s.user_id AND m.organization_id = s.organization_id
  JOIN users u ON u.id = s.user_id
  WHERE s.token_hash = p_token_hash
    AND s.revoked_at IS NULL
    AND s.expires_at > now()
    AND u.status = 'active';
END;
$$;

REVOKE ALL ON FUNCTION agentshield_resolve_session(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agentshield_resolve_session(bytea) TO agentshield_app;

CREATE OR REPLACE FUNCTION agentshield_login_candidates(p_email text)
RETURNS TABLE (
  user_id uuid,
  password_hash text,
  user_status text,
  organization_id uuid
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  RETURN QUERY
  SELECT u.id, u.password_hash, u.status, o.id
  FROM users u
  LEFT JOIN memberships m ON m.user_id = u.id
  LEFT JOIN organizations o ON o.id = m.organization_id AND o.status = 'active'
  WHERE u.email = p_email;
END;
$$;

REVOKE ALL ON FUNCTION agentshield_login_candidates(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agentshield_login_candidates(text) TO agentshield_app;

CREATE OR REPLACE FUNCTION agentshield_create_session(
  p_user_id uuid,
  p_organization_id uuid,
  p_token_hash bytea,
  p_expires_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  INSERT INTO user_sessions (user_id, organization_id, token_hash, expires_at)
  VALUES (p_user_id, p_organization_id, p_token_hash, p_expires_at);
END;
$$;

REVOKE ALL ON FUNCTION agentshield_create_session(uuid, uuid, bytea, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agentshield_create_session(uuid, uuid, bytea, timestamptz) TO agentshield_app;

INSERT INTO schema_migrations (version) VALUES ('0004_app_role_rls')
ON CONFLICT (version) DO NOTHING;
