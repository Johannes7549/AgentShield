-- AgentShield transactional schema, revision 0001.
--
-- This file is the schema source of truth. Docker applies it only when the
-- Postgres data volume is created for the first time.
--
-- Authorization rows are not projections of client input. Organization columns
-- exist so composite foreign keys can reject cross-organization references.
-- Row level security is intentionally not enabled: turning it on before the
-- application sets a session organization would make an empty policy fail
-- closed in a way this revision cannot operate. See docs/SECURITY_MODEL.md.
--
-- Secret key material is intentionally absent. Agent authentication stores a
-- 32-byte Ed25519 public key and its fingerprint.

CREATE EXTENSION IF NOT EXISTS citext;

-- ---------------------------------------------------------------------------
-- Tenancy and human identity
-- ---------------------------------------------------------------------------

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email citext NOT NULL UNIQUE,
  password_hash text NOT NULL,
  display_name text NOT NULL,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT users_email_ck CHECK (
    char_length(email::text) >= 3 AND position('@' IN email::text) > 1
  ),
  CONSTRAINT users_password_hash_ck CHECK (char_length(password_hash) >= 60),
  CONSTRAINT users_display_name_ck CHECK (char_length(btrim(display_name)) > 0),
  CONSTRAINT users_status_ck CHECK (status IN ('active', 'disabled'))
);

CREATE TABLE organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  slug text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT organizations_name_ck CHECK (char_length(btrim(name)) > 0),
  CONSTRAINT organizations_slug_ck CHECK (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
  CONSTRAINT organizations_status_ck CHECK (status IN ('active', 'suspended'))
);

CREATE TABLE memberships (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
  role text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT memberships_role_ck CHECK (
    role IN ('owner', 'admin', 'operator', 'auditor', 'approver')
  ),
  CONSTRAINT memberships_org_user_uq UNIQUE (organization_id, user_id)
);

-- ---------------------------------------------------------------------------
-- Agents and credentials
-- ---------------------------------------------------------------------------

CREATE TABLE agents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  name text NOT NULL,
  framework text NOT NULL,
  status text NOT NULL DEFAULT 'active',
  -- Display metadata only. The policy engine does not authorize from this column.
  permission_scope jsonb NOT NULL DEFAULT '{}'::jsonb,
  registered_at timestamptz NOT NULL DEFAULT now(),
  last_activity_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agents_org_pair_uq UNIQUE (id, organization_id),
  CONSTRAINT agents_org_name_uq UNIQUE (organization_id, name),
  CONSTRAINT agents_name_ck CHECK (char_length(btrim(name)) BETWEEN 1 AND 128),
  CONSTRAINT agents_framework_ck CHECK (framework IN (
    'langchain', 'langgraph', 'crewai', 'openai_agents', 'python', 'typescript', 'mcp', 'custom'
  )),
  CONSTRAINT agents_status_ck CHECK (status IN ('active', 'suspended', 'revoked')),
  CONSTRAINT agents_permission_scope_ck CHECK (jsonb_typeof(permission_scope) = 'object')
);

CREATE TABLE agent_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  algorithm text NOT NULL DEFAULT 'ed25519',
  public_key bytea NOT NULL,
  public_key_fingerprint text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'active',
  not_before timestamptz NOT NULL DEFAULT now(),
  not_after timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_credentials_agent_org_fk
    FOREIGN KEY (agent_id, organization_id)
    REFERENCES agents (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT agent_credentials_algorithm_ck CHECK (algorithm = 'ed25519'),
  CONSTRAINT agent_credentials_public_key_len_ck CHECK (octet_length(public_key) = 32),
  CONSTRAINT agent_credentials_fingerprint_ck CHECK (public_key_fingerprint ~ '^[0-9a-f]{64}$'),
  CONSTRAINT agent_credentials_status_ck CHECK (status IN ('active', 'rotated', 'revoked')),
  CONSTRAINT agent_credentials_revocation_ck CHECK (
    (status = 'revoked' AND revoked_at IS NOT NULL)
    OR (status <> 'revoked' AND revoked_at IS NULL)
  ),
  CONSTRAINT agent_credentials_window_ck CHECK (not_after IS NULL OR not_after > not_before)
);

-- ---------------------------------------------------------------------------
-- Policies. Versions are immutable. The current pointer lives on the parent.
-- ---------------------------------------------------------------------------

CREATE TABLE security_policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  name text NOT NULL,
  scope text NOT NULL,
  agent_id uuid,
  status text NOT NULL DEFAULT 'draft',
  current_version_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT security_policies_org_pair_uq UNIQUE (id, organization_id),
  CONSTRAINT security_policies_org_name_uq UNIQUE (organization_id, name),
  CONSTRAINT security_policies_name_ck CHECK (char_length(btrim(name)) BETWEEN 1 AND 128),
  CONSTRAINT security_policies_scope_ck CHECK (scope IN ('organization', 'agent')),
  CONSTRAINT security_policies_scope_target_ck CHECK (
    (scope = 'organization' AND agent_id IS NULL)
    OR (scope = 'agent' AND agent_id IS NOT NULL)
  ),
  CONSTRAINT security_policies_status_ck CHECK (status IN ('draft', 'active', 'archived')),
  CONSTRAINT security_policies_agent_fk
    FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE RESTRICT
);

CREATE TABLE policy_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  version integer NOT NULL,
  document jsonb NOT NULL,
  document_hash text NOT NULL,
  checksum_alg text NOT NULL DEFAULT 'sha256',
  created_by uuid REFERENCES users (id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT policy_versions_org_pair_uq UNIQUE (id, organization_id),
  CONSTRAINT policy_versions_policy_version_uq UNIQUE (policy_id, version),
  CONSTRAINT policy_versions_policy_org_fk
    FOREIGN KEY (policy_id, organization_id)
    REFERENCES security_policies (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT policy_versions_version_ck CHECK (version >= 1),
  CONSTRAINT policy_versions_document_ck CHECK (jsonb_typeof(document) = 'object'),
  CONSTRAINT policy_versions_hash_ck CHECK (document_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT policy_versions_checksum_ck CHECK (checksum_alg = 'sha256')
);

ALTER TABLE security_policies
  ADD CONSTRAINT security_policies_current_version_fk
  FOREIGN KEY (current_version_id, organization_id)
  REFERENCES policy_versions (id, organization_id)
  ON DELETE RESTRICT;

-- Materialized view of an activated policy version for the dashboard.
-- Evaluation reads policy_versions, not this table.
CREATE TABLE agent_permissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  action text NOT NULL,
  effect text NOT NULL,
  resource_pattern text,
  policy_version_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_permissions_agent_org_fk
    FOREIGN KEY (agent_id, organization_id)
    REFERENCES agents (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT agent_permissions_version_fk
    FOREIGN KEY (policy_version_id, organization_id)
    REFERENCES policy_versions (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT agent_permissions_action_ck CHECK (
    action ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'
  ),
  CONSTRAINT agent_permissions_effect_ck CHECK (effect IN ('allow', 'deny', 'require_approval')),
  CONSTRAINT agent_permissions_projection_uq
    UNIQUE NULLS NOT DISTINCT (agent_id, action, resource_pattern)
);

-- ---------------------------------------------------------------------------
-- Runtime records
-- ---------------------------------------------------------------------------

CREATE TABLE executions (
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  id uuid NOT NULL,
  agent_id uuid NOT NULL,
  status text NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  ended_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (organization_id, id),
  CONSTRAINT executions_agent_org_fk
    FOREIGN KEY (agent_id, organization_id)
    REFERENCES agents (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT executions_status_ck CHECK (status IN (
    'running', 'completed', 'failed', 'terminated', 'awaiting_approval'
  )),
  CONSTRAINT executions_metadata_ck CHECK (jsonb_typeof(metadata) = 'object'),
  CONSTRAINT executions_ended_ck CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE TABLE tool_invocations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  execution_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  idempotency_key text NOT NULL,
  tool_name text NOT NULL,
  operation text NOT NULL,
  resource text NOT NULL,
  arguments_redacted jsonb NOT NULL,
  arguments_hash text NOT NULL,
  requested_at timestamptz NOT NULL,
  CONSTRAINT tool_invocations_org_pair_uq UNIQUE (id, organization_id),
  CONSTRAINT tool_invocations_idempotency_uq UNIQUE (organization_id, idempotency_key),
  CONSTRAINT tool_invocations_execution_fk
    FOREIGN KEY (organization_id, execution_id)
    REFERENCES executions (organization_id, id) ON DELETE RESTRICT,
  CONSTRAINT tool_invocations_agent_org_fk
    FOREIGN KEY (agent_id, organization_id)
    REFERENCES agents (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT tool_invocations_idempotency_ck CHECK (char_length(idempotency_key) BETWEEN 16 AND 200),
  CONSTRAINT tool_invocations_tool_ck CHECK (char_length(btrim(tool_name)) BETWEEN 1 AND 128),
  CONSTRAINT tool_invocations_operation_ck CHECK (char_length(btrim(operation)) BETWEEN 1 AND 128),
  CONSTRAINT tool_invocations_resource_ck CHECK (char_length(resource) BETWEEN 1 AND 512),
  CONSTRAINT tool_invocations_arguments_ck CHECK (jsonb_typeof(arguments_redacted) = 'object'),
  CONSTRAINT tool_invocations_arguments_hash_ck CHECK (arguments_hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE authorization_decisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  tool_invocation_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  outcome text NOT NULL,
  policy_id uuid,
  policy_version_id uuid,
  explanation jsonb NOT NULL,
  risk_level text NOT NULL,
  decided_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT authorization_decisions_org_pair_uq UNIQUE (id, organization_id),
  CONSTRAINT authorization_decisions_invocation_fk
    FOREIGN KEY (tool_invocation_id, organization_id)
    REFERENCES tool_invocations (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT authorization_decisions_agent_org_fk
    FOREIGN KEY (agent_id, organization_id)
    REFERENCES agents (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT authorization_decisions_policy_fk
    FOREIGN KEY (policy_id, organization_id)
    REFERENCES security_policies (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT authorization_decisions_version_fk
    FOREIGN KEY (policy_version_id, organization_id)
    REFERENCES policy_versions (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT authorization_decisions_outcome_ck CHECK (
    outcome IN ('allow', 'deny', 'require_approval')
  ),
  CONSTRAINT authorization_decisions_risk_ck CHECK (
    risk_level IN ('none', 'low', 'medium', 'high', 'critical')
  ),
  CONSTRAINT authorization_decisions_explanation_ck CHECK (jsonb_typeof(explanation) = 'object'),
  CONSTRAINT authorization_decisions_policy_pair_ck CHECK (
    policy_version_id IS NULL OR policy_id IS NOT NULL
  )
);

CREATE TABLE approval_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  tool_invocation_id uuid NOT NULL,
  authorization_decision_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  payload_hash text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  expires_at timestamptz NOT NULL,
  decided_by uuid REFERENCES users (id) ON DELETE RESTRICT,
  decided_at timestamptz,
  decision_reason text,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT approval_requests_invocation_fk
    FOREIGN KEY (tool_invocation_id, organization_id)
    REFERENCES tool_invocations (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT approval_requests_decision_fk
    FOREIGN KEY (authorization_decision_id, organization_id)
    REFERENCES authorization_decisions (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT approval_requests_agent_org_fk
    FOREIGN KEY (agent_id, organization_id)
    REFERENCES agents (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT approval_requests_status_ck CHECK (
    status IN ('pending', 'approved', 'rejected', 'expired', 'consumed')
  ),
  CONSTRAINT approval_requests_payload_hash_ck CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT approval_requests_expiry_ck CHECK (expires_at > created_at),
  CONSTRAINT approval_requests_decision_fields_ck CHECK (
    (
      status IN ('approved', 'rejected', 'consumed')
      AND decided_at IS NOT NULL
      AND decided_by IS NOT NULL
    )
    OR (
      status = 'pending'
      AND decided_at IS NULL
      AND decided_by IS NULL
      AND consumed_at IS NULL
    )
    OR (status = 'expired' AND consumed_at IS NULL)
  ),
  CONSTRAINT approval_requests_consumed_ck CHECK (
    (status = 'consumed' AND consumed_at IS NOT NULL)
    OR (status <> 'consumed' AND consumed_at IS NULL)
  )
);

-- ---------------------------------------------------------------------------
-- Incidents, events, and the hash chain
-- ---------------------------------------------------------------------------

CREATE TABLE security_incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  agent_id uuid,
  severity text NOT NULL,
  status text NOT NULL DEFAULT 'open',
  title text NOT NULL,
  detection_reason text NOT NULL,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  opened_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  CONSTRAINT security_incidents_org_pair_uq UNIQUE (id, organization_id),
  CONSTRAINT security_incidents_severity_ck CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  CONSTRAINT security_incidents_status_ck CHECK (
    status IN ('open', 'investigating', 'resolved', 'false_positive')
  ),
  CONSTRAINT security_incidents_title_ck CHECK (char_length(btrim(title)) > 0),
  CONSTRAINT security_incidents_evidence_ck CHECK (jsonb_typeof(evidence) = 'object'),
  CONSTRAINT security_incidents_resolved_ck CHECK (
    (status IN ('resolved', 'false_positive') AND resolved_at IS NOT NULL)
    OR (status IN ('open', 'investigating') AND resolved_at IS NULL)
  )
);

CREATE TABLE security_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  agent_id uuid,
  execution_id uuid,
  event_type text NOT NULL,
  payload_redacted jsonb NOT NULL,
  occurred_at timestamptz NOT NULL,
  CONSTRAINT security_events_org_pair_uq UNIQUE (id, organization_id),
  CONSTRAINT security_events_execution_fk
    FOREIGN KEY (organization_id, execution_id)
    REFERENCES executions (organization_id, id) ON DELETE RESTRICT,
  CONSTRAINT security_events_type_ck CHECK (char_length(btrim(event_type)) BETWEEN 1 AND 128),
  CONSTRAINT security_events_payload_ck CHECK (jsonb_typeof(payload_redacted) = 'object')
);

CREATE TABLE audit_chain_heads (
  organization_id uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE RESTRICT,
  last_sequence bigint NOT NULL,
  last_hash text NOT NULL,
  CONSTRAINT audit_chain_heads_sequence_ck CHECK (last_sequence >= 0),
  CONSTRAINT audit_chain_heads_hash_ck CHECK (last_hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE audit_chain (
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  sequence bigint NOT NULL,
  event_id uuid NOT NULL,
  prev_hash text NOT NULL,
  event_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, sequence),
  CONSTRAINT audit_chain_event_uq UNIQUE (event_id),
  CONSTRAINT audit_chain_event_org_fk
    FOREIGN KEY (event_id, organization_id)
    REFERENCES security_events (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT audit_chain_sequence_ck CHECK (sequence > 0),
  CONSTRAINT audit_chain_prev_hash_ck CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT audit_chain_event_hash_ck CHECK (event_hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE anomaly_alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  agent_id uuid,
  rule_id text NOT NULL,
  severity text NOT NULL,
  summary text NOT NULL,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'open',
  incident_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT anomaly_alerts_severity_ck CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  CONSTRAINT anomaly_alerts_status_ck CHECK (status IN ('open', 'acknowledged', 'resolved')),
  CONSTRAINT anomaly_alerts_rule_ck CHECK (char_length(btrim(rule_id)) > 0),
  CONSTRAINT anomaly_alerts_summary_ck CHECK (char_length(btrim(summary)) > 0),
  CONSTRAINT anomaly_alerts_evidence_ck CHECK (jsonb_typeof(evidence) = 'object'),
  CONSTRAINT anomaly_alerts_incident_fk
    FOREIGN KEY (incident_id, organization_id)
    REFERENCES security_incidents (id, organization_id) ON DELETE RESTRICT
);

CREATE TABLE reliability_metrics (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  agent_id uuid,
  metric_name text NOT NULL,
  metric_value double precision NOT NULL,
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  labels jsonb NOT NULL DEFAULT '{}'::jsonb,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT reliability_metrics_name_ck CHECK (char_length(btrim(metric_name)) > 0),
  CONSTRAINT reliability_metrics_value_ck CHECK (metric_value >= 0),
  CONSTRAINT reliability_metrics_window_ck CHECK (window_end > window_start),
  CONSTRAINT reliability_metrics_labels_ck CHECK (jsonb_typeof(labels) = 'object')
);

-- ---------------------------------------------------------------------------
-- Chaos experiments. Scenarios stay disabled until the harness exists.
-- ---------------------------------------------------------------------------

CREATE TABLE chaos_scenarios (
  id text PRIMARY KEY,
  description text NOT NULL,
  preconditions jsonb NOT NULL,
  expected_behavior text NOT NULL,
  enabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT chaos_scenarios_id_ck CHECK (id ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
  CONSTRAINT chaos_scenarios_description_ck CHECK (char_length(btrim(description)) > 0),
  CONSTRAINT chaos_scenarios_preconditions_ck CHECK (jsonb_typeof(preconditions) = 'object'),
  CONSTRAINT chaos_scenarios_expected_ck CHECK (char_length(btrim(expected_behavior)) > 0)
);

CREATE TABLE chaos_executions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  scenario_id text NOT NULL REFERENCES chaos_scenarios (id) ON DELETE RESTRICT,
  agent_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  payload jsonb NOT NULL,
  actual_result jsonb,
  evidence_uri text,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT chaos_executions_agent_org_fk
    FOREIGN KEY (agent_id, organization_id)
    REFERENCES agents (id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT chaos_executions_status_ck CHECK (
    status IN ('pending', 'running', 'passed', 'failed', 'error')
  ),
  CONSTRAINT chaos_executions_payload_ck CHECK (jsonb_typeof(payload) = 'object'),
  CONSTRAINT chaos_executions_result_ck CHECK (
    actual_result IS NULL OR jsonb_typeof(actual_result) = 'object'
  ),
  CONSTRAINT chaos_executions_time_ck CHECK (
    finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at
  )
);

CREATE TABLE schema_migrations (
  version text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Integrity functions
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION agentshield_set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION agentshield_reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'append-only table % does not allow %', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION agentshield_reject_agent_org_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
    RAISE EXCEPTION 'agent organization_id is immutable'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION agentshield_enforce_agent_organization()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  found_org uuid;
BEGIN
  IF NEW.agent_id IS NULL THEN
    RETURN NEW;
  END IF;

  SELECT organization_id INTO found_org FROM agents WHERE id = NEW.agent_id;
  IF found_org IS NULL THEN
    RAISE EXCEPTION 'agent does not exist'
      USING ERRCODE = '23503';
  END IF;
  IF found_org IS DISTINCT FROM NEW.organization_id THEN
    RAISE EXCEPTION 'cross-organization agent reference rejected'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION agentshield_decision_policy_agreement()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  version_policy uuid;
  version_org uuid;
BEGIN
  IF NEW.policy_version_id IS NULL THEN
    RETURN NEW;
  END IF;

  SELECT policy_id, organization_id
  INTO version_policy, version_org
  FROM policy_versions
  WHERE id = NEW.policy_version_id;

  IF version_org IS DISTINCT FROM NEW.organization_id THEN
    RAISE EXCEPTION 'policy version is not in the decision organization'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.policy_id IS DISTINCT FROM version_policy THEN
    RAISE EXCEPTION 'policy id does not match policy version'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION agentshield_audit_head_before_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.last_sequence <> 0
     OR NEW.last_hash <> '0000000000000000000000000000000000000000000000000000000000000000' THEN
    RAISE EXCEPTION 'audit head must start at sequence 0 and the genesis hash'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION agentshield_audit_head_before_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
    RAISE EXCEPTION 'audit head organization is immutable'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.last_sequence <> OLD.last_sequence + 1 THEN
    RAISE EXCEPTION 'audit head sequence must advance by one'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.last_hash = OLD.last_hash OR NEW.last_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'audit head hash must be a new 64 character hex digest'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

-- Serializes appends per organization. Callers supply prev_hash and event_hash.
-- The sequence stored in the row is assigned here. A prev_hash that does not
-- match the current head is rejected so a forked chain cannot be inserted.
CREATE OR REPLACE FUNCTION agentshield_audit_chain_before_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  head_sequence bigint;
  head_hash text;
  event_org uuid;
  genesis text := '0000000000000000000000000000000000000000000000000000000000000000';
BEGIN
  IF NEW.prev_hash !~ '^[0-9a-f]{64}$' OR NEW.event_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'audit hash must be 64 lowercase hex characters'
      USING ERRCODE = '23514';
  END IF;

  SELECT organization_id INTO event_org
  FROM security_events
  WHERE id = NEW.event_id;

  IF event_org IS NULL THEN
    RAISE EXCEPTION 'security event does not exist'
      USING ERRCODE = '23503';
  END IF;
  IF event_org IS DISTINCT FROM NEW.organization_id THEN
    RAISE EXCEPTION 'audit link organization does not match the security event'
      USING ERRCODE = '23514';
  END IF;

  INSERT INTO audit_chain_heads (organization_id, last_sequence, last_hash)
  VALUES (NEW.organization_id, 0, genesis)
  ON CONFLICT (organization_id) DO NOTHING;

  SELECT last_sequence, last_hash
  INTO head_sequence, head_hash
  FROM audit_chain_heads
  WHERE organization_id = NEW.organization_id
  FOR UPDATE;

  IF head_hash IS DISTINCT FROM NEW.prev_hash THEN
    RAISE EXCEPTION 'audit prev_hash does not match chain head'
      USING ERRCODE = '40001';
  END IF;

  NEW.sequence := head_sequence + 1;

  UPDATE audit_chain_heads
  SET last_sequence = NEW.sequence,
      last_hash = NEW.event_hash
  WHERE organization_id = NEW.organization_id;

  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION agentshield_append_audit_link(
  p_organization_id uuid,
  p_event_id uuid,
  p_prev_hash text,
  p_event_hash text
) RETURNS bigint
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  assigned bigint;
BEGIN
  INSERT INTO audit_chain (organization_id, sequence, event_id, prev_hash, event_hash)
  VALUES (p_organization_id, 0, p_event_id, p_prev_hash, p_event_hash)
  RETURNING sequence INTO assigned;
  RETURN assigned;
END;
$$;

-- ---------------------------------------------------------------------------
-- Triggers
-- ---------------------------------------------------------------------------

CREATE TRIGGER users_set_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION agentshield_set_updated_at();

CREATE TRIGGER organizations_set_updated_at
  BEFORE UPDATE ON organizations
  FOR EACH ROW EXECUTE FUNCTION agentshield_set_updated_at();

CREATE TRIGGER agents_set_updated_at
  BEFORE UPDATE ON agents
  FOR EACH ROW EXECUTE FUNCTION agentshield_set_updated_at();

CREATE TRIGGER agents_org_immutable
  BEFORE UPDATE ON agents
  FOR EACH ROW EXECUTE FUNCTION agentshield_reject_agent_org_change();

CREATE TRIGGER security_policies_set_updated_at
  BEFORE UPDATE ON security_policies
  FOR EACH ROW EXECUTE FUNCTION agentshield_set_updated_at();

CREATE TRIGGER security_policies_agent_org
  BEFORE INSERT OR UPDATE ON security_policies
  FOR EACH ROW EXECUTE FUNCTION agentshield_enforce_agent_organization();

CREATE TRIGGER authorization_decisions_policy_agreement
  BEFORE INSERT ON authorization_decisions
  FOR EACH ROW EXECUTE FUNCTION agentshield_decision_policy_agreement();

CREATE TRIGGER security_incidents_agent_org
  BEFORE INSERT OR UPDATE ON security_incidents
  FOR EACH ROW EXECUTE FUNCTION agentshield_enforce_agent_organization();

CREATE TRIGGER security_events_agent_org
  BEFORE INSERT OR UPDATE ON security_events
  FOR EACH ROW EXECUTE FUNCTION agentshield_enforce_agent_organization();

CREATE TRIGGER anomaly_alerts_agent_org
  BEFORE INSERT OR UPDATE ON anomaly_alerts
  FOR EACH ROW EXECUTE FUNCTION agentshield_enforce_agent_organization();

CREATE TRIGGER reliability_metrics_agent_org
  BEFORE INSERT OR UPDATE ON reliability_metrics
  FOR EACH ROW EXECUTE FUNCTION agentshield_enforce_agent_organization();

CREATE TRIGGER policy_versions_append_only
  BEFORE UPDATE OR DELETE ON policy_versions
  FOR EACH ROW EXECUTE FUNCTION agentshield_reject_mutation();

CREATE TRIGGER authorization_decisions_append_only
  BEFORE UPDATE OR DELETE ON authorization_decisions
  FOR EACH ROW EXECUTE FUNCTION agentshield_reject_mutation();

CREATE TRIGGER security_events_append_only
  BEFORE UPDATE OR DELETE ON security_events
  FOR EACH ROW EXECUTE FUNCTION agentshield_reject_mutation();

CREATE TRIGGER audit_chain_append_only
  BEFORE UPDATE OR DELETE ON audit_chain
  FOR EACH ROW EXECUTE FUNCTION agentshield_reject_mutation();

CREATE TRIGGER audit_chain_heads_before_insert
  BEFORE INSERT ON audit_chain_heads
  FOR EACH ROW EXECUTE FUNCTION agentshield_audit_head_before_insert();

CREATE TRIGGER audit_chain_heads_before_update
  BEFORE UPDATE ON audit_chain_heads
  FOR EACH ROW EXECUTE FUNCTION agentshield_audit_head_before_update();

CREATE TRIGGER audit_chain_heads_no_delete
  BEFORE DELETE ON audit_chain_heads
  FOR EACH ROW EXECUTE FUNCTION agentshield_reject_mutation();

CREATE TRIGGER audit_chain_before_insert
  BEFORE INSERT ON audit_chain
  FOR EACH ROW EXECUTE FUNCTION agentshield_audit_chain_before_insert();

-- ---------------------------------------------------------------------------
-- Indexes for the reads Phase 1 and the dashboard will actually make
-- ---------------------------------------------------------------------------

CREATE INDEX memberships_user_idx ON memberships (user_id);
CREATE INDEX agents_org_status_idx ON agents (organization_id, status);
CREATE INDEX agent_credentials_agent_status_idx ON agent_credentials (agent_id, status);
CREATE INDEX executions_agent_started_idx ON executions (agent_id, started_at DESC);
CREATE INDEX tool_invocations_org_requested_idx ON tool_invocations (organization_id, requested_at DESC);
CREATE INDEX authorization_decisions_org_decided_idx
  ON authorization_decisions (organization_id, decided_at DESC);
CREATE INDEX approval_requests_pending_idx
  ON approval_requests (organization_id, expires_at)
  WHERE status = 'pending';
CREATE INDEX security_events_org_occurred_idx
  ON security_events (organization_id, occurred_at DESC);
CREATE INDEX security_incidents_org_status_idx
  ON security_incidents (organization_id, status, opened_at DESC);
CREATE INDEX anomaly_alerts_org_created_idx ON anomaly_alerts (organization_id, created_at DESC);
CREATE INDEX chaos_executions_org_created_idx ON chaos_executions (organization_id, created_at DESC);

COMMENT ON TABLE agent_credentials IS
  'Ed25519 public keys only. Fingerprints are lowercase SHA-256 hex of the raw 32-byte key.';

COMMENT ON TABLE policy_versions IS
  'Immutable policy documents. Updates and deletes are rejected by trigger.';

COMMENT ON TABLE security_events IS
  'Append-only redacted security events. Payload values are redacted before insert.';

COMMENT ON TABLE audit_chain IS
  'Per-organization hash chain. Sequence and head movement are enforced by trigger.';

COMMENT ON TABLE agent_permissions IS
  'Non-authoritative projection of an activated policy. Do not evaluate requests from this table.';

COMMENT ON FUNCTION agentshield_append_audit_link(uuid, uuid, text, text) IS
  'Inserts the next audit link. Concurrent appends that lose the head race must retry.';

INSERT INTO schema_migrations (version) VALUES ('0001_init');
