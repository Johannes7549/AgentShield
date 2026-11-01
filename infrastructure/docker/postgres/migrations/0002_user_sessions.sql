-- Human session tokens. The token itself is not stored.
-- token_hash is SHA-256 of the raw 32-byte token.

CREATE TABLE user_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
  token_hash bytea NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT user_sessions_token_hash_ck CHECK (octet_length(token_hash) = 32),
  CONSTRAINT user_sessions_expiry_ck CHECK (expires_at > created_at),
  CONSTRAINT user_sessions_revocation_ck CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX user_sessions_user_idx ON user_sessions (user_id);

COMMENT ON TABLE user_sessions IS
  'Bearer sessions for human callers. Only the SHA-256 of the token is stored.';

INSERT INTO schema_migrations (version) VALUES ('0002_user_sessions');
