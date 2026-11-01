import "reflect-metadata";
import { Client } from "pg";
import { hashPassword } from "./auth/passwords";
import { loadConfig } from "./config/configuration";

async function main(): Promise<void> {
  const config = loadConfig(process.env);
  if (!config.databaseUrl) {
    throw new Error("DATABASE_URL is required");
  }
  const email = required("AGENTSHIELD_BOOTSTRAP_EMAIL").toLowerCase();
  const password = required("AGENTSHIELD_BOOTSTRAP_PASSWORD");
  const displayName = required("AGENTSHIELD_BOOTSTRAP_DISPLAY_NAME").trim();
  const orgName = required("AGENTSHIELD_BOOTSTRAP_ORG_NAME").trim();
  const slug = required("AGENTSHIELD_BOOTSTRAP_ORG_SLUG").trim();
  if (password.length < 12 || password.length > 128) {
    throw new Error("bootstrap password must be 12 to 128 characters");
  }
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) {
    throw new Error("bootstrap organization slug is invalid");
  }
  if (displayName.length === 0 || orgName.length === 0 || !email.includes("@")) {
    throw new Error("bootstrap identity fields are invalid");
  }

  const client = new Client({ connectionString: config.databaseUrl });
  await client.connect();
  try {
    const existing = await client.query("SELECT id::text FROM organizations WHERE slug = $1", [slug]);
    if ((existing.rowCount ?? 0) > 0) {
      process.stdout.write("organization already exists\n");
      return;
    }
    const passwordHash = await hashPassword(password);
    await client.query("BEGIN");
    const user = await client.query<{ id: string }>(
      `INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, $3) RETURNING id::text`,
      [email, passwordHash, displayName],
    );
    const organization = await client.query<{ id: string }>(
      `INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
      [orgName, slug],
    );
    await client.query(
      `INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')`,
      [organization.rows[0].id, user.rows[0].id],
    );
    await client.query("COMMIT");
    process.stdout.write(`organization ${organization.rows[0].id}\n`);
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    await client.end();
  }
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "bootstrap failed";
  process.stderr.write(`${JSON.stringify({ level: "error", msg: "bootstrap failed", error: message })}\n`);
  process.exit(1);
});
