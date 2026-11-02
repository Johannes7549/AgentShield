import type { Pool, PoolClient, QueryResult, QueryResultRow } from "pg";
import { AsyncLocalStorage } from "async_hooks";

export const organizationStore = new AsyncLocalStorage<string>();

export async function setOrganization(client: PoolClient, organizationId: string): Promise<void> {
  await client.query(`SELECT set_config('app.organization_id', $1, true)`, [organizationId]);
}

export async function withOrganization<T>(
  pool: Pool,
  organizationId: string,
  run: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await setOrganization(client, organizationId);
    const result = await run(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export function runWithOrganization<T>(organizationId: string, run: () => T): T {
  return organizationStore.run(organizationId, run);
}

export function currentOrganization(): string | undefined {
  return organizationStore.getStore();
}

export function wrapPool(pool: Pool): Pool {
  const originalConnect = pool.connect.bind(pool);
  const originalQuery = pool.query.bind(pool);

  pool.query = (async (text: unknown, values?: unknown) => {
    const org = currentOrganization();
    if (!org || typeof text !== "string") {
      return originalQuery(text as never, values as never);
    }
    const client = await originalConnect();
    try {
      await client.query("BEGIN");
      await setOrganization(client, org);
      const result = await client.query(text, values as never);
      await client.query("COMMIT");
      return result as QueryResult<QueryResultRow>;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }) as Pool["query"];

  return pool;
}
