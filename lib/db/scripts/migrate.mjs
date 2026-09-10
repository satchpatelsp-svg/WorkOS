import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import pg from "pg";

const { Client } = pg;
const migrationsDirectory = path.resolve(
  import.meta.dirname,
  "..",
  "migrations",
);

if (!process.env.DATABASE_MIGRATION_URL) {
  throw new Error(
    "DATABASE_MIGRATION_URL must be set. Migration tooling does not fall back to DATABASE_URL.",
  );
}

const client = new Client({
  connectionString: process.env.DATABASE_MIGRATION_URL,
  application_name: "work-os-migrator",
});
await client.connect();

try {
  const migrationIdentity = await client.query(`
    select current_user, rolsuper, rolcreaterole
    from pg_roles
    where rolname = current_user
  `);
  const identity = migrationIdentity.rows[0];
  if (
    !identity ||
    identity.current_user === "workos_runtime" ||
    identity.current_user === "workos_worker" ||
    (!identity.rolsuper && !identity.rolcreaterole)
  ) {
    throw new Error(
      "DATABASE_MIGRATION_URL must use a separate migration/admin login with role-management authority",
    );
  }

  await client.query(`
    CREATE TABLE IF NOT EXISTS public.workos_migrations (
      filename text PRIMARY KEY,
      checksum text NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);

  const files = (await readdir(migrationsDirectory))
    .filter((filename) => filename.endsWith(".sql"))
    .sort();

  for (const filename of files) {
    const sql = await readFile(path.join(migrationsDirectory, filename), "utf8");
    const checksum = createHash("sha256").update(sql).digest("hex");
    const existing = await client.query(
      "select checksum from public.workos_migrations where filename = $1",
      [filename],
    );

    if (existing.rows[0]) {
      if (existing.rows[0].checksum !== checksum) {
        throw new Error(`Applied migration changed: ${filename}`);
      }
      process.stdout.write(`Already applied ${filename}\n`);
      continue;
    }

    process.stdout.write(`Applying ${filename}\n`);
    await client.query(sql);
    await client.query(
      "insert into public.workos_migrations (filename, checksum) values ($1, $2)",
      [filename, checksum],
    );
  }
} finally {
  await client.end();
}