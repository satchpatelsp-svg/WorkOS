import path from "node:path";
import pg from "pg";
import {
  executeAuditCli,
  safeResultLine,
} from "./stage-a-migration-audit-lib.mjs";

const { Client } = pg;
const migrationsDirectory = path.resolve(
  import.meta.dirname,
  "..",
  "migrations",
);

try {
  process.exitCode = await executeAuditCli({
    environment: process.env,
    migrationsDirectory,
    createClient: (connectionString) =>
      new Client({
        connectionString,
        application_name: "work-os-stage-a-migration-audit",
      }),
    writeLine: (line) => process.stdout.write(`${line}\n`),
  });
} catch {
  process.stdout.write(`${safeResultLine(false, "query_error")}\n`);
  process.exitCode = 1;
}