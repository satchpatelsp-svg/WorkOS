import { defineConfig } from "drizzle-kit";
import path from "path";

if (!process.env.DATABASE_MIGRATION_URL) {
  throw new Error(
    "DATABASE_MIGRATION_URL must be set. Migration tooling does not fall back to DATABASE_URL.",
  );
}

export default defineConfig({
  schema: path.join(__dirname, "./src/schema/index.ts"),
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_MIGRATION_URL,
  },
});
