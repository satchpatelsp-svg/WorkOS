import type { AccessCatalogContext } from "@workspace/request-context";
import { withAccessCatalogContext } from "./context";

export interface PortfolioMetadata {
  tenantId: string;
  tenantName: string;
  workspaceId: string;
  workspaceName: string;
  assignmentId: string;
  category: string;
  urgency: string;
  ageSeconds: number;
  slaDueAt: Date | null;
  status: string;
  refreshedAt: Date;
}

export async function openPortfolioContext(
  context: AccessCatalogContext,
  purpose: string,
): Promise<string> {
  return withAccessCatalogContext(context, async (_db, client) => {
    const result = await client.query<{ context_id: string }>(
      "select workos_security.open_portfolio_context($1) as context_id",
      [purpose],
    );
    const row = result.rows[0];
    if (!row) {
      throw new Error("Portfolio context was not created");
    }
    return row.context_id;
  });
}

export async function listPortfolioMetadata(
  context: AccessCatalogContext,
  portfolioContextId: string,
): Promise<PortfolioMetadata[]> {
  return withAccessCatalogContext(context, async (_db, client) => {
    const result = await client.query<{
      tenant_id: string;
      tenant_name: string;
      workspace_id: string;
      workspace_name: string;
      assignment_id: string;
      category: string;
      urgency: string;
      age_seconds: string;
      sla_due_at: Date | null;
      status: string;
      refreshed_at: Date;
    }>("select * from workos_security.get_portfolio_metadata($1)", [
      portfolioContextId,
    ]);
    return result.rows.map((row) => ({
      tenantId: row.tenant_id,
      tenantName: row.tenant_name,
      workspaceId: row.workspace_id,
      workspaceName: row.workspace_name,
      assignmentId: row.assignment_id,
      category: row.category,
      urgency: row.urgency,
      ageSeconds: Number(row.age_seconds),
      slaDueAt: row.sla_due_at,
      status: row.status,
      refreshedAt: row.refreshed_at,
    }));
  });
}